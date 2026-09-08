"""
ChromaDB 向量索引服务
为漏洞知识库构建语义向量索引，支持基于语义相似度的 RAG 检索
使用 ChromaDB 内置 all-MiniLM-L6-v2 嵌入模型 (无需外部 API)

优雅降级: chromadb 未安装时所有方法安全返回空结果
"""

import os
import logging

logger = logging.getLogger(__name__)

# 条件导入: chromadb 未安装时不阻塞应用启动
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.info('chromadb 未安装, 语义搜索功能不可用 (pip install chromadb)')

# 索引持久化路径
CHROMA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                         'database', 'chroma_db')


class ChromaService:
    """ChromaDB 向量索引服务 (单例模式)"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._client = None
        self._collection = None
        self._indexed_count = 0

    @property
    def is_available(self):
        """检查 ChromaDB 是否可用"""
        if not CHROMADB_AVAILABLE:
            return False
        try:
            self._ensure_collection()
            return True
        except Exception:
            return False

    def _ensure_collection(self):
        """确保 ChromaDB 客户端和集合已初始化"""
        if not CHROMADB_AVAILABLE:
            raise RuntimeError('chromadb 未安装')
        if self._client is None:
            os.makedirs(CHROMA_DIR, exist_ok=True)
            self._client = chromadb.PersistentClient(path=CHROMA_DIR)
            # 使用内置嵌入模型 (all-MiniLM-L6-v2, ~80MB, 首次自动下载)
            self._collection = self._client.get_or_create_collection(
                name='vulnerabilities',
                metadata={'hnsw:space': 'cosine'}
            )
        return self._collection

    def index_vulnerabilities(self, vulnerabilities):
        """
        为漏洞列表构建/更新向量索引
        :param vulnerabilities: Vulnerability 模型对象列表
        :return: 索引的文档数量
        """
        collection = self._ensure_collection()

        documents = []
        metadatas = []
        ids = []

        for vuln in vulnerabilities:
            # 构建富文本: 名称 + 描述 + 分类 + 攻击方法 + 修复方案
            text_parts = [vuln.name]
            if vuln.description:
                text_parts.append(vuln.description)
            if hasattr(vuln, 'category') and vuln.category:
                text_parts.append(f'分类: {vuln.category.name}')
            if hasattr(vuln, 'attack_method') and vuln.attack_method:
                text_parts.append(f'攻击方法: {vuln.attack_method}')
            if vuln.solution:
                text_parts.append(f'修复方案: {vuln.solution}')
            if vuln.impact:
                text_parts.append(f'影响: {vuln.impact}')

            doc_text = '\n'.join(text_parts)
            documents.append(doc_text)
            ids.append(f'vuln_{vuln.id}')
            metadatas.append({
                'vuln_id': vuln.id,
                'name': vuln.name,
                'severity': vuln.severity or 'Unknown',
                'category': vuln.category.name if hasattr(vuln, 'category') and vuln.category else '',
            })

        if not documents:
            return 0

        # upsert: 如果 ID 已存在则更新，否则插入
        collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        self._indexed_count = len(documents)
        logger.info(f'ChromaDB: 已索引 {len(documents)} 条漏洞记录')
        return len(documents)

    def search_similar(self, query_text, n_results=3, exclude_vuln_id=None):
        """
        语义相似度搜索
        :param query_text: 查询文本 (漏洞名称、描述等)
        :param n_results: 返回结果数量
        :param exclude_vuln_id: 排除的漏洞ID (避免返回自身)
        :return: [(vuln_id, 相似度分数, 文档文本)] 列表
        """
        collection = self._ensure_collection()

        if collection.count() == 0:
            return []

        try:
            where_filter = None
            if exclude_vuln_id is not None:
                where_filter = {'vuln_id': {'$ne': exclude_vuln_id}}

            results = collection.query(
                query_texts=[query_text],
                n_results=min(n_results, collection.count()),
                where=where_filter,
                include=['documents', 'metadatas', 'distances']
            )

            similar = []
            if results and results['ids'] and results['ids'][0]:
                for i, doc_id in enumerate(results['ids'][0]):
                    distance = results['distances'][0][i] if results.get('distances') else 0
                    document = results['documents'][0][i] if results.get('documents') else ''
                    metadata = results['metadatas'][0][i] if results.get('metadatas') else {}
                    # cosine distance -> similarity (ChromaDB cosine: 0=same, 2=opposite)
                    similarity = max(0, 1 - distance)
                    similar.append({
                        'vuln_id': metadata.get('vuln_id'),
                        'name': metadata.get('name', ''),
                        'severity': metadata.get('severity', ''),
                        'similarity': round(similarity, 3),
                        'document': document[:500],  # 截断避免过长
                    })

            return similar

        except Exception as e:
            logger.error(f'ChromaDB 搜索失败: {e}')
            return []

    def get_index_stats(self):
        """获取索引统计信息"""
        try:
            collection = self._ensure_collection()
            return {
                'total_documents': collection.count(),
                'collection_name': collection.name,
                'available': True,
            }
        except Exception as e:
            return {
                'total_documents': 0,
                'available': False,
                'error': str(e),
            }

    def rebuild_index(self, vulnerabilities):
        """
        重建索引 (清除旧数据后重新索引)
        :param vulnerabilities: 漏洞列表
        :return: 索引数量
        """
        collection = self._ensure_collection()
        # 删除所有旧文档
        if collection.count() > 0:
            collection.delete(where={'vuln_id': {'$gte': 0}})
        return self.index_vulnerabilities(vulnerabilities)
