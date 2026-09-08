"""
RAG安全知识增强服务模块 (ChromaDB 语义检索版)
从漏洞知识库检索相关上下文，增强Prompt
使用 ChromaDB 向量数据库实现语义相似度检索，替代原有的分类匹配方式
"""

import logging
from app.models.vulnerability import Vulnerability
from app.services.chroma_service import ChromaService

logger = logging.getLogger(__name__)


class RAGService:
    """RAG知识增强服务 (ChromaDB 语义检索版)"""

    def __init__(self):
        self.chroma = ChromaService()

    def retrieve_vuln_context(self, vulnerability):
        """
        根据漏洞对象检索相关上下文
        优先使用 ChromaDB 语义检索，降级使用分类匹配
        :param vulnerability: Vulnerability模型对象
        :return: 上下文文本字符串
        """
        if not vulnerability:
            return ''

        parts = []

        # 漏洞基本信息 (始终包含)
        parts.append(f"漏洞名称: {vulnerability.name}")
        if vulnerability.description:
            parts.append(f"漏洞描述: {vulnerability.description}")
        if hasattr(vulnerability, 'category') and vulnerability.category:
            parts.append(f"所属分类: {vulnerability.category.name}")
        if hasattr(vulnerability, 'severity') and vulnerability.severity:
            parts.append(f"严重程度: {vulnerability.severity}")
        if vulnerability.solution:
            parts.append(f"修复方案: {vulnerability.solution}")
        if hasattr(vulnerability, 'cve') and vulnerability.cve:
            parts.append(f"CVE编号: {vulnerability.cve}")
        if hasattr(vulnerability, 'attack_method') and vulnerability.attack_method:
            parts.append(f"攻击方法: {vulnerability.attack_method}")
        if hasattr(vulnerability, 'owasp') and vulnerability.owasp:
            parts.append(f"OWASP分类: {vulnerability.owasp.name}")
            if vulnerability.owasp.description:
                parts.append(f"OWASP描述: {vulnerability.owasp.description[:300]}")

        # ---- ChromaDB 语义检索相关漏洞 ----
        if self.chroma.is_available:
            similar = self._chroma_search(vulnerability)
            if similar:
                parts.append('\n--- 语义相关漏洞 (ChromaDB) ---')
                for item in similar:
                    parts.append(
                        f"- [{item['name']}] (相似度: {item['similarity']:.0%}) "
                        f"{item['document'][:200]}"
                    )
        else:
            # 降级: 分类匹配
            related = self._search_related_vulnerabilities(vulnerability)
            if related:
                parts.append('\n--- 相关漏洞参考 ---')
                for rv in related:
                    parts.append(f"- {rv.name}: {(rv.description or '')[:150]}")

        return '\n'.join(parts) if parts else ''

    def _chroma_search(self, vulnerability):
        """
        使用 ChromaDB 语义搜索相关漏洞
        如果索引为空，自动构建索引
        :param vulnerability: 当前漏洞对象
        :return: 相似漏洞列表
        """
        # 自动索引: 首次使用时构建向量索引
        self._ensure_indexed()

        # 构建查询文本: 用漏洞名称+描述作为语义查询
        query_parts = [vulnerability.name]
        if vulnerability.description:
            query_parts.append(vulnerability.description[:300])
        if hasattr(vulnerability, 'attack_method') and vulnerability.attack_method:
            query_parts.append(vulnerability.attack_method[:200])
        query_text = ' '.join(query_parts)

        try:
            return self.chroma.search_similar(
                query_text=query_text,
                n_results=3,
                exclude_vuln_id=vulnerability.id
            )
        except Exception as e:
            logger.warning(f'ChromaDB 语义搜索失败, 降级为分类匹配: {e}')
            return []

    def _ensure_indexed(self):
        """确保 ChromaDB 索引已构建 (延迟初始化)"""
        try:
            stats = self.chroma.get_index_stats()
            if stats.get('available') and stats.get('total_documents', 0) == 0:
                vulns = Vulnerability.query.all()
                if vulns:
                    count = self.chroma.index_vulnerabilities(vulns)
                    logger.info(f'ChromaDB: 延迟索引构建完成, {count} 条记录')
        except Exception as e:
            logger.debug(f'ChromaDB 自动索引跳过: {e}')

    def retrieve_scan_context(self, scan_results):
        """
        根据扫描结果生成安全上下文
        :param scan_results: ScanResult列表
        :return: 上下文文本
        """
        if not scan_results:
            return ''

        high_risk_ports = {22, 23, 3389, 3306, 1433, 5432, 6379, 27017, 11211}

        parts = []
        risky_ports = []
        for r in scan_results:
            port = getattr(r, 'port', 0)
            service = getattr(r, 'service', '') or ''
            if port in high_risk_ports:
                risky_ports.append(f"端口{port}({service}) - 高风险数据库/远程服务")

        if risky_ports:
            parts.append("高风险端口发现:")
            parts.extend(risky_ports)

        # 尝试用 ChromaDB 检索与开放端口相关的漏洞知识
        if self.chroma.is_available and scan_results:
            port_services = []
            for r in scan_results:
                service = getattr(r, 'service', '') or ''
                version = getattr(r, 'version', '') or ''
                if service:
                    port_services.append(f'{service} {version}'.strip())

            if port_services:
                query = ' '.join(port_services[:5])
                try:
                    similar = self.chroma.search_similar(query, n_results=2)
                    if similar:
                        parts.append('\n--- 端口关联漏洞知识 ---')
                        for item in similar:
                            parts.append(
                                f"- [{item['name']}] {item['document'][:150]}"
                            )
                except Exception:
                    pass

        return '\n'.join(parts)

    def retrieve_general_context(self, query_text):
        """
        通用语义检索: 针对自定义分析输入文本, 从漏洞知识库检索相关上下文
        :param query_text: 用户输入的分析内容
        :return: 上下文字符串 (无结果返回 '')
        """
        if not query_text or not query_text.strip():
            return ''
        if not self.chroma.is_available:
            return ''

        self._ensure_indexed()
        try:
            similar = self.chroma.search_similar(query_text, n_results=3)
        except Exception as e:
            logger.warning(f'ChromaDB 通用检索失败: {e}')
            return ''

        if not similar:
            return ''

        parts = ['\n--- 安全知识库相关参考 (ChromaDB 语义检索) ---']
        for item in similar:
            parts.append(f"- [{item['name']}] {item['document'][:200]}")
        return '\n'.join(parts)

    def _search_related_vulnerabilities(self, vulnerability):
        """
        降级搜索: 按分类/OWASP匹配 (ChromaDB 不可用时使用)
        :param vulnerability: 当前漏洞
        :return: 相关Vulnerability列表 (最多3个)
        """
        if not vulnerability:
            return []
        try:
            if vulnerability.category_id:
                related = Vulnerability.query.filter(
                    Vulnerability.category_id == vulnerability.category_id,
                    Vulnerability.id != vulnerability.id
                ).limit(3).all()
                if related:
                    return related
            if vulnerability.owasp_id:
                related = Vulnerability.query.filter(
                    Vulnerability.owasp_id == vulnerability.owasp_id,
                    Vulnerability.id != vulnerability.id
                ).limit(3).all()
                return related
        except Exception:
            pass
        return []
