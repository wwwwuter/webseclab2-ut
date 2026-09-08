"""
NVD (National Vulnerability Database) 漏洞库自动同步服务

通过 NVD REST API 2.0 获取公开 CVE 漏洞数据，自动同步到本地知识库。
支持:
- 关键词过滤 (如 SQL Injection, XSS)
- 增量同步 (按最后修改时间)
- CWE → 本地分类自动映射
- CVSS 评分 → 严重等级转换
- CVE 去重 (已有记录更新, 不重复创建)

NVD API 文档: https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
import time
from datetime import datetime, timedelta
from app.extensions import db
from app.models.vulnerability import Vulnerability, VulnerabilityCategory

logger = logging.getLogger(__name__)

# ==================== NVD API 配置 ====================

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_RATE_LIMIT_DELAY = 6.5   # 无 API Key 时, NVD 限制 5 req/30s → 间隔 6.5s
NVD_DEFAULT_PER_PAGE = 20    # 每次请求拉取数量 (NVD 最大 2000, 保守取 20)

# ==================== CWE → 本地分类映射表 ====================
# CWE (Common Weakness Enumeration) 是 NVD 使用的漏洞类型编号
# 这里映射到项目 init_vulnerability.py 中预置的分类名称

CWE_TO_CATEGORY = {
    # SQL 注入相关
    'CWE-89':  'SQL Injection',
    'CWE-564': 'SQL Injection',

    # XSS 相关
    'CWE-79':  'XSS',
    'CWE-80':  'XSS',
    'CWE-81':  'XSS',

    # 文件上传/包含
    'CWE-434': 'File Upload',
    'CWE-98':  'File Upload',
    'CWE-22':  'File Upload',    # 路径遍历也归入文件类
    'CWE-73':  'File Upload',

    # 命令注入
    'CWE-78':  'Command Injection',
    'CWE-77':  'Command Injection',
    'CWE-88':  'Command Injection',

    # CSRF
    'CWE-352': 'CSRF',

    # 访问控制
    'CWE-862': 'Broken Access Control',
    'CWE-863': 'Broken Access Control',
    'CWE-284': 'Broken Access Control',
    'CWE-285': 'Broken Access Control',
    'CWE-639': 'Broken Access Control',

    # 安全配置错误
    'CWE-16':  'Security Misconfiguration',
    'CWE-2':   'Security Misconfiguration',
    'CWE-119': 'Security Misconfiguration',
    'CWE-200': 'Security Misconfiguration',
    'CWE-310': 'Security Misconfiguration',

    # 反序列化
    'CWE-502': 'Insecure Deserialization',
}


class NVDSyncService:
    """NVD 漏洞库同步服务"""

    def __init__(self):
        self._stats = {
            'fetched': 0,
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
        }
        self._messages = []  # 进度消息列表

    @property
    def stats(self):
        return self._stats.copy()

    @property
    def messages(self):
        return list(self._messages)

    def _log(self, msg, *args):
        """记录进度消息 (支持 printf 风格格式化)"""
        if args:
            msg = msg % args
        self._messages.append(msg)
        logger.info('NVD Sync: %s', msg)

    # ==================== 主同步入口 ====================

    def sync(self, keyword=None, days_back=30, max_results=20):
        """
        从 NVD 拉取漏洞数据并同步到本地数据库

        :param keyword: 搜索关键词 (如 'SQL Injection'), None 则不按关键词过滤
        :param days_back: 拉取最近 N 天修改的漏洞 (增量同步)
        :param max_results: 最大拉取条数
        :return: dict 同步统计 {'fetched', 'created', 'updated', 'skipped', 'errors'}
        """
        import requests

        self._stats = {'fetched': 0, 'created': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
        self._messages = []

        self._log('开始同步 (keyword=%s, days_back=%d, max=%d)',
                  keyword or '无', days_back, max_results)

        # 构建 API 请求参数
        params = {
            'resultsPerPage': min(max_results, NVD_DEFAULT_PER_PAGE),
            'startIndex': 0,
        }

        # 关键词过滤
        if keyword:
            params['keywordSearch'] = keyword

        # 增量同步: 按最后修改时间过滤
        if days_back > 0:
            pub_start = datetime.utcnow() - timedelta(days=days_back)
            params['lastModStartDate'] = pub_start.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['lastModEndDate'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000')

        # 分页拉取
        total_fetched = 0
        while total_fetched < max_results:
            try:
                logger.info('NVD API 请求: params=%s', params)
                resp = requests.get(NVD_API_URL, params=params, timeout=30)

                if resp.status_code == 403:
                    self._log('NVD API 速率限制 (403), 等待 30 秒...')
                    time.sleep(30)
                    continue

                if resp.status_code != 200:
                    self._log('NVD API 错误: HTTP %d', resp.status_code)
                    self._stats['errors'] += 1
                    break

                data = resp.json()

            except requests.ConnectionError:
                self._log('网络连接失败, 请检查网络')
                self._stats['errors'] += 1
                break
            except requests.Timeout:
                self._log('NVD API 请求超时')
                self._stats['errors'] += 1
                break
            except Exception as e:
                self._log('请求异常: %s', e)
                self._stats['errors'] += 1
                break

            # 解析响应
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)

            if not vulnerabilities:
                self._log('没有更多数据')
                break

            self._log('获取到 %d 条 (总计 %d / 可用 %d)',
                      len(vulnerabilities), total_results, total_fetched + len(vulnerabilities))

            # 逐条处理
            for item in vulnerabilities:
                if total_fetched >= max_results:
                    break
                self._process_cve(item)
                total_fetched += 1
                self._stats['fetched'] = total_fetched

            # 分页: 更新 startIndex
            params['startIndex'] = params['startIndex'] + len(vulnerabilities)

            # 如果已经拉取完所有结果
            if params['startIndex'] >= total_results:
                break

            # NVD 速率限制: 无 API Key 时每请求间隔 6.5 秒
            if total_fetched < max_results:
                self._log('速率限制等待 %.1f 秒...', NVD_RATE_LIMIT_DELAY)
                time.sleep(NVD_RATE_LIMIT_DELAY)

        self._log('同步完成: 获取 %d, 新建 %d, 更新 %d, 跳过 %d, 错误 %d',
                  self._stats['fetched'], self._stats['created'],
                  self._stats['updated'], self._stats['skipped'],
                  self._stats['errors'])

        return self._stats

    # ==================== 单条 CVE 处理 ====================

    def _process_cve(self, item):
        """
        处理单条 NVD CVE 数据, 映射到本地 Vulnerability 模型

        去重策略:
        - 有 CVE 编号: 按 cve 字段去重, 已存在则更新
        - 无 CVE 编号: 按 name 去重
        """
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id', '')  # e.g. "CVE-2024-12345"

        # 提取英文描述
        description = self._extract_description(cve_data)
        if not description:
            self._stats['skipped'] += 1
            return

        # 构建漏洞名称: CVE ID + 简短描述
        name = self._build_name(cve_id, description)

        # 提取严重等级
        severity = self._extract_severity(cve_data)

        # 提取 CWE 并映射到本地分类
        category_id = self._extract_category_id(cve_data)

        # 提取参考链接
        reference = self._extract_references(cve_data)

        # 提取攻击方法 (从 CWE 描述推导)
        attack_method = self._extract_attack_method(cve_data)

        # 去重: 检查 CVE 是否已存在
        existing = None
        if cve_id:
            existing = Vulnerability.query.filter_by(cve=cve_id).first()

        if existing:
            # 更新已有记录
            self._update_existing(existing, name, description, severity,
                                  category_id, reference, attack_method)
            self._stats['updated'] += 1
        else:
            # 新建记录
            self._create_new(name, cve_id, description, severity,
                             category_id, reference, attack_method)
            self._stats['created'] += 1

    def _update_existing(self, vuln, name, description, severity,
                         category_id, reference, attack_method):
        """更新已有漏洞记录 (保留手动编辑的字段, 仅更新 NVD 数据)"""
        if not vuln.description or vuln.source == 'nvd':
            vuln.description = description[:3000] if description else vuln.description
        if not vuln.severity or vuln.severity == 'Medium':
            vuln.severity = severity
        if category_id and not vuln.category_id:
            vuln.category_id = category_id
        if reference and not vuln.reference:
            vuln.reference = reference
        if attack_method and not vuln.attack_method:
            vuln.attack_method = attack_method
        vuln.source = 'nvd'
        vuln.updated_time = datetime.now()
        db.session.commit()
        logger.debug('更新: %s (%s)', vuln.name, vuln.cve)

    def _create_new(self, name, cve_id, description, severity,
                    category_id, reference, attack_method):
        """创建新的漏洞记录"""
        vuln = Vulnerability(
            name=name[:128],
            cve=cve_id[:32] if cve_id else '',
            description=(description or '')[:3000],
            severity=severity,
            category_id=category_id,
            attack_method=(attack_method or '')[:2000],
            impact='',   # NVD API 不直接提供影响描述, 留空由管理员补充
            solution='', # NVD API 不直接提供修复方案, 留空由管理员补充
            reference=(reference or '')[:2000],
            source='nvd',
        )
        db.session.add(vuln)
        db.session.commit()
        logger.debug('新建: %s (%s)', name, cve_id)

    # ==================== NVD 数据提取辅助方法 ====================

    @staticmethod
    def _extract_description(cve_data):
        """提取英文描述 (优先 en, 兜底取第一条)"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        if descriptions:
            return descriptions[0].get('value', '')
        return ''

    @staticmethod
    def _build_name(cve_id, description):
        """构建漏洞名称: CVE-ID + 描述前 60 字符"""
        short_desc = description[:60].rstrip('.')
        if cve_id:
            return f'{cve_id}: {short_desc}' if short_desc else cve_id
        return short_desc or 'Unknown Vulnerability'

    @staticmethod
    def _extract_severity(cve_data):
        """
        从 CVSS 评分提取严重等级
        优先 CVSS v3.1 → v3.0 → v2.0, 兜底 Medium
        """
        metrics = cve_data.get('metrics', {})

        # CVSS v3.1
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            score = cvss_v31[0].get('cvssData', {}).get('baseScore', 0)
            return NVDSyncService._score_to_severity(score)

        # CVSS v3.0
        cvss_v30 = metrics.get('cvssMetricV30', [])
        if cvss_v30:
            score = cvss_v30[0].get('cvssData', {}).get('baseScore', 0)
            return NVDSyncService._score_to_severity(score)

        # CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            score = cvss_v2[0].get('cvssData', {}).get('baseScore', 0)
            return NVDSyncService._score_to_severity(score)

        return 'Medium'

    @staticmethod
    def _score_to_severity(score):
        """CVSS 分数 → 严重等级"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    @staticmethod
    def _extract_category_id(cve_data):
        """提取 CWE 编号并映射到本地分类 ID"""
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_id = desc.get('value', '')
                if cwe_id in CWE_TO_CATEGORY:
                    cat_name = CWE_TO_CATEGORY[cwe_id]
                    cat = VulnerabilityCategory.query.filter_by(name=cat_name).first()
                    if cat:
                        return cat.id
        return None

    @staticmethod
    def _extract_references(cve_data):
        """提取参考链接 (取前 5 个, 换行分隔)"""
        refs = cve_data.get('references', [])
        urls = [r.get('url', '') for r in refs[:5] if r.get('url')]
        return '\n'.join(urls)

    @staticmethod
    def _extract_attack_method(cve_data):
        """从 CWE 描述推导攻击方法 (简要)"""
        weaknesses = cve_data.get('weaknesses', [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_id = desc.get('value', '')
                if cwe_id.startswith('CWE-'):
                    cwe_ids.append(cwe_id)

        if cwe_ids:
            return f'CWE: {", ".join(cwe_ids)} (详见 NVD 描述)'
        return ''

    # ==================== 辅助查询 ====================

    @staticmethod
    def get_sync_stats():
        """获取本地漏洞库的同步统计信息"""
        total = Vulnerability.query.count()
        from_nvd = Vulnerability.query.filter_by(source='nvd').count()
        manual = Vulnerability.query.filter_by(source='manual').count()
        no_cve = Vulnerability.query.filter(
            (Vulnerability.cve == '') | (Vulnerability.cve.is_(None))
        ).count()

        return {
            'total': total,
            'from_nvd': from_nvd,
            'manual': manual,
            'no_cve': no_cve,
        }

    @staticmethod
    def search_nvd(keyword, max_results=5):
        """
        搜索 NVD (不写入数据库, 仅预览)
        用于管理员在同步前预览搜索结果
        """
        import requests

        params = {
            'resultsPerPage': min(max_results, 20),
            'startIndex': 0,
        }
        if keyword:
            params['keywordSearch'] = keyword

        try:
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            if resp.status_code != 200:
                return None, f'NVD API 错误: HTTP {resp.status_code}'

            data = resp.json()
            results = []
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                desc = NVDSyncService._extract_description(cve_data)
                severity = NVDSyncService._extract_severity(cve_data)
                exists = Vulnerability.query.filter_by(cve=cve_id).first() if cve_id else None

                results.append({
                    'cve_id': cve_id,
                    'description': (desc or '')[:200],
                    'severity': severity,
                    'already_synced': exists is not None,
                })

            return {
                'total': data.get('totalResults', 0),
                'items': results,
            }, None

        except requests.ConnectionError:
            return None, '网络连接失败'
        except requests.Timeout:
            return None, 'NVD API 请求超时'
        except Exception as e:
            return None, f'请求异常: {e}'
