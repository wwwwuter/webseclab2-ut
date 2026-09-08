"""
风险评分引擎服务模块 (RiskEngine)

实现 WebSecLab 自有的多因素漏洞风险评分模型, 区别于直接使用 CVSS 评分。

评分公式 (论文核心创新点之一):
  FinalScore = CVSS × 0.35
             + AssetImportance × 0.20
             + ExploitSuccess × 0.20
             + Exposure × 0.10
             + AIConfidence × 0.15

各因素评分范围: 0~10
最终评分范围: 0~100 (各项 × 权重后求和再 × 10)

设计原则:
- 评分过程透明可解释 (scoring_detail 记录完整计算过程)
- 支持自动评估 (从已有数据推断) 和手动评估 (管理员指定)
- 与 AI 分析结果联动 (AIConfidence 由 AI 输出质量决定)
"""

import json
import logging
from datetime import datetime
from app.extensions import db
from app.models.risk import RiskAssessment
from app.models.ai_analysis import AIAnalysis
from app.models.scan import ScanTask, ScanResult
from app.models.experiment import Experiment
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class RiskEngine:
    """多因素风险评分引擎"""

    # ==================== 核心评分方法 ====================

    def calculate(self, cvss=5.0, asset=6.0, exploit=5.0, exposure=5.0, ai_conf=5.0,
                  user_id=None, experiment_id=None, scan_id=None,
                  ai_analysis_id=None, vulnerability_id=None, source='auto'):
        """
        计算风险评分并持久化

        参数 (均为 0~10):
            cvss: CVSS 漏洞基础评分
            asset: 资产重要程度
            exploit: 漏洞利用成功率
            exposure: 暴露程度
            ai_conf: AI分析可信度

        返回:
            RiskAssessment 实例
        """
        # 确保输入在合法范围
        cvss = self._clamp(cvss)
        asset = self._clamp(asset)
        exploit = self._clamp(exploit)
        exposure = self._clamp(exposure)
        ai_conf = self._clamp(ai_conf)

        # 加权计算: 各项 0~10 × 权重, 求和后 × 10 → 0~100
        weighted = (
            cvss * RiskAssessment.WEIGHT_CVSS
            + asset * RiskAssessment.WEIGHT_ASSET
            + exploit * RiskAssessment.WEIGHT_EXPLOIT
            + exposure * RiskAssessment.WEIGHT_EXPOSURE
            + ai_conf * RiskAssessment.WEIGHT_AI
        )
        final_score = round(weighted * 10, 1)
        final_score = min(100.0, max(0.0, final_score))

        risk_level = RiskAssessment.classify_risk(final_score)

        # 评分明细: 记录完整计算过程, 便于论文展示和审计
        detail = {
            'formula': 'FinalScore = (CVSS×0.35 + Asset×0.20 + Exploit×0.20 + Exposure×0.10 + AI×0.15) × 10',
            'factors': {
                'cvss': {'value': cvss, 'weight': 0.35, 'weighted': round(cvss * 0.35, 2)},
                'asset': {'value': asset, 'weight': 0.20, 'weighted': round(asset * 0.20, 2)},
                'exploit': {'value': exploit, 'weight': 0.20, 'weighted': round(exploit * 0.20, 2)},
                'exposure': {'value': exposure, 'weight': 0.10, 'weighted': round(exposure * 0.10, 2)},
                'ai_confidence': {'value': ai_conf, 'weight': 0.15, 'weighted': round(ai_conf * 0.15, 2)},
            },
            'weighted_sum': round(weighted, 2),
            'final_score': final_score,
            'risk_level': risk_level,
            'calculated_at': datetime.now().isoformat()
        }

        assessment = RiskAssessment(
            user_id=user_id,
            experiment_id=experiment_id,
            scan_id=scan_id,
            ai_analysis_id=ai_analysis_id,
            vulnerability_id=vulnerability_id,
            cvss_score=cvss,
            asset_score=asset,
            exploit_score=exploit,
            exposure_score=exposure,
            ai_score=ai_conf,
            final_score=final_score,
            risk_level=risk_level,
            scoring_detail=json.dumps(detail, ensure_ascii=False),
            source=source,
        )
        db.session.add(assessment)
        db.session.commit()

        logger.info('风险评估完成: score=%.1f level=%s source=%s',
                     final_score, risk_level, source)
        return assessment

    # ==================== 自动评估 (从已有数据推断各因素) ====================

    def assess_from_experiment(self, experiment_id, user_id):
        """
        基于实验数据自动评估风险

        自动推断逻辑:
        - CVSS: 从关联漏洞的 severity 转换
        - Asset: 根据实验目标类型推断
        - Exploit: 根据实验状态 (success/failed) 推断
        - Exposure: 根据目标地址推断
        - AI: 从最新 AI 分析结果推断
        """
        experiment = db.session.get(Experiment, experiment_id)
        if not experiment:
            return None, '实验不存在'
        if not experiment.is_owner(user_id):
            return None, '无权评估该实验'

        # CVSS: 从关联漏洞 severity 转换
        cvss = 5.0
        vuln_id = None
        if experiment.vulnerability_id:
            vuln = db.session.get(Vulnerability, experiment.vulnerability_id)
            if vuln:
                cvss = self._severity_to_cvss(vuln.severity)
                vuln_id = vuln.id

        # Asset: 默认实验环境为 DVWA, 属于测试环境 → 3
        asset = 3.0

        # Exploit: 根据实验状态
        exploit = self._experiment_status_to_exploit(experiment.status)

        # Exposure: DVWA 一般为内网测试 → 5
        exposure = self._target_to_exposure(experiment.target)

        # AI: 查找最新 AI 分析
        ai_conf = 5.0
        ai_id = None
        latest_ai = AIAnalysis.query.filter_by(
            experiment_id=experiment_id, status='completed'
        ).order_by(AIAnalysis.created_time.desc()).first()
        if latest_ai:
            ai_conf = self._ai_risk_to_confidence(latest_ai)
            ai_id = latest_ai.id

        # 查找关联扫描任务
        scan_id = None
        latest_scan = ScanTask.query.filter_by(
            experiment_id=experiment_id
        ).order_by(ScanTask.created_time.desc()).first()
        if latest_scan:
            scan_id = latest_scan.id

        assessment = self.calculate(
            cvss=cvss, asset=asset, exploit=exploit,
            exposure=exposure, ai_conf=ai_conf,
            user_id=user_id, experiment_id=experiment_id,
            scan_id=scan_id, ai_analysis_id=ai_id,
            vulnerability_id=vuln_id, source='auto'
        )
        return assessment, None

    def assess_from_scan(self, scan_task_id, user_id):
        """
        基于扫描任务自动评估风险

        自动推断逻辑:
        - CVSS: 根据开放端口数量和敏感端口推断
        - Asset: 根据扫描目标类型推断
        - Exploit: 根据敏感端口开放情况推断
        - Exposure: 根据目标地址推断
        - AI: 从最新 AI 分析结果推断
        """
        task = db.session.get(ScanTask, scan_task_id)
        if not task:
            return None, '扫描任务不存在'
        if not task.is_owner(user_id):
            return None, '无权评估该扫描任务'

        results = ScanResult.query.filter_by(
            task_id=scan_task_id, state='open'
        ).all()

        # CVSS: 根据开放端口分析
        cvss = self._ports_to_cvss(results)

        # Asset: 根据目标推断
        asset = self._target_to_asset(task.target)

        # Exploit: 根据敏感端口开放情况
        exploit = self._ports_to_exploit(results)

        # Exposure: 根据目标地址
        exposure = self._target_to_exposure(task.target)

        # AI: 查找最新分析
        ai_conf = 5.0
        ai_id = None
        latest_ai = AIAnalysis.query.filter_by(
            scan_task_id=scan_task_id, status='completed'
        ).order_by(AIAnalysis.created_time.desc()).first()
        if latest_ai:
            ai_conf = self._ai_risk_to_confidence(latest_ai)
            ai_id = latest_ai.id

        assessment = self.calculate(
            cvss=cvss, asset=asset, exploit=exploit,
            exposure=exposure, ai_conf=ai_conf,
            user_id=user_id, scan_id=scan_task_id,
            ai_analysis_id=ai_id,
            experiment_id=task.experiment_id, source='auto'
        )
        return assessment, None

    def assess_from_ai(self, ai_analysis_id, user_id):
        """
        AI分析完成后自动触发风险评估

        当 AI 分析完成时调用, 利用 AI 输出结果中的 risk_level
        和其他已有数据综合评估
        """
        analysis = db.session.get(AIAnalysis, ai_analysis_id)
        if not analysis:
            return None, 'AI分析不存在'
        if analysis.user_id != user_id:
            return None, '无权操作'

        # AI 可信度直接来自分析结果
        ai_conf = self._ai_risk_to_confidence(analysis)

        # CVSS: 尝试从关联漏洞获取
        cvss = 5.0
        if analysis.vulnerability_id:
            vuln = db.session.get(Vulnerability, analysis.vulnerability_id)
            if vuln:
                cvss = self._severity_to_cvss(vuln.severity)

        # Asset: 尝试从关联实验/扫描推断
        asset = 6.0
        if analysis.experiment_id:
            exp = db.session.get(Experiment, analysis.experiment_id)
            if exp:
                asset = self._target_to_asset(exp.target)
        elif analysis.scan_task_id:
            scan = db.session.get(ScanTask, analysis.scan_task_id)
            if scan:
                asset = self._target_to_asset(scan.target)

        # Exploit
        exploit = 5.0
        if analysis.experiment_id:
            exp = db.session.get(Experiment, analysis.experiment_id)
            if exp:
                exploit = self._experiment_status_to_exploit(exp.status)

        # Exposure
        exposure = 5.0
        if analysis.experiment_id:
            exp = db.session.get(Experiment, analysis.experiment_id)
            if exp:
                exposure = self._target_to_exposure(exp.target)

        assessment = self.calculate(
            cvss=cvss, asset=asset, exploit=exploit,
            exposure=exposure, ai_conf=ai_conf,
            user_id=user_id,
            experiment_id=analysis.experiment_id,
            scan_id=analysis.scan_task_id,
            ai_analysis_id=ai_analysis_id,
            vulnerability_id=analysis.vulnerability_id,
            source='ai'
        )
        return assessment, None

    # ==================== 批量评估 ====================

    def batch_assess_experiments(self, user_id):
        """为用户所有未完成评估的实验生成风险评估"""
        experiments = Experiment.query.filter_by(user_id=user_id).all()
        existing_exp_ids = {
            a.experiment_id for a in RiskAssessment.query.filter(
                RiskAssessment.user_id == user_id,
                RiskAssessment.experiment_id.isnot(None)
            ).all()
        }

        created = 0
        for exp in experiments:
            if exp.id not in existing_exp_ids:
                assessment, error = self.assess_from_experiment(exp.id, user_id)
                if assessment:
                    created += 1
        return created

    # ==================== 查询接口 ====================

    def get_user_assessments(self, user_id=None, page=1, per_page=20):
        """获取风险评估列表 (分页)。

        user_id 为具体用户时只查该用户; 为 None 时查询全部用户
        (管理员全局视图)。
        """
        query = RiskAssessment.query
        if user_id is not None:
            query = query.filter_by(user_id=user_id)
        return query.order_by(
            RiskAssessment.created_time.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

    def get_assessment_by_id(self, assessment_id, user_id=None):
        """获取单条评估记录"""
        assessment = db.session.get(RiskAssessment, assessment_id)
        if not assessment:
            return None, '评估记录不存在'
        if user_id is not None and assessment.user_id != user_id:
            return None, '无权访问'
        return assessment, None

    def delete_assessment(self, assessment_id, user_id=None):
        """删除风险评估记录。

        user_id 为具体用户时只能删除自己的记录; 为 None 时
        (管理员) 可删除任意记录。
        """
        assessment = db.session.get(RiskAssessment, assessment_id)
        if not assessment:
            return False, '评估记录不存在'
        if user_id is not None and assessment.user_id != user_id:
            return False, '无权删除该评估记录'
        db.session.delete(assessment)
        db.session.commit()
        return True, None

    def batch_delete_assessments(self, assessment_ids, user_id=None):
        """批量删除风险评估记录。

        Args:
            assessment_ids: 要删除的 ID 列表
            user_id: 具体用户时只能删自己的; 为 None 时(管理员)可删任意
        Returns:
            (deleted_count, error) 元组
        """
        if not assessment_ids:
            return 0, '未选择任何记录'

        query = RiskAssessment.query.filter(RiskAssessment.id.in_(assessment_ids))
        if user_id is not None:
            query = query.filter_by(user_id=user_id)

        records = query.all()
        if not records:
            return 0, '未找到可删除的记录'

        deleted_count = len(records)
        for r in records:
            db.session.delete(r)
        db.session.commit()

        logger.info('批量删除风险评估: %d 条 (user=%s)', deleted_count, user_id)
        return deleted_count, None

    def get_risk_distribution(self, user_id=None):
        """获取风险等级分布统计"""
        query = db.session.query(
            RiskAssessment.risk_level,
            db.func.count(RiskAssessment.id)
        )
        if user_id:
            query = query.filter(RiskAssessment.user_id == user_id)
        results = query.group_by(RiskAssessment.risk_level).all()

        levels = ['Critical', 'High', 'Medium', 'Low']
        level_map = {r[0]: r[1] for r in results}
        return [{'name': level, 'count': level_map.get(level, 0)} for level in levels]

    def get_score_trend(self, user_id=None, days=30):
        """获取评分趋势 (按日聚合)"""
        from sqlalchemy import func
        from datetime import timedelta, date

        start_date = datetime.now() - timedelta(days=days)
        # 用 SQLite 原生 date() 函数替代 cast(col, Date)
        # 避免 SQLAlchemy Date 类型处理器的 fromisoformat 兼容性问题
        date_col = func.date(RiskAssessment.created_time).label('date')
        query = db.session.query(
            date_col,
            func.avg(RiskAssessment.final_score).label('avg_score'),
            func.count(RiskAssessment.id).label('count')
        ).filter(
            RiskAssessment.created_time >= start_date,
            RiskAssessment.created_time.isnot(None)
        )

        if user_id:
            query = query.filter(RiskAssessment.user_id == user_id)

        results = query.group_by(date_col).all()

        # 有数据的日期 -> {date_str: {avg_score, count}}
        data_map = {
            str(r.date): {'avg_score': round(r.avg_score, 1), 'count': r.count}
            for r in results
        }

        # 补零: 覆盖完整 days 天窗口, 无数据日 count=0 / avg_score=null
        # 升序排列, x 轴时间从左到右递增
        today = datetime.now().date()
        trend = []
        for i in range(days):
            ds = (today - timedelta(days=days - 1 - i)).isoformat()
            if ds in data_map:
                trend.append({'date': ds, **data_map[ds]})
            else:
                trend.append({'date': ds, 'avg_score': None, 'count': 0})
        return trend

    def get_statistics(self, user_id=None):
        """获取风险评估统计概览"""
        query = RiskAssessment.query
        if user_id:
            query = query.filter_by(user_id=user_id)

        total = query.count()
        if total == 0:
            return {
                'total': 0, 'avg_score': 0, 'max_score': 0, 'min_score': 0,
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0
            }

        avg_score = round(db.session.query(
            db.func.avg(RiskAssessment.final_score)
        ).filter(
            RiskAssessment.user_id == user_id if user_id else True
        ).scalar() or 0, 1)

        max_score = round(query.with_entities(
            db.func.max(RiskAssessment.final_score)
        ).scalar() or 0, 1)

        return {
            'total': total,
            'avg_score': avg_score,
            'max_score': max_score,
            'critical': query.filter_by(risk_level='Critical').count(),
            'high': query.filter_by(risk_level='High').count(),
            'medium': query.filter_by(risk_level='Medium').count(),
            'low': query.filter_by(risk_level='Low').count(),
        }

    # ==================== 因素推断辅助方法 ====================

    @staticmethod
    def _severity_to_cvss(severity):
        """漏洞 severity 标签 → CVSS 近似分值"""
        mapping = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5,
        }
        return mapping.get(severity, 5.0)

    @staticmethod
    def _experiment_status_to_exploit(status):
        """实验状态 → 利用成功率"""
        mapping = {
            'success': 10.0,   # 实验成功 → 漏洞可被利用
            'running': 5.0,    # 进行中 → 不确定
            'failed': 2.0,     # 失败 → 利用难度高
            'created': 3.0,    # 未开始 → 未知
            'closed': 5.0,     # 已关闭 → 中间值
        }
        return mapping.get(status, 5.0)

    @staticmethod
    def _target_to_exposure(target):
        """目标地址 → 暴露程度"""
        if not target:
            return 5.0
        target_lower = target.lower()
        # 公网IP或域名
        if any(kw in target_lower for kw in ['http://', 'https://', '.com', '.cn', '.org']):
            return 8.0
        # 内网地址
        if any(kw in target_lower for kw in ['192.168.', '10.', '172.16.', '172.17.', 'localhost', '127.0.0.1']):
            return 5.0
        # DVWA Docker 容器
        if 'dvwa' in target_lower or '8080' in target_lower or '8888' in target_lower:
            return 4.0
        return 5.0

    @staticmethod
    def _target_to_asset(target):
        """目标地址 → 资产重要程度"""
        if not target:
            return 6.0
        target_lower = target.lower()
        # 数据库类
        if any(kw in target_lower for kw in ['mysql', 'mongo', 'redis', 'postgres', '3306', '27017']):
            return 10.0
        # 核心Web应用
        if any(kw in target_lower for kw in ['admin', 'api', 'portal']):
            return 8.0
        # DVWA / 实验环境
        if any(kw in target_lower for kw in ['dvwa', 'lab', 'test', 'localhost']):
            return 3.0
        return 6.0

    @staticmethod
    def _ports_to_cvss(results):
        """开放端口列表 → CVSS 近似分值"""
        if not results:
            return 3.0

        # 敏感端口权重
        sensitive_ports = {
            21: 7.0,   # FTP
            22: 6.0,   # SSH
            23: 8.0,   # Telnet (高危)
            25: 5.0,   # SMTP
            80: 5.0,   # HTTP
            135: 7.0,  # RPC
            139: 7.0,  # NetBIOS
            443: 4.0,  # HTTPS
            445: 8.0,  # SMB (高危)
            1433: 8.0, # MSSQL
            1521: 8.0, # Oracle
            3306: 9.0, # MySQL
            3389: 9.0, # RDP (高危)
            5432: 8.0, # PostgreSQL
            5900: 8.0, # VNC
            6379: 8.0, # Redis
            8080: 5.0, # HTTP Alt
            27017: 9.0 # MongoDB
        }

        max_cvss = 3.0
        for r in results:
            port = getattr(r, 'port', 0)
            if port in sensitive_ports:
                max_cvss = max(max_cvss, sensitive_ports[port])

        # 端口数量越多, 攻击面越大, 额外加分
        port_bonus = min(2.0, len(results) * 0.2)
        return min(10.0, max_cvss + port_bonus)

    @staticmethod
    def _ports_to_exploit(results):
        """开放端口 → 利用成功率"""
        if not results:
            return 2.0

        # 可远程利用的高危端口
        high_risk = {23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
        port_set = {getattr(r, 'port', 0) for r in results}

        if port_set & high_risk:
            return 8.0
        if len(results) > 10:
            return 6.0
        return 4.0

    @staticmethod
    def _ai_risk_to_confidence(analysis):
        """AI分析结果 → AI可信度评分"""
        if not analysis or analysis.status != 'completed':
            return 3.0

        # 基于风险等级和输出完整性
        base = 5.0
        risk_bonus = {'Critical': 3.0, 'High': 2.0, 'Medium': 1.0, 'Low': 0.5, 'Info': 0.0}
        base += risk_bonus.get(analysis.risk_level, 0.0)

        # 输出字段完整度加分
        fields = [analysis.vulnerability_analysis, analysis.possible_attack,
                  analysis.impact, analysis.fix_solution, analysis.security_advice]
        completeness = sum(1 for f in fields if f and len(f) > 10)
        base += completeness * 0.4

        return min(10.0, base)

    @staticmethod
    def _clamp(value, min_val=0.0, max_val=10.0):
        """限制值在合法范围内"""
        return max(min_val, min(max_val, float(value)))
