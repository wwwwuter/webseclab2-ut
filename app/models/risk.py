"""
风险评估模型模块
定义 RiskAssessment 风险评估记录表
实现 WebSecLab 自有的多因素漏洞风险评分模型

评分公式:
  FinalScore = CVSS × 0.35
             + AssetImportance × 0.20
             + ExploitSuccess × 0.20
             + Exposure × 0.10
             + AIConfidence × 0.15

评分区间: 0~100
风险等级: Critical (>=80) / High (>=60) / Medium (>=40) / Low (<40)
"""

from datetime import datetime
from app.extensions import db


class RiskAssessment(db.Model):
    """风险评估记录表"""
    __tablename__ = 'risk_assessments'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户ID (外键)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 关联实验ID (可选)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=True)

    # 关联扫描任务ID (可选)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=True)

    # 关联AI分析ID (可选)
    ai_analysis_id = db.Column(db.Integer, db.ForeignKey('ai_analyses.id'), nullable=True)

    # 关联漏洞ID (可选)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)

    # ===== 五因素评分 (每项 0~10) =====

    # CVSS 漏洞基础评分 (0~10)
    cvss_score = db.Column(db.Float, default=0.0)

    # 资产重要程度 (0~10): 数据库=10, 核心Web=8, 普通Web=6, 测试环境=3
    asset_score = db.Column(db.Float, default=0.0)

    # 漏洞利用成功率 (0~10): 成功=10, 部分成功=5, 失败=0
    exploit_score = db.Column(db.Float, default=0.0)

    # 暴露程度 (0~10): 公网=10, DMZ=7, 内网=5, 隔离=2
    exposure_score = db.Column(db.Float, default=0.0)

    # AI分析可信度 (0~10): 基于AI输出质量和一致性
    ai_score = db.Column(db.Float, default=0.0)

    # ===== 综合评分 =====

    # 最终加权评分 (0~100)
    final_score = db.Column(db.Float, default=0.0)

    # 风险等级: Critical / High / Medium / Low
    risk_level = db.Column(db.String(16), default='Low')

    # 评分明细 (JSON, 记录每项因素的来源和计算过程, 便于论文解释)
    scoring_detail = db.Column(db.Text, default='{}')

    # 评估来源: manual(手动) / auto(自动) / ai(AI辅助)
    source = db.Column(db.String(16), default='auto')

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # ===== 关系 =====
    user = db.relationship('User', backref=db.backref('risk_assessments', lazy='dynamic'))
    experiment = db.relationship('Experiment', backref=db.backref('risk_assessments', lazy='dynamic'))
    scan_task = db.relationship('ScanTask', backref=db.backref('risk_assessments', lazy='dynamic'))
    ai_analysis = db.relationship('AIAnalysis', backref=db.backref('risk_assessments', lazy='dynamic'))
    vulnerability = db.relationship('Vulnerability', backref=db.backref('risk_assessments', lazy='dynamic'))

    # 权重常量 (论文核心参数, 集中管理便于调优)
    WEIGHT_CVSS = 0.35
    WEIGHT_ASSET = 0.20
    WEIGHT_EXPLOIT = 0.20
    WEIGHT_EXPOSURE = 0.10
    WEIGHT_AI = 0.15

    # 风险等级阈值
    THRESHOLD_CRITICAL = 80
    THRESHOLD_HIGH = 60
    THRESHOLD_MEDIUM = 40

    # 风险等级常量
    RISK_CRITICAL = 'Critical'
    RISK_HIGH = 'High'
    RISK_MEDIUM = 'Medium'
    RISK_LOW = 'Low'

    def __repr__(self):
        return f'<RiskAssessment {self.id} score={self.final_score:.1f} [{self.risk_level}]>'

    @property
    def risk_badge(self):
        """风险等级对应的Bootstrap颜色类"""
        badge_map = {
            'Critical': 'dark',
            'High': 'danger',
            'Medium': 'warning',
            'Low': 'info'
        }
        return badge_map.get(self.risk_level, 'secondary')

    @property
    def risk_label(self):
        """风险等级的中文标签"""
        label_map = {
            'Critical': '严重',
            'High': '高危',
            'Medium': '中危',
            'Low': '低危'
        }
        return label_map.get(self.risk_level, self.risk_level)

    @property
    def score_color(self):
        """评分对应的颜色 (用于前端可视化)"""
        if self.final_score >= self.THRESHOLD_CRITICAL:
            return '#212529'  # dark
        elif self.final_score >= self.THRESHOLD_HIGH:
            return '#dc3545'  # red
        elif self.final_score >= self.THRESHOLD_MEDIUM:
            return '#ffc107'  # yellow
        else:
            return '#0dcaf0'  # cyan

    @property
    def score_display(self):
        """格式化评分显示"""
        return f'{self.final_score:.1f}'

    @classmethod
    def classify_risk(cls, score):
        """根据评分划分风险等级"""
        if score >= cls.THRESHOLD_CRITICAL:
            return cls.RISK_CRITICAL
        elif score >= cls.THRESHOLD_HIGH:
            return cls.RISK_HIGH
        elif score >= cls.THRESHOLD_MEDIUM:
            return cls.RISK_MEDIUM
        else:
            return cls.RISK_LOW
