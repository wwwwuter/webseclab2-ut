"""Models包初始化 - 导入所有模型以便Flask-Migrate发现"""

from app.models.user import User
from app.models.login_log import LoginLog
from app.models.vulnerability import VulnerabilityCategory, OWASPCategory, Vulnerability
from app.models.experiment import Experiment, ExperimentLog
from app.models.scan import ScanTask, ScanResult
from app.models.ai_analysis import AIAnalysis
from app.models.report import Report
from app.models.prompt_template import PromptTemplate
from app.models.risk import RiskAssessment
from app.models.rbac import Role, Permission, role_permissions, user_roles
