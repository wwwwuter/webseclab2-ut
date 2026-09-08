"""
Prompt模板数据库模型
存储可配置的AI分析Prompt模板，支持管理员在线编辑
"""

from datetime import datetime
from app.extensions import db


class PromptTemplate(db.Model):
    """Prompt模板表"""
    __tablename__ = 'prompt_templates'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 模板唯一标识 (如 vuln_analysis, scan_analysis, custom_analysis)
    template_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # 模板显示名称
    name = db.Column(db.String(128), nullable=False)

    # 模板描述
    description = db.Column(db.Text, default='')

    # 场景分类: general(通用) / sql_injection / xss / file_upload / command_injection / scan
    scene = db.Column(db.String(32), default='general', index=True)

    # 模板内容 (支持 {placeholder} 占位符)
    content = db.Column(db.Text, nullable=False)

    # 可用占位符说明 (JSON格式, 如 {"vulnerability_name": "漏洞名称"})
    available_variables = db.Column(db.Text, default='{}')

    # 是否为系统默认模板 (不可删除)
    is_default = db.Column(db.Boolean, default=False)

    # 是否启用
    is_active = db.Column(db.Boolean, default=True)

    # 版本号 (每次编辑自增, 便于版本追踪)
    version = db.Column(db.Integer, default=1)

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 最后修改时间
    updated_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return f'<PromptTemplate {self.template_key}: {self.name}>'

    @property
    def variable_list(self):
        """解析可用变量列表"""
        import json
        try:
            return json.loads(self.available_variables) if self.available_variables else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    # 系统模板常量
    KEY_VULN_ANALYSIS = 'vuln_analysis'
    KEY_SCAN_ANALYSIS = 'scan_analysis'
    KEY_CUSTOM_ANALYSIS = 'custom_analysis'

    # 场景常量
    SCENE_GENERAL = 'general'
    SCENE_SQL_INJECTION = 'sql_injection'
    SCENE_XSS = 'xss'
    SCENE_FILE_UPLOAD = 'file_upload'
    SCENE_COMMAND_INJECTION = 'command_injection'
    SCENE_SCAN = 'scan'

    SCENE_LABELS = {
        'general': '通用分析',
        'sql_injection': 'SQL注入',
        'xss': 'XSS跨站脚本',
        'file_upload': '文件上传',
        'command_injection': '命令注入',
        'scan': '端口扫描',
    }

    @property
    def scene_label(self):
        """返回场景的中文标签"""
        return self.SCENE_LABELS.get(self.scene, self.scene or '通用')
