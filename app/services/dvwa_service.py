"""
DVWA关联服务模块
生成DVWA实验访问地址，实现实验平台与DVWA环境逻辑关联
注意: 当前阶段不实现自动登录DVWA，仅生成关联URL
"""

from urllib.parse import urlencode


class DVWAService:
    """DVWA关联服务类"""

    @staticmethod
    def generate_dvwa_url(target, token, level='low'):
        """
        生成DVWA实验访问地址
        :param target: DVWA目标基础地址 (如 http://192.168.56.101/dvwa)
        :param token: 实验Token
        :param level: DVWA安全等级
        :return: 完整的DVWA访问URL
        """
        if not target:
            return ''

        # 去除末尾斜杠
        base_url = target.rstrip('/')

        # 构建带实验参数的URL
        params = {
            'experiment_token': token,
            'dvwa_level': level
        }
        return f'{base_url}?{urlencode(params)}'

    @staticmethod
    def get_dvwa_security_url(target, level='low'):
        """
        生成DVWA安全等级设置页面URL
        :param target: DVWA目标地址
        :param level: 安全等级
        :return: DVWA安全设置页面URL
        """
        if not target:
            return ''
        base_url = target.rstrip('/')
        # DVWA安全设置页面路径
        return f'{base_url}/security.php'

    @staticmethod
    def validate_target_url(target):
        """
        验证目标地址格式
        :param target: 目标URL
        :return: (True/False, 错误信息)
        """
        if not target:
            return False, '目标地址不能为空'
        if not target.startswith(('http://', 'https://')):
            return False, '目标地址必须以http://或https://开头'
        return True, None
