"""
Nmap集成服务模块
调用Nmap进行深度端口扫描和服务版本识别
支持python-nmap库，当不可用时回退到subprocess调用
"""

import subprocess
import json
import shutil


class NmapScanner:
    """Nmap扫描服务类"""

    def __init__(self):
        """初始化Nmap扫描器，检测Nmap是否可用"""
        self.nmap_path = shutil.which('nmap')
        self.available = self.nmap_path is not None

    def is_available(self):
        """检查Nmap是否已安装"""
        return self.available

    def scan(self, target, ports=None):
        """
        执行Nmap扫描
        :param target: 目标IP/域名
        :param ports: 端口范围字符串 (如 '1-1024' 或 None使用默认)
        :return: 扫描结果列表 [{port, protocol, state, service, version, banner}]
        """
        if not self.available:
            return [], 'Nmap未安装，请安装nmap后重试'

        try:
            return self._scan_subprocess(target, ports)
        except Exception as e:
            return [], f'Nmap扫描出错: {str(e)}'

    def _scan_subprocess(self, target, ports=None):
        """
        使用subprocess调用Nmap
        :param target: 目标
        :param ports: 端口范围
        :return: (结果列表, 错误信息)
        """
        # 构建Nmap命令: -sV服务版本探测 -oX XML输出
        cmd = [self.nmap_path, '-sV', '-T4', '--max-retries', '1']

        if ports:
            cmd.extend(['-p', ports])
        else:
            cmd.extend(['-p', '1-1024'])

        # JSON输出格式
        cmd.extend(['-oX', '-', target])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )

            if result.returncode != 0 and not result.stdout:
                return [], f'Nmap执行失败: {result.stderr}'

            return self._parse_nmap_xml(result.stdout), None

        except subprocess.TimeoutExpired:
            return [], 'Nmap扫描超时(>5分钟)'
        except FileNotFoundError:
            return [], 'Nmap命令未找到'

    def _parse_nmap_xml(self, xml_output):
        """
        解析Nmap XML输出
        :param xml_output: Nmap的XML输出字符串
        :return: 结果列表
        """
        results = []

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)

            for host in root.findall('.//host'):
                for port_elem in host.findall('.//port'):
                    port_id = int(port_elem.get('portid', 0))
                    protocol = port_elem.get('protocol', 'tcp').upper()

                    state_elem = port_elem.find('state')
                    state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

                    service_elem = port_elem.find('service')
                    service = ''
                    version = ''
                    banner = ''

                    if service_elem is not None:
                        service = service_elem.get('name', '')
                        product = service_elem.get('product', '')
                        ver = service_elem.get('version', '')
                        extra = service_elem.get('extrainfo', '')

                        version = f'{product} {ver}'.strip() if product else ver
                        banner = f'{product} {ver} {extra}'.strip() if product else ''

                    if port_id > 0:
                        results.append({
                            'port': port_id,
                            'protocol': protocol.upper(),
                            'state': state,
                            'service': service,
                            'version': version[:128],
                            'banner': banner[:500]
                        })

        except Exception:
            pass

        results.sort(key=lambda x: x['port'])
        return results
