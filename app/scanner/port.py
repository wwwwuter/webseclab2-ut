"""
端口与服务映射模块
定义常用端口列表、服务名称映射、Banner探测请求模板
"""

# 常用端口列表 (按使用频率排序)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888, 9090, 27017, 6379, 11211, 5432, 1433, 1521, 2049
]

# 端口到服务名称的映射
PORT_SERVICE_MAP = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPCBind',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    1723: 'PPTP',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt',
    9090: 'WebConsole',
    11211: 'Memcached',
    27017: 'MongoDB'
}

# Banner探测请求模板 (端口 -> 请求数据)
BANNER_REQUESTS = {
    80: b'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n',
    443: b'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n',
    8080: b'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n',
    8888: b'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n',
    21: b'',   # FTP自动返回banner
    22: b'',   # SSH自动返回banner
    25: b'',   # SMTP自动返回banner
    3306: b'', # MySQL自动返回banner
    6379: b'INFO\r\n',  # Redis INFO命令
}


def get_service_name(port):
    """
    根据端口号获取服务名称
    :param port: 端口号
    :return: 服务名称字符串
    """
    return PORT_SERVICE_MAP.get(port, f'Unknown-{port}')


def get_port_list(port_range_str):
    """
    解析端口范围字符串，返回端口列表
    :param port_range_str: 端口范围 (如 '1-1024', 'common', '80,443,8080')
    :return: 端口号列表
    """
    if port_range_str == 'common':
        return COMMON_PORTS

    # 逗号分隔的端口列表
    if ',' in port_range_str:
        try:
            return [int(p.strip()) for p in port_range_str.split(',') if p.strip().isdigit()]
        except ValueError:
            return COMMON_PORTS

    # 范围格式: start-end
    if '-' in port_range_str:
        try:
            parts = port_range_str.split('-')
            start = int(parts[0])
            end = int(parts[1])
            start = max(1, start)
            end = min(65535, end)
            if start > end:
                start, end = end, start
            # 限制最大扫描范围防止过慢
            if end - start > 10000:
                end = start + 10000
            return list(range(start, end + 1))
        except (ValueError, IndexError):
            return COMMON_PORTS

    # 单个端口
    if port_range_str.isdigit():
        port = int(port_range_str)
        if 1 <= port <= 65535:
            return [port]

    return COMMON_PORTS
