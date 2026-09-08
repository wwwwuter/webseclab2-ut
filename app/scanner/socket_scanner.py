"""
多线程Socket端口扫描器
使用ThreadPoolExecutor实现并发TCP Connect扫描
支持Banner探测和服务识别
支持进度回调(on_progress)和取消检测(is_cancelled)
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.scanner.port import get_service_name, BANNER_REQUESTS


class SocketScanner:
    """多线程Socket端口扫描器"""

    def __init__(self, target, ports, timeout=1, max_workers=20, on_progress=None):
        """
        初始化扫描器
        :param target: 目标IP或域名
        :param ports: 端口号列表
        :param timeout: 连接超时时间(秒)
        :param max_workers: 最大线程数
        :param on_progress: 进度回调函数
            签名: on_progress(scanned_so_far, total_ports, found_so_far, current_port)
        """
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_workers = max_workers
        self.on_progress = on_progress
        self._cancelled = False

    def cancel(self):
        """请求取消扫描"""
        self._cancelled = True

    def scan(self):
        """
        执行多线程端口扫描
        使用批量提交 + 批量处理策略，支持进度上报和取消检测
        :return: 扫描结果列表 [{port, protocol, state, service, banner}]
        """
        results = []
        total = len(self.ports)
        processed = 0
        batch_size = max(self.max_workers * 2, 20)

        # 分批提交扫描任务，每批结束后上报进度并检查取消
        for i in range(0, total, batch_size):
            if self._cancelled:
                break

            batch = self.ports[i:i + batch_size]

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, port): port
                    for port in batch
                }

                for future in as_completed(future_to_port):
                    if self._cancelled:
                        break
                    result = future.result()
                    processed += 1
                    if result and result['state'] == 'open':
                        results.append(result)

            # 批量处理完成后上报进度 (降低回调频率，减轻DB压力)
            if self.on_progress and not self._cancelled:
                current_port = self.ports[min(i + batch_size - 1, total - 1)]
                self.on_progress(processed, total, len(results), current_port)

        # 按端口号排序
        results.sort(key=lambda x: x['port'])
        return results

    def _scan_port(self, port):
        """
        扫描单个端口 (TCP Connect Scan)
        :param port: 端口号
        :return: 扫描结果字典 或 None(端口关闭)
        """
        try:
            # 创建TCP Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # TCP Connect
            result = sock.connect_ex((self.target, port))

            if result == 0:
                # 端口开放，尝试Banner识别
                banner = self._grab_banner(sock, port)
                service = get_service_name(port)

                # 从Banner中解析服务版本信息
                version = self._parse_version(banner)

                return {
                    'port': port,
                    'protocol': 'TCP',
                    'state': 'open',
                    'service': service,
                    'version': version,
                    'banner': banner[:500]  # 限制Banner长度
                }

            sock.close()
            return None

        except (ConnectionRefusedError, TimeoutError, OSError, socket.error):
            # 端口关闭或不可达，忽略错误继续扫描
            return None
        except Exception:
            # 捕获所有未预期异常，防止单个端口失败导致整个扫描中断
            return None

    def _grab_banner(self, sock, port):
        """
        尝试获取端口Banner信息
        :param sock: 已连接的Socket对象
        :param port: 端口号
        :return: Banner字符串
        """
        try:
            sock.settimeout(2)

            # 检查是否有预定义的Banner请求
            if port in BANNER_REQUESTS:
                request = BANNER_REQUESTS[port]
                if request:
                    # 替换Host占位符
                    data = request.replace(b'%s', self.target.encode())
                    sock.sendall(data)
            else:
                # 通用: 发送空数据尝试触发响应
                sock.sendall(b'\r\n')

            # 接收响应
            response = sock.recv(4096)
            sock.close()

            if response:
                return self._decode_banner(response)

        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return ''

    @staticmethod
    def _decode_banner(raw_bytes):
        """
        智能解码 Banner 字节序列
        依次尝试: UTF-8 → GBK/GB2312(中文服务器常见) → Latin-1(保底, 不丢字节)
        """
        if not raw_bytes:
            return ''

        # 1. UTF-8（最常见）
        try:
            text = raw_bytes.decode('utf-8')
            # 如果没有替换字符说明解码正常
            if '\ufffd' not in text:
                return ' '.join(text.split())
        except (UnicodeDecodeError, ValueError):
            pass

        # 2. GBK/GB2312（中文 Windows / 国内服务器）
        for enc in ('gbk', 'gb2312', 'gb18030'):
            try:
                text = raw_bytes.decode(enc)
                if '\ufffd' not in text:
                    return ' '.join(text.split())
            except (UnicodeDecodeError, ValueError, LookupError):
                continue

        # 3. Latin-1 保底（映射每个字节到 Unicode 0-255，永不失败）
        text = raw_bytes.decode('latin-1')
        # 过滤掉不可打印的控制字符，保留可见字符
        cleaned = ''.join(ch for ch in text if ch.isprintable() or ch in '\r\n\t')
        return ' '.join(cleaned.split())

    @staticmethod
    def _parse_version(banner):
        """
        从Banner中解析版本信息
        :param banner: Banner字符串
        :return: 版本字符串
        """
        if not banner:
            return ''

        # 提取Server头信息 (HTTP)
        for line in banner.split('\\r\\n'):
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()[:128]

        # 如果Banner较短直接返回
        if len(banner) < 128:
            return banner

        return banner[:128]
