"""
扫描任务管理服务模块
封装扫描任务创建、执行、结果保存等业务逻辑
融合Socket扫描和Nmap扫描
支持异步后台执行，前端通过轮询获取进度
"""

import os
import re
import socket
import ipaddress
import threading
import logging
from datetime import datetime
from flask import current_app
from app.extensions import db
from app.models.scan import ScanTask, ScanResult
from app.scanner.socket_scanner import SocketScanner
from app.scanner.port import get_port_list
from app.services.nmap_service import NmapScanner

logger = logging.getLogger(__name__)


# ==================== SSRF 防护 ====================

# 云元数据地址 (169.254.0.0/16) 始终拦截, 即使显式允许内网扫描也不例外,
# 防止通过扫描目标读取云实例凭证 (经典 SSRF 危害)。
_METADATA_NETWORK = ipaddress.ip_network('169.254.0.0/16')


def _normalize_scan_target(raw):
    """
    从用户输入中解析出 host 与 port, 去除协议头/scheme、路径与查询参数。
    支持 IPv4 / IPv6(含 [::1]:port 形式) / 主机名:port。
    """
    t = (raw or '').strip()
    # 去除协议头 (http:// https:// ftp://)
    t = re.sub(r'^(https?|ftp)://', '', t, flags=re.IGNORECASE)
    # 去掉路径与查询
    t = t.split('/')[0].split('?')[0]
    if not t:
        return '', None

    # IPv6 形式 [::1]:port
    if t.startswith('['):
        m = re.match(r'^\[(.+?)\](?::(\d+))?$', t)
        if m:
            return m.group(1), (int(m.group(2)) if m.group(2) else None)
        return t, None

    # 含冒号: 可能是 host:port 或 IPv6 字面量
    if ':' in t:
        try:
            ipaddress.ip_address(t)  # 纯 IPv6 字面量 (无端口)
            return t, None
        except ValueError:
            pass
        host, _, p = t.rpartition(':')
        if host and p.isdigit():
            return host, int(p)
        return t, None

    return t, None


def _is_blocked_ip(ip, allow_private):
    """判断单个 IP 是否应被 SSRF 防护拦截。"""
    # 云元数据地址: 无论是否允许内网, 始终拦截
    if ip.version == 4 and ip in _METADATA_NETWORK:
        return True
    if allow_private:
        # 实验环境显式允许内网扫描时, 仅保留元数据地址的硬性拦截
        return False
    # 默认 (生产/未授权) 拦截所有内网/保留/回环/链路本地/多播地址
    if (ip.is_loopback or ip.is_unspecified or ip.is_private
            or ip.is_link_local or ip.is_multicast or ip.is_reserved):
        return True
    return False


def _target_is_ssrf_blocked(raw_target, allow_private):
    """扫描目标是否指向内网/保留地址 (SSRF 防护)。主机名会解析全部 A/AAAA 记录。"""
    host, _ = _normalize_scan_target(raw_target)
    if not host:
        return False
    # IP 字面量直接判断
    try:
        return _is_blocked_ip(ipaddress.ip_address(host), allow_private)
    except ValueError:
        pass
    # 主机名: 解析所有记录, 任一命中内网即拦截
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        # 无法解析: 不视为 SSRF 命中, 交由扫描阶段正常报错
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip, allow_private):
            return True
    return False


class ScannerService:
    """扫描任务管理服务类"""

    def __init__(self):
        self.nmap_scanner = NmapScanner()

    # ==================== 任务创建 ====================

    def create_task(self, user_id, target, scan_type='socket', port_range='common', experiment_id=None):
        """
        创建扫描任务
        :param user_id: 用户ID
        :param target: 扫描目标
        :param scan_type: 扫描类型 (socket/nmap/both)
        :param port_range: 端口范围
        :param experiment_id: 关联实验ID (可选)
        :return: (ScanTask对象, 错误信息)
        """
        if not target or not target.strip():
            return None, '扫描目标不能为空'

        # SSRF 防护: 拦截指向内网/保留地址的扫描目标 (云元数据地址始终拦截)
        # WebSecLab 是安全实验平台, 用户需要扫描内网/VM 目标做实验,
        # 默认允许私有地址扫描; 仅硬性拦截云元数据地址 (169.254.0.0/16) 防止凭证泄露。
        # 如需恢复严格 SSRF 拦截, 设置环境变量 SCAN_ALLOW_PRIVATE_TARGETS=false
        allow_private = os.environ.get('SCAN_ALLOW_PRIVATE_TARGETS', 'true').lower() in ('1', 'true', 'yes', 'on')
        if _target_is_ssrf_blocked(target, allow_private):
            return None, (
                '扫描目标指向云元数据地址 (169.254.0.0/16), 已被安全策略拦截。'
            )

        if scan_type not in ['socket', 'nmap', 'both']:
            return None, '无效的扫描类型'

        # Nmap类型检查Nmap是否可用
        if scan_type in ['nmap', 'both'] and not self.nmap_scanner.is_available():
            return None, 'Nmap未安装，请选择Socket扫描或安装Nmap'

        task = ScanTask(
            user_id=user_id,
            target=target.strip(),
            scan_type=scan_type,
            port_range=port_range,
            experiment_id=experiment_id or None,
            status=ScanTask.STATUS_CREATED
        )
        # 用户内展示序号: 用纯 SQL 查最大值 (避免 ORM 在 display_id 列尚未就绪时报 no such column)
        try:
            from sqlalchemy import func, text
            max_seq = db.session.query(func.max(ScanTask.display_id)).filter_by(user_id=user_id).scalar()
            task.display_id = (max_seq or 0) + 1
        except Exception:
            # 列尚不存在时 (迁移尚未执行或失败), 先用 None 占位; 启动迁移会补回填
            task.display_id = None
        db.session.add(task)
        db.session.commit()
        return task, None

    # ==================== 任务调度 ====================

    def dispatch_task(self, task_id):
        """
        派发扫描任务到后台线程异步执行
        立即返回，不阻塞请求线程
        :param task_id: 任务ID
        :return: (bool, 错误信息)
        """
        task = db.session.get(ScanTask, task_id)
        if not task:
            return False, '扫描任务不存在'

        if task.status != ScanTask.STATUS_CREATED:
            return False, f'任务当前状态为 {task.status_label}，无法执行'

        # 获取 Flask 应用实例，传递给后台线程使用独立的 app context
        app = current_app._get_current_object()

        thread = threading.Thread(
            target=self._execute_in_background,
            args=(task_id, app),
            daemon=True,
            name=f'scan-worker-{task_id}'
        )
        thread.start()

        return True, None

    # ==================== 后台执行 ====================

    def _execute_in_background(self, task_id, app):
        """
        在后台线程中执行扫描任务
        使用独立的 Flask app context 和 DB session，避免与主请求线程冲突

        设计要点:
        1. 后台线程必须创建自己的 app context，才能使用 Flask 扩展 (如 SQLAlchemy)
        2. 进度通过 on_progress 回调实时更新到数据库
        3. 扫描结果在全部完成后一次性批量写入，减少 DB 锁竞争
        4. 异常安全：任何异常都会被捕获并记录到任务的 error_message
        """
        with app.app_context():
            task = db.session.get(ScanTask, task_id)
            if not task:
                logger.error(f'后台扫描线程: 任务 {task_id} 不存在')
                return

            # 标记为运行中
            task.status = ScanTask.STATUS_RUNNING
            task.start_time = datetime.now()
            task.progress = 0
            task.progress_message = '扫描准备中...'
            db.session.commit()

            try:
                all_results = []
                nmap_scanner = NmapScanner()

                # ---- 进度回调函数 ----
                # 闭包捕获 task，通过独立事务更新进度
                # 同时检测任务是否被外部停止 (stop_task 修改了 status)
                def on_progress(scanned, total, found, current_port):
                    try:
                        # 检测外部停止信号 (stop_task 将 status 设为 failed)
                        db.session.refresh(task)
                        if task.status != ScanTask.STATUS_RUNNING:
                            scanner.cancel()
                            return

                        task.total_ports = total
                        task.scanned_ports = scanned
                        task.progress = int(scanned / total * 90)  # Socket阶段占90%，留10%给Nmap/保存
                        task.progress_message = f'已扫描 {scanned}/{total} 个端口，发现 {found} 个开放端口'
                        db.session.commit()
                    except Exception as e:
                        logger.warning(f'进度更新失败: {e}')
                        db.session.rollback()

                # ---- Socket扫描阶段 ----
                if task.scan_type in ['socket', 'both']:
                    ports = get_port_list(task.port_range)
                    task.total_ports = len(ports)
                    task.progress_message = f'Socket扫描准备中，共 {len(ports)} 个端口...'
                    db.session.commit()

                    scanner = SocketScanner(
                        task.target, ports,
                        timeout=1, max_workers=20,
                        on_progress=on_progress
                    )
                    socket_results = scanner.scan()
                    all_results.extend(socket_results)

                # Socket扫描后检查是否被外部停止
                db.session.refresh(task)
                if task.status != ScanTask.STATUS_RUNNING:
                    logger.info(f'扫描任务 #{task_id} 被外部停止')
                    return

                # ---- Nmap扫描阶段 ----
                if task.scan_type in ['nmap', 'both']:
                    task.progress = 90
                    task.progress_message = '正在执行Nmap深度扫描...'
                    db.session.commit()

                    nmap_port_range = task.port_range if task.port_range != 'common' else '1-1024'
                    nmap_results, error = nmap_scanner.scan(task.target, nmap_port_range)

                    if error:
                        if task.scan_type == 'nmap':
                            task.status = ScanTask.STATUS_FAILED
                            task.error_message = error
                            task.end_time = datetime.now()
                            task.progress = 100
                            db.session.commit()
                            return
                        # both模式: Nmap失败继续用Socket结果
                        logger.warning(f'Nmap扫描失败(both模式继续): {error}')
                    else:
                        if task.scan_type == 'nmap':
                            all_results = nmap_results
                        else:
                            all_results = self._merge_results(all_results, nmap_results)

                # ---- 批量保存结果 ----
                task.progress = 95
                task.progress_message = f'扫描完成，正在保存 {len(all_results)} 条结果...'
                db.session.commit()

                self._save_results(task.id, all_results)

                # ---- 更新任务状态为完成 ----
                # 先 refresh 获取 _save_results 提交后的最新 DB 状态，
                # 再设置完成属性（refresh 必须在赋值之前，否则会覆盖脏标记！）
                try:
                    db.session.refresh(task)
                except Exception:
                    pass  # 对象可能已脱离 session（测试场景），忽略

                actual_count = task.open_ports_count
                # 防御: DB 查询返回 0 但内存列表有结果时，以内存为准（极端 session 隔离场景）
                if actual_count == 0 and len(all_results) > 0:
                    logger.warning(
                        f'扫描任务 #{task_id}: open_ports_count 返回 0 '
                        f'但内存有 {len(all_results)} 条结果，使用内存计数'
                    )
                    actual_count = len(all_results)

                task.status = ScanTask.STATUS_COMPLETED
                task.end_time = datetime.now()
                task.progress = 100
                task.progress_message = f'扫描完成，共发现 {actual_count} 个开放端口'
                db.session.commit()

                logger.info(f'扫描任务 #{task_id} 完成: {actual_count} 个开放端口')

            except Exception as e:
                logger.error(f'扫描任务 #{task_id} 异常: {e}', exc_info=True)
                # 检查任务是否已被外部停止，避免覆盖停止状态
                db.session.refresh(task)
                if task.status == ScanTask.STATUS_RUNNING:
                    task.status = ScanTask.STATUS_FAILED
                    task.error_message = f'扫描执行失败: {str(e)}'
                    task.end_time = datetime.now()
                    task.progress = 100
                    db.session.commit()

    # ==================== 任务停止 ====================

    def stop_task(self, task_id, user_id):
        """
        停止正在运行的扫描任务
        注意: Socket扫描在批次间检查取消标记，不是即时中断
        :param task_id: 任务ID
        :param user_id: 当前用户ID (权限验证)
        :return: (bool, 错误信息)
        """
        task = db.session.get(ScanTask, task_id)
        if not task:
            return False, '扫描任务不存在'
        if not task.is_owner(user_id):
            return False, '无权操作该扫描任务'
        if task.status != ScanTask.STATUS_RUNNING:
            return False, '只能停止正在运行的任务'

        task.status = ScanTask.STATUS_FAILED
        task.error_message = '用户手动停止扫描'
        task.end_time = datetime.now()
        db.session.commit()
        return True, None

    # ==================== 任务查询 ====================

    def get_user_tasks(self, user_id, page=1, per_page=10):
        """获取用户的扫描任务列表 (分页)"""
        return ScanTask.query.filter_by(user_id=user_id).order_by(
            ScanTask.created_time.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

    def get_task_by_id(self, task_id, user_id=None):
        """
        获取任务详情 (带用户隔离)
        :param task_id: 任务ID
        :param user_id: 当前用户ID (None表示不验证)
        :return: (ScanTask对象, 错误信息)
        """
        task = db.session.get(ScanTask, task_id)
        if not task:
            return None, '扫描任务不存在'
        if user_id is not None and not task.is_owner(user_id):
            return None, '无权访问该扫描任务'
        return task, None

    def get_task_results(self, task_id):
        """获取任务的扫描结果"""
        return ScanResult.query.filter_by(task_id=task_id).order_by(ScanResult.port).all()

    # ==================== 任务删除 ====================

    def delete_task(self, task_id, user_id):
        """删除扫描任务及其结果"""
        task = db.session.get(ScanTask, task_id)
        if not task:
            return False, '扫描任务不存在'
        if not task.is_owner(user_id):
            return False, '无权删除该扫描任务'

        ScanResult.query.filter_by(task_id=task_id).delete()
        db.session.delete(task)
        db.session.commit()
        return True, None

    def batch_delete_tasks(self, task_ids, user_id):
        """
        批量删除扫描任务（仅允许删除已完成/失败的任务）
        :param task_ids: 任务ID列表
        :param user_id: 当前用户ID
        :return: (成功数, 跳过原因列表)
        """
        deleted = 0
        skipped = []
        allowed_statuses = ('completed', 'failed')

        for tid in task_ids:
            task = db.session.get(ScanTask, int(tid))
            if not task:
                skipped.append(f'任务 {tid} 不存在')
                continue
            if not task.is_owner(user_id):
                skipped.append(f'任务 {tid} 无权删除')
                continue
            if task.status in ('running', 'created'):
                skipped.append(f'任务 {tid} 正在运行，请先停止')
                continue

            ScanResult.query.filter_by(task_id=tid).delete()
            db.session.delete(task)
            deleted += 1

        if deleted > 0:
            db.session.commit()

        return deleted, skipped

    # ==================== 内部方法 ====================

    @staticmethod
    def _sanitize_string(text, max_len=128):
        """
        清洗扫描结果中的非打印字符和二进制乱码
        支持字符串和字节输入; 多编码回退 (UTF-8 → GBK → Latin-1)
        """
        if not text:
            return ''
        # 字节输入: 智能解码
        if isinstance(text, bytes):
            for enc in ('utf-8', 'gbk', 'gb2312', 'latin-1'):
                try:
                    decoded = text.decode(enc)
                    # UTF-8/GBK 无替换字符则采用
                    if enc != 'latin-1' and '\ufffd' not in decoded:
                        text = decoded
                        break
                    elif enc == 'latin-1':
                        text = decoded
                        break
                except (UnicodeDecodeError, ValueError, LookupError):
                    continue
            else:
                text = text.decode('utf-8', errors='replace')
        # 移除控制字符 (保留空格/换行/制表符)
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
        # 移除 Unicode 替换字符
        text = text.replace('\ufffd', '')
        return text.strip()[:max_len]

    def _save_results(self, task_id, results):
        """
        批量保存扫描结果到数据库
        先清空该任务的旧结果再写入，防止重复累积（重新扫描等场景）
        使用单次事务提交，减少DB锁竞争
        :param task_id: 任务ID
        :param results: 扫描结果列表
        """
        ScanResult.query.filter_by(task_id=task_id).delete()
        for r in results:
            scan_result = ScanResult(
                task_id=task_id,
                port=r['port'],
                protocol=r.get('protocol', 'TCP'),
                state=r.get('state', 'open'),
                service=self._sanitize_string(r.get('service', ''), 64),
                version=self._sanitize_string(r.get('version', ''), 128),
                banner=self._sanitize_string(r.get('banner', ''), 500)
            )
            db.session.add(scan_result)
        db.session.commit()

    @staticmethod
    def _merge_results(socket_results, nmap_results):
        """
        合并Socket和Nmap扫描结果，Nmap的服务版本信息优先
        :param socket_results: Socket扫描结果
        :param nmap_results: Nmap扫描结果
        :return: 合并后的结果列表
        """
        merged = {}

        # 先放入Socket结果
        for r in socket_results:
            merged[r['port']] = r.copy()

        # Nmap结果覆盖或补充
        for r in nmap_results:
            port = r['port']
            if port in merged:
                if r.get('service'):
                    merged[port]['service'] = r['service']
                if r.get('version'):
                    merged[port]['version'] = r['version']
                if r.get('banner'):
                    merged[port]['banner'] = r['banner']
            else:
                merged[port] = r.copy()

        results = list(merged.values())
        results.sort(key=lambda x: x['port'])
        return results
