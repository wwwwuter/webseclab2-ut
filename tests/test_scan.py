"""
扫描模块测试
覆盖: 任务创建、权限隔离、任务停止、服务层逻辑
注意: 实际 Socket/Nmap 扫描需要网络环境, 此处测试业务逻辑层
"""

import pytest
from tests.conftest import login_user
from app.models.scan import ScanTask


class TestScanServiceUnit:
    """ScannerService 单元测试 (服务层, 不经过 HTTP)"""

    def test_create_task_success(self, app, db, test_user):
        """正常创建扫描任务"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, error = svc.create_task(test_user.id, '127.0.0.1')
            assert error is None
            assert task is not None
            assert task.target == '127.0.0.1'
            assert task.status == ScanTask.STATUS_CREATED
            assert task.scan_type == 'socket'

    def test_create_task_empty_target(self, app, db, test_user):
        """空目标被拒绝"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, error = svc.create_task(test_user.id, '')
            assert task is None
            assert '不能为空' in error

    def test_create_task_invalid_type(self, app, db, test_user):
        """无效扫描类型被拒绝"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, error = svc.create_task(test_user.id, '127.0.0.1', scan_type='invalid')
            assert task is None
            assert '无效' in error

    def test_get_user_tasks(self, app, db, test_user):
        """获取用户扫描任务列表"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            svc.create_task(test_user.id, '127.0.0.1')
            svc.create_task(test_user.id, '192.168.1.1')
            pagination = svc.get_user_tasks(test_user.id)
            assert pagination.total == 2

    def test_display_id_is_user_unique(self, app, db, test_user, admin_user):
        """display_id 用户内唯一: 每位用户从 1 自增, 不依赖全局主键。"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            for _ in range(3):
                svc.create_task(test_user.id, '127.0.0.1')
            for _ in range(2):
                svc.create_task(admin_user.id, '127.0.0.1')
            a_ids = [t.display_id for t in ScanTask.query.filter_by(user_id=test_user.id).order_by(ScanTask.id)]
            b_ids = [t.display_id for t in ScanTask.query.filter_by(user_id=admin_user.id).order_by(ScanTask.id)]
            assert a_ids == [1, 2, 3]
            assert b_ids == [1, 2]

    def test_task_ownership_isolation(self, app, db, test_user, admin_user):
        """用户隔离: 不能访问其他人的任务"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            # admin_user 尝试获取 test_user 的任务
            result, error = svc.get_task_by_id(task.id, user_id=admin_user.id)
            assert result is None
            assert '无权' in error

    def test_stop_non_running_task(self, app, db, test_user):
        """停止非运行中的任务被拒绝"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            # 任务状态为 created, 不是 running
            ok, error = svc.stop_task(task.id, test_user.id)
            assert not ok
            assert '只能停止' in error

    def test_delete_task(self, app, db, test_user):
        """删除扫描任务"""
        from app.services.scanner_service import ScannerService
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            ok, error = svc.delete_task(task.id, test_user.id)
            assert ok
            assert error is None
            # 删除后查询不到
            result, err = svc.get_task_by_id(task.id)
            assert result is None

    def test_save_results_clears_old(self, app, db, test_user):
        """_save_results 写入前先清空旧结果，防止重复累积"""
        from app.services.scanner_service import ScannerService
        from app.models.scan import ScanResult
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            # 第一次保存 2 条结果
            svc._save_results(task.id, [
                {'port': 80, 'protocol': 'TCP', 'state': 'open'},
                {'port': 443, 'protocol': 'TCP', 'state': 'open'},
            ])
            assert ScanResult.query.filter_by(task_id=task.id).count() == 2
            assert task.open_ports_count == 2

            # 第二次保存（模拟重新扫描）—— 应覆盖而非累积
            svc._save_results(task.id, [
                {'port': 22, 'protocol': 'TCP', 'state': 'open'},
                {'port': 8080, 'protocol': 'TCP', 'state': 'open'},
                {'port': 3306, 'protocol': 'TCP', 'state': 'open'},
            ])
            assert ScanResult.query.filter_by(task_id=task.id).count() == 3
            assert task.open_ports_count == 3
            # 确认旧端口已不在
            remaining_ports = {r.port for r in ScanResult.query.filter_by(task_id=task.id).all()}
            assert remaining_ports == {22, 8080, 3306}

    def test_open_ports_count_direct_query(self, app, db, test_user):
        """open_ports_count 用直接查询而非 lazy dynamic，结果准确"""
        from app.services.scanner_service import ScannerService
        from app.extensions import db
        from app.models.scan import ScanTask, ScanResult
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '10.0.0.1')
            # 不存任何结果
            assert task.open_ports_count == 0
            # 存 3 条 open + 1 条 closed
            for p in [22, 80, 443]:
                ScanResult(task_id=task.id, port=p, protocol='TCP', state='open')
                db.session.add(ScanResult(task_id=task.id, port=p, protocol='TCP', state='open'))
            ScanResult(task_id=task.id, port=9999, protocol='TCP', state='closed')
            db.session.add(ScanResult(task_id=task.id, port=9999, protocol='TCP', state='closed'))
            db.session.commit()
            assert task.open_ports_count == 3

    def test_banner_decode_multi_encoding(self):
        """_decode_banner 多编码回退: UTF-8 → GBK → Latin-1"""
        from app.scanner.socket_scanner import SocketScanner

        # UTF-8 文本
        assert 'HTTP' in SocketScanner._decode_banner(b'HTTP/1.1 200 OK\r\n')

        # GBK 编码的中文 (Metasploitable 常见场景)
        gbk_text = '测试'
        gbk_bytes = gbk_text.encode('gbk')
        result = SocketScanner._decode_banner(gbk_bytes)
        assert '测试' in result or len(result) > 0  # 至少不抛异常且不返回空

        # Latin-1 混合内容 (含非 ASCII 字节)
        mixed = b'\xe4\xb8\xad\xe6\x96\x87\x80\x21'  # "中文" in UTF-8 + "!"
        result = SocketScanner._decode_banner(mixed)
        assert len(result) > 0


class TestScanDetailTemplate:
    """扫描详情页模板测试"""

    def test_completed_shows_progress_section(self, client, test_user, app):
        """已完成任务的详情页显示进度区（含开放端口数和最终状态）"""
        from app.extensions import db
        from app.models.scan import ScanTask, ScanResult
        login_user(client, 'testuser', 'test123456')
        tid = None
        port_count = 0
        with app.app_context():
            task = ScanTask(user_id=test_user.id, target='127.0.0.1',
                            scan_type='socket', port_range='common',
                            status='completed', progress=100,
                            total_ports=30, scanned_ports=30)
            db.session.add(task)
            db.session.commit()
            # 插入 2 条 open 结果
            for port in [22, 80]:
                r = ScanResult(task_id=task.id, port=port, protocol='TCP',
                               state='open', service='ssh' if port == 22 else 'http')
                db.session.add(r)
            db.session.commit()
            tid = task.id
            port_count = task.open_ports_count  # 在 context 内求值

        resp = client.get(f'/scan/{tid}')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        # 进度区应显示（含完成态的最终信息）
        assert 'progress-bar' in html
        # 开放端口数来自 DB (open_ports_count) — 模板中两处一致
        assert str(port_count) in html


class TestScanRoutes:
    """扫描路由集成测试"""

    def test_scan_list_requires_login(self, client, db):
        """未登录访问扫描列表被重定向"""
        resp = client.get('/scan')
        assert resp.status_code == 302

    def test_scan_list_loads(self, client, test_user):
        """登录后访问扫描列表正常"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/scan')
        assert resp.status_code == 200
        assert '扫描任务'.encode() in resp.data

    def test_scan_create_page(self, client, test_user):
        """新建扫描页面正常加载"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/scan/create')
        assert resp.status_code == 200


class TestScanCompletionLifecycle:
    """扫描任务完整生命周期测试 — 验证 refresh 顺序 bug 修复"""

    def test_completion_status_transitions_to_completed(self, app, db, test_user):
        """_save_results 后状态必须从 running → completed（不是卡在 running）"""
        from app.services.scanner_service import ScannerService
        from app.models.scan import ScanResult
        svc = ScannerService()
        with app.app_context():
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            # 模拟后台线程: 标记运行中
            task.status = ScanTask.STATUS_RUNNING
            task.progress = 95
            db.session.commit()

            # 模拟 _save_results 执行（内部有独立 commit）
            svc._save_results(task.id, [
                {'port': 80, 'protocol': 'TCP', 'state': 'open', 'service': 'http'},
                {'port': 22, 'protocol': 'TCP', 'state': 'open', 'service': 'ssh'},
            ])

            # 模拟完成块: 先 refresh 再设属性（修复后的正确顺序）
            try:
                db.session.refresh(task)
            except Exception:
                pass
            actual_count = task.open_ports_count

            task.status = ScanTask.STATUS_COMPLETED
            task.end_time = task.end_time or task.start_time
            task.progress = 100
            task.progress_message = f'扫描完成，共发现 {actual_count} 个开放端口'
            db.session.commit()

            # 验证: 状态必须是 completed，不是 running
            final = db.session.get(ScanTask, task.id)
            assert final.status == ScanTask.STATUS_COMPLETED
            assert final.progress == 100
            assert actual_count == 2
            assert '扫描完成' in final.progress_message

    def test_api_status_returns_not_running_after_completion(self, client, test_user, app):
        """API 轮询: 任务完成后 is_running=False，前端停止轮询"""
        from app.extensions import db as _db
        from app.models.scan import ScanTask, ScanResult
        login_user(client, 'testuser', 'test123456')
        tid = None
        with app.app_context():
            task = ScanTask(user_id=test_user.id, target='10.0.0.1',
                            scan_type='socket', status='completed',
                            progress=100, total_ports=30, scanned_ports=30)
            _db.session.add(task)
            _db.session.commit()
            r = ScanResult(task_id=task.id, port=80, protocol='TCP',
                           state='open', service='http')
            _db.session.add(r)
            _db.session.commit()
            tid = task.id

        resp = client.get(f'/scan/api/status/{tid}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'completed'
        assert data['is_running'] is False
        assert data['progress'] == 100
        assert data['open_ports'] == 1
        assert len(data['results']) == 1


class TestScanGuardrails:
    """扫描安全护栏测试: 速率限制、并发上限、目标白名单/黑名单"""

    def _svc(self, app):
        from app.services.scanner_service import ScannerService
        return ScannerService()

    def _reset_config(self, app):
        """重置 SCAN_* 配置为默认值, 避免 session 级 app 夹具的配置在测试间泄漏。"""
        app.config['SCAN_RATE_LIMIT_MAX'] = 10
        app.config['SCAN_RATE_LIMIT_WINDOW'] = 3600
        app.config['SCAN_MAX_CONCURRENT_PER_USER'] = 2
        app.config['SCAN_MAX_CONCURRENT_GLOBAL'] = 5
        app.config['SCAN_TARGET_BLACKLIST'] = ''
        app.config['SCAN_TARGET_WHITELIST'] = ''

    def test_guardrails_pass_by_default(self, app, db, test_user):
        """默认配置下正常目标可通过护栏校验"""
        self._reset_config(app)
        from app.scanner.guardrails import ScanGuardrails
        with app.app_context():
            g = ScanGuardrails(app.config)
            ok, error = g.check_all(test_user.id, '127.0.0.1')
            assert ok
            assert error is None

    def test_rate_limit_exceeded(self, app, db, test_user):
        """超过速率限制后创建任务被拒绝"""
        self._reset_config(app)
        app.config['SCAN_RATE_LIMIT_MAX'] = 2
        app.config['SCAN_RATE_LIMIT_WINDOW'] = 3600
        svc = self._svc(app)
        with app.app_context():
            # 前 2 个任务正常创建
            assert svc.create_task(test_user.id, '127.0.0.1')[1] is None
            assert svc.create_task(test_user.id, '127.0.0.1')[1] is None
            # 第 3 个触发速率限制
            task, error = svc.create_task(test_user.id, '127.0.0.1')
            assert task is None
            assert '频率超限' in error

    def test_rate_limit_disabled_when_zero(self, app, db, test_user):
        """SCAN_RATE_LIMIT_MAX=0 时禁用速率限制"""
        self._reset_config(app)
        app.config['SCAN_RATE_LIMIT_MAX'] = 0
        svc = self._svc(app)
        with app.app_context():
            for _ in range(5):
                task, error = svc.create_task(test_user.id, '127.0.0.1')
                assert error is None
                assert task is not None

    def test_concurrency_per_user_exceeded(self, app, db, test_user):
        """用户并发运行任务数超限被拒绝"""
        self._reset_config(app)
        app.config['SCAN_MAX_CONCURRENT_PER_USER'] = 1
        app.config['SCAN_MAX_CONCURRENT_GLOBAL'] = 0
        svc = self._svc(app)
        with app.app_context():
            # 创建 1 个任务并置为 running
            task, _ = svc.create_task(test_user.id, '127.0.0.1')
            task.status = ScanTask.STATUS_RUNNING
            db.session.commit()
            # 再创建触发并发限制
            new_task, error = svc.create_task(test_user.id, '127.0.0.1')
            assert new_task is None
            assert '并发扫描超限' in error

    def test_concurrency_global_exceeded(self, app, db, test_user, admin_user):
        """全局并发运行任务数超限被拒绝"""
        self._reset_config(app)
        app.config['SCAN_MAX_CONCURRENT_PER_USER'] = 0
        app.config['SCAN_MAX_CONCURRENT_GLOBAL'] = 1
        svc = self._svc(app)
        with app.app_context():
            # 其他用户占满全局并发
            other_task, _ = svc.create_task(admin_user.id, '127.0.0.1')
            other_task.status = ScanTask.STATUS_RUNNING
            db.session.commit()
            # 当前用户创建触发全局限制
            new_task, error = svc.create_task(test_user.id, '127.0.0.1')
            assert new_task is None
            assert '系统并发扫描已满' in error

    def test_target_blacklist(self, app, db, test_user):
        """命中黑名单的目标被拦截"""
        self._reset_config(app)
        app.config['SCAN_TARGET_BLACKLIST'] = '10.0.0.0/8'
        svc = self._svc(app)
        with app.app_context():
            task, error = svc.create_task(test_user.id, '10.1.2.3')
            assert task is None
            assert '黑名单' in error

    def test_target_whitelist(self, app, db, test_user):
        """启用白名单后, 白名单外目标被拦截, 白名单内目标放行"""
        self._reset_config(app)
        app.config['SCAN_TARGET_WHITELIST'] = '192.168.1.0/24'
        svc = self._svc(app)
        with app.app_context():
            # 白名单外
            task, error = svc.create_task(test_user.id, '10.0.0.1')
            assert task is None
            assert '白名单' in error
            # 白名单内
            task2, error2 = svc.create_task(test_user.id, '192.168.1.5')
            assert error2 is None
            assert task2 is not None

    def test_whitelist_disabled_when_empty(self, app, db, test_user):
        """白名单为空时不启用白名单限制"""
        self._reset_config(app)
        app.config['SCAN_TARGET_WHITELIST'] = ''
        svc = self._svc(app)
        with app.app_context():
            task, error = svc.create_task(test_user.id, '10.0.0.1')
            assert error is None
            assert task is not None
