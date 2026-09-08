"""
Dashboard统计服务模块
提供安全态势可视化数据
"""

from datetime import datetime, timedelta
from sqlalchemy import func, case
from app.extensions import db
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilityCategory
from app.models.experiment import Experiment
from app.models.scan import ScanTask, ScanResult
from app.models.ai_analysis import AIAnalysis
from app.models.report import Report
from app.models.risk import RiskAssessment
from app.models.prompt_template import PromptTemplate


# ==================== 告警阈值 (集中配置, 避免硬编码散落) ====================
ALERT_THRESHOLDS = {
    'high_risk_recent': 5,        # 近24h 高危(Critical+High)评估数阈值
    'failed_experiments': 3,      # 近24h 失败实验数阈值
    'scan_abuse_count': 20,       # 单用户近1h 扫描次数阈值
    'scan_abuse_window': 1,       # 扫描滥用检测窗口(小时)
    'new_users': 10,              # 近24h 新增用户数阈值
}


class DashboardService:
    """Dashboard统计服务类"""

    def get_user_dashboard(self, user_id):
        """
        获取普通用户Dashboard数据
        :return: 统计数据字典
        """
        return {
            'user_stats': self._get_user_stats(user_id),
            'experiment_stats': self._get_user_experiment_stats(user_id),
            'scan_stats': self._get_user_scan_stats(user_id),
            'ai_stats': self._get_user_ai_stats(user_id),
            'report_stats': self._get_user_report_stats(user_id),
            'risk_distribution': self._get_user_risk_distribution(user_id),
            'experiment_status_chart': self._get_user_experiment_status(user_id),
            'risk_stats': self._get_risk_stats(user_id=user_id),
            'risk_score_distribution': self._get_risk_score_distribution(user_id=user_id),
        }

    def get_admin_dashboard(self):
        """
        获取管理员Dashboard数据 (全平台)
        :return: 统计数据字典
        """
        return {
            'platform_stats': self._get_platform_stats(),
            'vulnerability_chart': self._get_vulnerability_chart(),
            'risk_distribution': self._get_all_risk_distribution(),
            'experiment_status_chart': self._get_all_experiment_status(),
            'scan_overview': self._get_scan_overview(),
            'ai_overview': self._get_ai_overview(),
            'risk_stats': self._get_risk_stats(user_id=None),
            'risk_score_distribution': self._get_risk_score_distribution(user_id=None),
            'kri': self.get_kri(),
            'alerts': self.get_alerts(),
        }

    def get_kri(self):
        """关键风险指标 (KRI) — 供管理员 Dashboard 卡片展示

        包含: 平台平均风险评分、高危(Critical+High)评估占比、
        近24h 新增评估数、存在高危评估的去重用户数。
        """
        since_24h = datetime.now() - timedelta(hours=24)
        total = RiskAssessment.query.count()
        avg_score = round(db.session.query(
            func.avg(RiskAssessment.final_score)
        ).scalar() or 0, 1)
        high_cnt = RiskAssessment.query.filter(
            RiskAssessment.risk_level.in_(['Critical', 'High'])
        ).count()
        high_ratio = round(high_cnt / total * 100, 1) if total else 0
        assess_24h = RiskAssessment.query.filter(
            RiskAssessment.created_time >= since_24h
        ).count()
        high_users = db.session.query(
            RiskAssessment.user_id
        ).filter(
            RiskAssessment.risk_level.in_(['Critical', 'High'])
        ).distinct().count()
        return {
            'avg_score': avg_score,
            'high_risk_ratio': high_ratio,
            'assessments_24h': assess_24h,
            'high_risk_users': high_users,
            'total': total,
            'high_cnt': high_cnt,
        }

    # ==================== 用户统计 ====================

    def _get_user_stats(self, user_id):
        """用户概览统计"""
        return {
            'experiment_count': Experiment.query.filter_by(user_id=user_id).count(),
            'scan_count': ScanTask.query.filter_by(user_id=user_id).count(),
            'ai_count': AIAnalysis.query.filter_by(user_id=user_id).count(),
            'report_count': Report.query.filter_by(user_id=user_id).count(),
        }

    def _get_user_experiment_stats(self, user_id):
        """用户实验统计"""
        total = Experiment.query.filter_by(user_id=user_id).count()
        success = Experiment.query.filter_by(user_id=user_id, status='success').count()
        failed = Experiment.query.filter_by(user_id=user_id, status='failed').count()
        running = Experiment.query.filter_by(user_id=user_id, status='running').count()
        return {'total': total, 'success': success, 'failed': failed, 'running': running}

    def _get_user_scan_stats(self, user_id):
        """用户扫描统计"""
        total = ScanTask.query.filter_by(user_id=user_id).count()
        completed = ScanTask.query.filter_by(user_id=user_id, status='completed').count()
        # 总开放端口数
        task_ids = [t.id for t in ScanTask.query.filter_by(user_id=user_id).with_entities(ScanTask.id).all()]
        open_ports = ScanResult.query.filter(
            ScanResult.task_id.in_(task_ids), ScanResult.state == 'open'
        ).count() if task_ids else 0
        return {'total': total, 'completed': completed, 'open_ports': open_ports}

    def _get_user_ai_stats(self, user_id):
        """用户AI分析统计"""
        total = AIAnalysis.query.filter_by(user_id=user_id).count()
        completed = AIAnalysis.query.filter_by(user_id=user_id, status='completed').count()
        return {'total': total, 'completed': completed}

    def _get_user_report_stats(self, user_id):
        """用户报告统计"""
        total = Report.query.filter_by(user_id=user_id).count()
        generated = Report.query.filter_by(user_id=user_id, status='generated').count()
        return {'total': total, 'generated': generated}

    def _get_user_risk_distribution(self, user_id):
        """用户AI风险等级分布"""
        results = db_session_query_risk(user_id)
        return results

    def _get_user_experiment_status(self, user_id):
        """用户实验状态分布"""
        results = db_session_query_exp_status(user_id)
        return results

    # ==================== 管理员统计 ====================

    def _get_platform_stats(self):
        """全平台统计"""
        return {
            'user_count': User.query.count(),
            'vulnerability_count': Vulnerability.query.count(),
            'experiment_count': Experiment.query.count(),
            'scan_count': ScanTask.query.count(),
            'ai_count': AIAnalysis.query.count(),
            'report_count': Report.query.count(),
        }

    def _get_vulnerability_chart(self):
        """漏洞分类柱状图数据"""
        results = Vulnerability.query.join(VulnerabilityCategory).with_entities(
            VulnerabilityCategory.name, func.count(Vulnerability.id)
        ).group_by(VulnerabilityCategory.name).all()
        return [{'name': r[0], 'count': r[1]} for r in results]

    def _get_all_risk_distribution(self):
        """全平台AI风险分布"""
        results = db_session_query_risk(None)
        return results

    def _get_all_experiment_status(self):
        """全平台实验状态"""
        results = db_session_query_exp_status(None)
        return results

    def _get_scan_overview(self):
        """扫描概览"""
        total = ScanTask.query.count()
        completed = ScanTask.query.filter_by(status='completed').count()
        return {'total': total, 'completed': completed}

    def _get_ai_overview(self):
        """AI分析概览"""
        total = AIAnalysis.query.count()
        completed = AIAnalysis.query.filter_by(status='completed').count()
        return {'total': total, 'completed': completed}

    def _get_risk_stats(self, user_id=None):
        """风险评估统计"""
        query = RiskAssessment.query
        if user_id:
            query = query.filter_by(user_id=user_id)
        total = query.count()
        avg_score = round(db.session.query(
            func.avg(RiskAssessment.final_score)
        ).filter(
            RiskAssessment.user_id == user_id if user_id else True
        ).scalar() or 0, 1)
        return {'total': total, 'avg_score': avg_score}

    def _get_risk_score_distribution(self, user_id=None):
        """风险评估等级分布 (供Dashboard图表)"""
        query = db.session.query(
            RiskAssessment.risk_level, func.count(RiskAssessment.id)
        )
        if user_id:
            query = query.filter(RiskAssessment.user_id == user_id)
        results = query.group_by(RiskAssessment.risk_level).all()
        levels = ['Critical', 'High', 'Medium', 'Low']
        level_map = {r[0]: r[1] for r in results}
        return [{'name': level, 'count': level_map.get(level, 0)} for level in levels]

    # ==================== 异常告警 ====================

    def get_alerts(self):
        """生成管理员视图的异常告警列表

        :return: [{'level':'critical'|'warning', 'title', 'detail', 'time', 'link'}, ...]
                 按严重度排序 (critical 在前)
        """
        alerts = []
        alerts += self._alert_high_risk_recent()
        alerts += self._alert_failed_experiments()
        alerts += self._alert_scan_abuse()
        alerts += self._alert_new_users()
        alerts.sort(key=lambda a: 0 if a['level'] == 'critical' else 1)
        return alerts

    def _alert_high_risk_recent(self, hours=24):
        """近24h 高危(Critical+High)评估数超阈值 -> critical"""
        since = datetime.now() - timedelta(hours=hours)
        cnt = RiskAssessment.query.filter(
            RiskAssessment.risk_level.in_(['Critical', 'High']),
            RiskAssessment.created_time >= since,
        ).count()
        if cnt >= ALERT_THRESHOLDS['high_risk_recent']:
            return [{
                'level': 'critical',
                'title': '近24h 高危风险评估激增',
                'detail': f'近 {hours} 小时新增 {cnt} 条 Critical/High 风险评估',
                'time': since.strftime('%Y-%m-%d %H:%M'),
                'link': '/risk',
            }]
        return []

    def _alert_failed_experiments(self, hours=24):
        """近24h 失败实验数超阈值 -> warning"""
        since = datetime.now() - timedelta(hours=hours)
        cnt = Experiment.query.filter(
            Experiment.status == 'failed',
            Experiment.created_time >= since,
        ).count()
        if cnt >= ALERT_THRESHOLDS['failed_experiments']:
            return [{
                'level': 'warning',
                'title': '近24h 实验失败增多',
                'detail': f'近 {hours} 小时有 {cnt} 个实验执行失败',
                'time': since.strftime('%Y-%m-%d %H:%M'),
                'link': '/experiment',
            }]
        return []

    def _alert_scan_abuse(self, hours=ALERT_THRESHOLDS['scan_abuse_window']):
        """单用户近1h 扫描次数超阈值 -> critical (疑似暴力/滥用)"""
        since = datetime.now() - timedelta(hours=hours)
        rows = db.session.query(
            ScanTask.user_id, func.count(ScanTask.id).label('c')
        ).filter(ScanTask.created_time >= since).group_by(ScanTask.user_id).all()
        abusers = [(uid, c) for uid, c in rows if c >= ALERT_THRESHOLDS['scan_abuse_count']]
        if abusers:
            parts = []
            for uid, c in abusers:
                u = db.session.get(User, uid)
                parts.append(f'{u.username if u else uid}({c}次)')
            return [{
                'level': 'critical',
                'title': '疑似扫描滥用',
                'detail': '近1h 高频发起扫描: ' + ', '.join(parts),
                'time': since.strftime('%Y-%m-%d %H:%M'),
                'link': '/scan',
            }]
        return []

    def _alert_new_users(self, hours=24):
        """近24h 新增用户数超阈值 -> warning"""
        since = datetime.now() - timedelta(hours=hours)
        cnt = User.query.filter(User.created_time >= since).count()
        if cnt >= ALERT_THRESHOLDS['new_users']:
            return [{
                'level': 'warning',
                'title': '近24h 新增用户较多',
                'detail': f'近 {hours} 小时新增 {cnt} 个用户',
                'time': since.strftime('%Y-%m-%d %H:%M'),
                'link': '/admin',
            }]
        return []

    def get_platform_overview(self):
        """公开平台总览 (供首页展示, 无需登录)

        返回全平台的关键计数, 与 _get_platform_stats 同源但作为公开方法暴露。
        """
        return self._get_platform_stats()

    def get_recent_activity(self, user_id, limit=8):
        """用户最近活动流: 扫描 / 实验 / AI分析 / 报告 混合, 按时间倒序

        :param user_id: 用户ID (强制用户隔离)
        :param limit: 返回条数
        :return: [{'type','title','time','status','status_label','status_badge','link'}, ...]
        """
        events = []

        # 扫描任务
        scans = ScanTask.query.filter_by(user_id=user_id).order_by(
            ScanTask.created_time.desc()
        ).limit(limit).all()
        for t in scans:
            events.append({
                'type': 'scan',
                'title': f'扫描 {t.target}',
                'time': t.created_time,
                'status': t.status,
                'status_label': t.status_label,
                'status_badge': t.status_badge,
                'link': f'/scan/{t.id}',
            })

        # 实验
        exps = Experiment.query.filter_by(user_id=user_id).order_by(
            Experiment.created_time.desc()
        ).limit(limit).all()
        for e in exps:
            events.append({
                'type': 'experiment',
                'title': e.experiment_name or f'实验 #{e.id}',
                'time': e.created_time,
                'status': e.status,
                'status_label': e.status_label,
                'status_badge': e.status_badge,
                'link': f'/experiment/{e.id}',
            })

        # AI分析
        ais = AIAnalysis.query.filter_by(user_id=user_id).order_by(
            AIAnalysis.created_time.desc()
        ).limit(limit).all()
        for a in ais:
            model_tag = f' ({a.model})' if a.model else ''
            events.append({
                'type': 'ai',
                'title': f'AI分析{model_tag}',
                'time': a.created_time,
                'status': a.status,
                'status_label': a.status_label,
                'status_badge': a.status_badge,
                'link': f'/ai/result/{a.id}',
            })

        # 按时间倒序, 取前 limit 条
        events.sort(
            key=lambda x: x['time'] or datetime.min.replace(tzinfo=None),
            reverse=True
        )
        return events[:limit]

    def get_user_risk_ranking(self, limit=10):
        """Top N 风险用户: 按高危(Critical+High)评估数降序"""
        high_expr = func.sum(case((RiskAssessment.risk_level.in_(['Critical', 'High']), 1), else_=0))
        rows = db.session.query(
            User.id, User.username,
            func.count(RiskAssessment.id).label('assess_cnt'),
            func.avg(RiskAssessment.final_score).label('avg_score'),
            high_expr.label('high_cnt'),
        ).join(RiskAssessment, RiskAssessment.user_id == User.id).group_by(
            User.id, User.username
        ).order_by(high_expr.desc()).limit(limit).all()
        return [{
            'user_id': r.id,
            'username': r.username,
            'assess_cnt': r.assess_cnt,
            'avg_score': round(r.avg_score or 0, 1),
            'high_cnt': r.high_cnt,
        } for r in rows]

    def get_dangerous_experiments(self, limit=10):
        """Top N 危险实验: 按失败数降序"""
        fail_expr = func.sum(case((Experiment.status == 'failed', 1), else_=0))
        rows = db.session.query(
            Experiment.experiment_name,
            func.count(Experiment.id).label('total'),
            fail_expr.label('failed_cnt'),
        ).group_by(Experiment.experiment_name).order_by(fail_expr.desc()).limit(limit).all()
        return [{
            'name': r.experiment_name,
            'total': r.total,
            'failed_cnt': r.failed_cnt,
            'fail_rate': round(r.failed_cnt / r.total * 100, 1) if r.total else 0,
        } for r in rows]


    # ==================== 首页安全实验态势中心 (UI v3) ====================

    def get_home_dashboard(self, user_id):
        """聚合首页「安全实验态势中心」全部模块数据 (登录态)

        返回模块 ②~⑨ 所需数据; 模块①系统状态由 SystemStatusService 单独提供。
        不修改任何数据库结构, 只读复用现有表。
        """
        return {
            'core_metrics': self._get_home_core_metrics(user_id),
            'my_experiments': self.get_my_experiments(user_id, limit=3),
            'trends': self.get_home_trends(user_id=user_id, days=7),
            'risk_distribution': self.get_home_risk_distribution(user_id),
            'ai_copilot': self.get_ai_copilot_summary(user_id),
            'activity': self.get_recent_activity(user_id, limit=8),
            'recommendation': self.get_daily_recommendation(user_id),
        }

    def _get_home_core_metrics(self, user_id):
        """模块③ 核心指标 (实验平台视角, 非企业SOC指标)"""
        stats = self._get_user_stats(user_id)
        risk = self._get_risk_stats(user_id=user_id)
        # 综合风险评分等级
        score = risk.get('avg_score', 0)
        level = RiskAssessment.classify_risk(score) if hasattr(RiskAssessment, 'classify_risk') else 'Medium'
        return {
            'experiment_count': stats['experiment_count'],
            'scan_count': stats['scan_count'],
            'ai_count': stats['ai_count'],
            'report_count': stats['report_count'],
            'risk_score': score,
            'risk_level': level,
        }

    def get_my_experiments(self, user_id, limit=3):
        """模块⑤ 我的实验 — 最近 N 个实验, 进度由状态推导 (无 progress 字段)"""
        exps = Experiment.query.filter_by(user_id=user_id).order_by(
            Experiment.created_time.desc()
        ).limit(limit).all()
        out = []
        for e in exps:
            if e.status == 'created':
                progress = 0
            elif e.status == 'running':
                progress = 50
            elif e.status in ('success', 'closed', 'failed'):
                progress = 100
            else:
                progress = 0
            vuln = e.vulnerability
            out.append({
                'id': e.id,
                'name': e.experiment_name or f'实验 #{e.id}',
                'vuln_name': vuln.name if vuln else '通用漏洞',
                'vuln_severity': vuln.severity if vuln else 'Medium',
                'status': e.status,
                'status_label': e.status_label,
                'status_badge': e.status_badge,
                'progress': progress,
            })
        return out

    def get_home_trends(self, user_id=None, days=7):
        """模块⑥ 风险趋势 — 最近 days 天: 扫描次数 / 漏洞数量 / 风险指数 三序列

        漏洞数量映射为「每日完成的 AI 分析数」(每次 AI 分析对应一次漏洞发现)。
        风险指数为当日 RiskAssessment.final_score 均值。
        """
        today = datetime.now().date()
        dates = [(today - timedelta(days=days - 1 - i)).isoformat() for i in range(days)]

        scan_q = db.session.query(
            func.date(ScanTask.created_time), func.count(ScanTask.id))
        ai_q = db.session.query(
            func.date(AIAnalysis.created_time), func.count(AIAnalysis.id)
        ).filter(AIAnalysis.status == 'completed')
        risk_q = db.session.query(
            func.date(RiskAssessment.created_time),
            func.avg(RiskAssessment.final_score))
        if user_id:
            scan_q = scan_q.filter_by(user_id=user_id)
            ai_q = ai_q.filter_by(user_id=user_id)
            risk_q = risk_q.filter_by(user_id=user_id)

        scan_map = {str(r[0]): r[1] for r in
                    scan_q.group_by(func.date(ScanTask.created_time)).all()}
        vuln_map = {str(r[0]): r[1] for r in
                    ai_q.group_by(func.date(AIAnalysis.created_time)).all()}
        risk_map = {str(r[0]): round(r[1] or 0, 1) for r in
                    risk_q.group_by(func.date(RiskAssessment.created_time)).all()}

        return {
            'dates': dates,
            'scan_counts': [scan_map.get(d, 0) for d in dates],
            'vuln_counts': [vuln_map.get(d, 0) for d in dates],
            'risk_scores': [risk_map.get(d) for d in dates],
        }

    def get_home_risk_distribution(self, user_id):
        """模块⑦ 漏洞风险分布 — 复用现有 5 级风险分布 (含 Info)"""
        return db_session_query_risk(user_id)

    def get_ai_copilot_summary(self, user_id):
        """模块④ AI 安全助手 — 今日分析数 / 发现高危漏洞数 / 建议 / 下一步"""
        today_dt = datetime.combine(datetime.now().date(), datetime.min.time())
        today_count = AIAnalysis.query.filter_by(user_id=user_id).filter(
            AIAnalysis.created_time >= today_dt
        ).count()
        found = AIAnalysis.query.filter_by(
            user_id=user_id, status='completed'
        ).filter(
            AIAnalysis.risk_level.in_(['Critical', 'High'])
        ).count()
        # 建议: 取最近一个未完成的实验
        sugg = Experiment.query.filter_by(user_id=user_id).filter(
            Experiment.status.in_(['created', 'running'])
        ).order_by(Experiment.created_time.desc()).first()
        if sugg:
            suggestion = f'优先完成 {sugg.experiment_name or "当前"} 实验'
            next_step = '进行漏洞扫描以验证防护效果'
        else:
            suggestion = '已完成全部实验，建议生成实验报告'
            next_step = '查看风险趋势与漏洞分布'
        return {
            'today_count': today_count,
            'found_vulns': found,
            'suggestion': suggestion,
            'next_step': next_step,
        }

    def get_daily_recommendation(self, user_id):
        """模块⑨ 今日推荐 — 推荐一个用户尚未完成的漏洞实验

        进度/难度按 severity 预设; OWASP 取自漏洞关联分类。
        """
        done_ids = {e.vulnerability_id for e in
                    Experiment.query.filter_by(user_id=user_id).all()
                    if e.vulnerability_id}
        candidates = Vulnerability.query.all()
        pick = next((v for v in candidates if v.id not in done_ids), None) or \
            (candidates[0] if candidates else None)
        if not pick:
            return None
        study_map = {'Critical': 25, 'High': 20, 'Medium': 15, 'Low': 10}
        diff_map = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2}
        owasp = pick.owasp.name if pick.owasp else 'OWASP Top 10'
        return {
            'vuln_id': pick.id,
            'name': pick.name,
            'severity': pick.severity,
            'study_time': study_map.get(pick.severity, 15),
            'difficulty': diff_map.get(pick.severity, 3),
            'owasp': owasp,
        }

    def get_admin_home_summary(self):
        """管理员首页折叠面板 — 系统概览 / 用户数 / 今日新增实验 / AI调用 / Prompt数 / 系统日志"""
        today_dt = datetime.combine(datetime.now().date(), datetime.min.time())
        user_count = User.query.count()
        new_exp_today = Experiment.query.filter(
            Experiment.created_time >= today_dt
        ).count()
        ai_calls = AIAnalysis.query.count()
        prompt_count = PromptTemplate.query.count()

        # 系统日志: 全平台最近活动 (扫描 + 实验, 取前 6)
        events = []
        for t in ScanTask.query.order_by(ScanTask.created_time.desc()).limit(5).all():
            events.append({
                'type': 'scan', 'title': f'扫描 {t.target}', 'time': t.created_time,
                'status': t.status, 'status_label': t.status_label,
                'status_badge': t.status_badge, 'link': f'/scan/{t.id}',
            })
        for e in Experiment.query.order_by(Experiment.created_time.desc()).limit(5).all():
            events.append({
                'type': 'experiment', 'title': e.experiment_name or f'实验 #{e.id}',
                'time': e.created_time, 'status': e.status,
                'status_label': e.status_label, 'status_badge': e.status_badge,
                'link': f'/experiment/{e.id}',
            })
        events.sort(
            key=lambda x: x['time'] or datetime.min.replace(tzinfo=None), reverse=True)
        recent_logs = events[:6]

        return {
            'user_count': user_count,
            'new_experiments_today': new_exp_today,
            'ai_calls': ai_calls,
            'prompt_count': prompt_count,
            'recent_logs': recent_logs,
        }


def db_session_query_risk(user_id=None):
    """查询AI风险等级分布"""
    from app.extensions import db
    query = db.session.query(
        AIAnalysis.risk_level, func.count(AIAnalysis.id)
    ).filter(AIAnalysis.status == 'completed')

    if user_id is not None:
        query = query.filter(AIAnalysis.user_id == user_id)

    results = query.group_by(AIAnalysis.risk_level).all()
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    risk_map = {r[0]: r[1] for r in results}
    return [{'name': risk, 'count': risk_map.get(risk, 0)} for risk in risk_order]


def db_session_query_exp_status(user_id=None):
    """查询实验状态分布 — 仅三种有效状态: 进行中 / 成功 / 失败"""
    from app.extensions import db
    query = db.session.query(
        Experiment.status, func.count(Experiment.id)
    )
    if user_id is not None:
        query = query.filter(Experiment.user_id == user_id)

    results = query.group_by(Experiment.status).all()
    status_map = {r[0]: r[1] for r in results}
    # 新流程: complete 即终态, 只保留三种有意义的运行状态
    statuses = ['running', 'success', 'failed']
    labels = {'running': '进行中', 'success': '成功', 'failed': '失败'}
    return [{'name': labels.get(s, s), 'count': status_map.get(s, 0)} for s in statuses]
