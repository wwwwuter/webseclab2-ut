"""
实验管理服务模块
封装实验CRUD、状态管理、日志记录等业务逻辑
所有状态变更必须通过Service层，禁止直接修改数据库字段
"""

from datetime import datetime, timedelta
from sqlalchemy import case, update
from flask import current_app

from app.extensions import db
from app.models.experiment import Experiment, ExperimentLog
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.utils.token import generate_experiment_token
from app.services.dvwa_service import DVWAService


class ExperimentService:
    """实验管理服务类"""

    # ==================== 实验创建 ====================

    @staticmethod
    def create_experiment(user_id, vulnerability_id, experiment_name, target, dvwa_level='low'):
        """
        创建实验任务
        :param user_id: 用户ID
        :param vulnerability_id: 漏洞ID
        :param experiment_name: 实验名称
        :param target: DVWA目标地址
        :param dvwa_level: DVWA安全等级
        :return: (Experiment对象, 错误信息)
        """
        # 输入验证
        if not isinstance(experiment_name, str) or not experiment_name.strip():
            return None, '实验名称不能为空'
        experiment_name = experiment_name.strip()
        if not 2 <= len(experiment_name) <= Experiment.NAME_MAX_LENGTH:
            return None, '实验名称须为 2–128 个字符'
        target = target.strip() if isinstance(target, str) else ''
        valid, error = DVWAService.validate_target_url(target)
        if not valid:
            return None, error
        if len(target) > Experiment.TARGET_MAX_LENGTH:
            return None, '目标地址不能超过 256 个字符'

        if dvwa_level not in Experiment.DVWA_LEVELS:
            return None, f'无效的DVWA等级: {dvwa_level}'

        # 验证漏洞是否存在
        if vulnerability_id:
            vuln = db.session.get(Vulnerability, vulnerability_id)
            if not vuln:
                return None, '指定的漏洞不存在'

        # 生成唯一Token (防重复)
        token = generate_experiment_token()
        while Experiment.query.filter_by(token=token).first():
            token = generate_experiment_token()

        # 创建实验记录
        experiment = Experiment(
            user_id=user_id,
            vulnerability_id=vulnerability_id or None,
            experiment_name=experiment_name.strip(),
            target=target.strip() if target else '',
            dvwa_level=dvwa_level,
            token=token,
            status=Experiment.STATUS_CREATED
        )
        try:
            db.session.add(experiment)
            db.session.flush()
            # 日志与业务记录必须同事务提交，避免只保存一半。
            ExperimentService._add_log(
                experiment.id, 'create', f'创建实验: {experiment.experiment_name}'
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception('实验创建事务失败')
            return None, '实验未保存，请稍后重试'
        return experiment, None

    # ==================== 实验查询 (用户隔离) ====================

    @staticmethod
    def get_user_experiments(user_id, page=1, per_page=10):
        """
        获取用户自己的实验列表 (分页)
        :param user_id: 用户ID
        :param page: 页码
        :param per_page: 每页数量
        :return: Pagination对象
        """
        return Experiment.query.filter_by(
            user_id=user_id
        ).order_by(Experiment.created_time.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

    @staticmethod
    def get_user_experiments_filtered(user_id, keyword=None, status=None, dvwa_level=None,
                                      sort_by=None, order='desc', page=1, per_page=10):
        """
        获取用户自己的实验列表 (分页 + 多维筛选 + 排序, 用户隔离)
        复用管理员端 get_experiments_filtered 的语义排序思路, 但限定 user_id
        可排序字段: created_time / completed_time / status(语义) / dvwa_level(语义)
        :return: Pagination对象
        """
        query = Experiment.query.filter_by(user_id=user_id)

        if keyword:
            query = query.filter(
                db.or_(
                    Experiment.experiment_name.ilike(f'%{keyword}%'),
                    Experiment.token.ilike(f'%{keyword}%')
                )
            )

        if status:
            query = query.filter(Experiment.status == status)
        if dvwa_level:
            query = query.filter(Experiment.dvwa_level == dvwa_level)

        # 排序: 白名单 + 语义排序 (status / dvwa_level 非字母序)
        order = 'desc' if order not in ('asc', 'desc') else order
        dir_fn = db.desc if order == 'desc' else db.asc

        if sort_by == 'status':
            status_order = case(
                (Experiment.status == 'created', 1),
                (Experiment.status == 'running', 2),
                (Experiment.status == 'success', 3),
                (Experiment.status == 'failed', 4),
                (Experiment.status == 'closed', 5),
                else_=9
            )
            query = query.order_by(dir_fn(status_order), Experiment.created_time.desc())
        elif sort_by == 'dvwa_level':
            dvwa_order = case(
                (Experiment.dvwa_level == 'low', 1),
                (Experiment.dvwa_level == 'medium', 2),
                (Experiment.dvwa_level == 'high', 3),
                (Experiment.dvwa_level == 'impossible', 4),
                else_=9
            )
            query = query.order_by(dir_fn(dvwa_order), Experiment.created_time.desc())
        elif sort_by == 'completed_time':
            query = query.order_by(dir_fn(Experiment.completed_time.is_(None)), dir_fn(Experiment.completed_time))
        else:
            query = query.order_by(dir_fn(Experiment.created_time))

        return query.paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_experiment_by_id(experiment_id, user_id=None):
        """
        获取实验详情 (带用户隔离验证)
        :param experiment_id: 实验ID
        :param user_id: 当前用户ID (None表示管理员不验证)
        :return: (Experiment对象, 错误信息)
        """
        experiment = db.session.get(Experiment, experiment_id)
        if not experiment:
            return None, '实验记录不存在'

        # 用户隔离: 非管理员只能查看自己的实验
        if user_id is not None and not experiment.is_owner(user_id):
            return None, '无权访问该实验'

        return experiment, None

    @staticmethod
    def get_all_experiments(page=1, per_page=10):
        """
        获取全部实验列表 (管理员用)
        :param page: 页码
        :param per_page: 每页数量
        :return: Pagination对象
        """
        return Experiment.query.order_by(
            Experiment.created_time.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_experiments_filtered(keyword=None, status=None, dvwa_level=None,
                                 page=1, per_page=10, sort_by=None, order='desc'):
        """
        多维度筛选实验列表 (管理员端使用)
        支持关键词(实验名/Token/用户名) + 状态 + DVWA等级 组合筛选 + 排序
        可排序字段: created_time / completed_time / status(语义) / dvwa_level(语义)
        :return: Pagination对象
        """
        query = Experiment.query

        if keyword:
            query = query.join(
                User, Experiment.user_id == User.id, isouter=True
            ).filter(
                db.or_(
                    Experiment.experiment_name.ilike(f'%{keyword}%'),
                    Experiment.token.ilike(f'%{keyword}%'),
                    User.username.ilike(f'%{keyword}%')
                )
            )

        if status:
            query = query.filter(Experiment.status == status)
        if dvwa_level:
            query = query.filter(Experiment.dvwa_level == dvwa_level)

        # 排序: 白名单 + 语义排序 (status / dvwa_level 非字母序)
        order = 'desc' if order not in ('asc', 'desc') else order
        dir_fn = db.desc if order == 'desc' else db.asc

        if sort_by == 'status':
            status_order = case(
                (Experiment.status == 'created', 1),
                (Experiment.status == 'running', 2),
                (Experiment.status == 'success', 3),
                (Experiment.status == 'failed', 4),
                (Experiment.status == 'closed', 5),
                else_=9
            )
            query = query.order_by(dir_fn(status_order), Experiment.created_time.desc())
        elif sort_by == 'dvwa_level':
            dvwa_order = case(
                (Experiment.dvwa_level == 'low', 1),
                (Experiment.dvwa_level == 'medium', 2),
                (Experiment.dvwa_level == 'high', 3),
                (Experiment.dvwa_level == 'impossible', 4),
                else_=9
            )
            query = query.order_by(dir_fn(dvwa_order), Experiment.created_time.desc())
        elif sort_by == 'created_time':
            query = query.order_by(dir_fn(Experiment.created_time))
        elif sort_by == 'completed_time':
            query = query.order_by(dir_fn(Experiment.completed_time.is_(None)), dir_fn(Experiment.completed_time))
        else:
            query = query.order_by(Experiment.created_time.desc())

        return query.paginate(page=page, per_page=per_page, error_out=False)

    # ==================== 实验状态管理 ====================

    @staticmethod
    def start_experiment(experiment_id, user_id):
        """
        启动实验 (状态: created -> running)
        :param experiment_id: 实验ID
        :param user_id: 操作用户ID
        :return: (Experiment对象, 错误信息)
        """
        experiment, error = ExperimentService.get_experiment_by_id(experiment_id, user_id)
        if error:
            return None, error

        return ExperimentService._transition(
            experiment, user_id, 'start', {'status': Experiment.STATUS_RUNNING},
            '开始实验记录（未启动或控制 DVWA 环境）'
        )

    @staticmethod
    def complete_experiment(experiment_id, user_id, result_text, status='success'):
        """
        完成实验 (提交结果)
        :param experiment_id: 实验ID
        :param user_id: 操作用户ID
        :param result_text: 实验结果描述
        :param status: 最终状态 (success/failed)
        :return: (Experiment对象, 错误信息)
        """
        experiment, error = ExperimentService.get_experiment_by_id(experiment_id, user_id)
        if error:
            return None, error

        if status not in [Experiment.STATUS_SUCCESS, Experiment.STATUS_FAILED]:
            return None, '无效的实验完成状态'

        result_text = result_text.strip() if isinstance(result_text, str) else ''
        if not result_text:
            return None, '请填写实验结果描述，不能只包含空白字符'
        if len(result_text) > Experiment.RESULT_MAX_LENGTH:
            return None, '实验结果不能超过 20000 个字符'

        status_label = '成功' if status == 'success' else '失败'
        return ExperimentService._transition(
            experiment, user_id, 'complete',
            {'status': status, 'result': result_text, 'completed_time': datetime.now()},
            f'人工提交{status_label}（未经自动验证）: {result_text[:100]}'
        )

    @staticmethod
    def close_experiment(experiment_id, user_id):
        """
        关闭未完成实验 (状态: created/running -> closed)
        :param experiment_id: 实验ID
        :param user_id: 操作用户ID
        :return: (Experiment对象, 错误信息)
        """
        experiment, error = ExperimentService.get_experiment_by_id(experiment_id, user_id)
        if error:
            return None, error

        return ExperimentService._transition(
            experiment, user_id, 'close',
            {'status': Experiment.STATUS_CLOSED, 'completed_time': datetime.now()},
            '关闭未完成实验（未停止 DVWA 环境）'
        )

    @staticmethod
    def _transition(experiment, user_id, action, values, description):
        if not experiment.can_perform(action):
            return None, f'当前状态“{experiment.status_label}”不允许此操作，请返回详情查看'
        experiment_id = experiment.id
        expected_status = experiment.status
        try:
            # 条件更新防止旧页面和并发请求覆盖另一请求刚提交的终态。
            statement = update(Experiment).where(
                Experiment.id == experiment_id,
                Experiment.user_id == user_id,
                Experiment.status == expected_status,
            ).values(**values).execution_options(synchronize_session=False)
            if db.session.execute(statement).rowcount != 1:
                db.session.rollback()
                return None, '实验状态已变更，请刷新详情后重试'
            ExperimentService._add_log(experiment_id, action, description)
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception('实验状态事务失败 [id=%s, action=%s]', experiment_id, action)
            return None, '操作未保存，请刷新详情后重试'
        return db.session.get(Experiment, experiment_id), None

    # ==================== 实验删除 ====================

    @staticmethod
    def delete_experiment(experiment_id, user_id):
        """
        删除实验 (仅所有者或管理员)
        :param experiment_id: 实验ID
        :param user_id: 操作用户ID
        :return: (True/False, 错误信息)
        """
        experiment = db.session.get(Experiment, experiment_id)
        if not experiment:
            return False, '实验记录不存在'
        # user_id 为 None 表示管理员操作, 跳过所有者校验 (对齐 risk 删除修复)
        if user_id is not None and not experiment.is_owner(user_id):
            return False, '无权删除该实验'

        # 删除关联日志
        ExperimentLog.query.filter_by(experiment_id=experiment_id).delete()
        db.session.delete(experiment)
        db.session.commit()
        return True, None

    @staticmethod
    def batch_delete_experiments(exp_ids, user_id=None):
        """
        批量删除实验 (管理员, selection-mode 使用)
        user_id 为 None 表示管理员操作, 跳过所有者校验 (对齐 delete_experiment)
        逐条校验存在性并清理关联日志, 一次提交
        :param exp_ids: 实验ID字符串列表
        :param user_id: 操作用户ID (None=管理员)
        :return: 成功删除的数量
        """
        deleted = 0
        for raw in exp_ids:
            try:
                eid = int(raw)
            except (TypeError, ValueError):
                continue
            exp = db.session.get(Experiment, eid)
            if not exp:
                continue
            if user_id is not None and not exp.is_owner(user_id):
                continue
            ExperimentLog.query.filter_by(experiment_id=eid).delete()
            db.session.delete(exp)
            deleted += 1
        if deleted:
            db.session.commit()
        return deleted

    # ==================== DVWA关联 ====================

    @staticmethod
    def get_dvwa_url(experiment_id, user_id):
        """
        获取实验的DVWA访问URL
        :param experiment_id: 实验ID
        :param user_id: 用户ID
        :return: (URL字符串, 错误信息)
        """
        experiment, error = ExperimentService.get_experiment_by_id(experiment_id, user_id)
        if error:
            return None, error

        url = DVWAService.generate_dvwa_url(
            experiment.target, experiment.token, experiment.dvwa_level
        )
        return url, None

    # ==================== 日志管理 ====================

    @staticmethod
    def _add_log(experiment_id, action, description=''):
        """
        添加实验日志 (内部方法)
        :param experiment_id: 实验ID
        :param action: 操作类型
        :param description: 操作描述
        """
        log = ExperimentLog(
            experiment_id=experiment_id,
            action=action,
            description=description
        )
        db.session.add(log)

    @staticmethod
    def get_experiment_logs(experiment_id):
        """
        获取实验日志列表
        :param experiment_id: 实验ID
        :return: ExperimentLog列表
        """
        return ExperimentLog.query.filter_by(
            experiment_id=experiment_id
        ).order_by(ExperimentLog.time.desc()).all()

    # ==================== 统计 ====================

    @staticmethod
    def get_user_statistics(user_id):
        """获取用户实验统计"""
        experiments = Experiment.query.filter_by(user_id=user_id)
        return {
            'total': experiments.count(),
            'created': experiments.filter_by(status='created').count(),
            'running': experiments.filter_by(status='running').count(),
            'success': experiments.filter_by(status='success').count(),
            'failed': experiments.filter_by(status='failed').count(),
            'closed': experiments.filter_by(status='closed').count()
        }

    @staticmethod
    def get_admin_statistics():
        """获取全局实验统计 (管理员), 含 DVWA 等级分布/成功率/近7天新增 (供 KRI 卡���图表)"""
        total = Experiment.query.count()
        stats = {
            'total': total,
            'created': Experiment.query.filter_by(status='created').count(),
            'running': Experiment.query.filter_by(status='running').count(),
            'success': Experiment.query.filter_by(status='success').count(),
            'failed': Experiment.query.filter_by(status='failed').count(),
            'closed': Experiment.query.filter_by(status='closed').count(),
            'low': Experiment.query.filter_by(dvwa_level='low').count(),
            'medium': Experiment.query.filter_by(dvwa_level='medium').count(),
            'high': Experiment.query.filter_by(dvwa_level='high').count(),
            'impossible': Experiment.query.filter_by(dvwa_level='impossible').count(),
        }
        finished = stats['success'] + stats['failed']
        stats['success_rate'] = round(stats['success'] / finished * 100, 1) if finished else 0
        since = datetime.now() - timedelta(days=7)
        stats['recent_7d'] = Experiment.query.filter(Experiment.created_time >= since).count()
        return stats
