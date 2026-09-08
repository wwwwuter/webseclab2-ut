"""
AI分析主服务模块
整合Ollama/OpenAI兼容API、PromptBuilder、RAG服务，实现完整的AI漏洞分析流程
支持双模式: LLM_MODE=ollama (本地) 或 LLM_MODE=api (云端DeepSeek/DashScope/OpenAI)
新增: 流式分析支持 (prepare + stream 分离)
"""

import json
import logging
from datetime import datetime
from flask import current_app
from sqlalchemy import case
from app.extensions import db
from app.models.ai_analysis import AIAnalysis
from app.models.experiment import Experiment
from app.models.scan import ScanTask, ScanResult
from app.models.vulnerability import Vulnerability
from app.services.ollama_service import OllamaService
from app.services.openai_service import OpenAICompatibleService
from app.services.prompt_service import PromptBuilder
from app.services.rag_service import RAGService

logger = logging.getLogger(__name__)


class AIService:
    """AI漏洞分析主服务类"""

    def __init__(self, model=None):
        self.prompt_builder = PromptBuilder()
        self.rag = RAGService()

        # 根据配置选择 LLM 后端
        try:
            mode = current_app.config.get('LLM_MODE', 'ollama')
        except RuntimeError:
            mode = 'ollama'  # 测试环境无 app context

        if mode == 'api':
            try:
                cfg = current_app.config
            except RuntimeError:
                cfg = {}
            self.llm = OpenAICompatibleService(
                provider=cfg.get('LLM_API_PROVIDER', 'deepseek'),
                api_key=cfg.get('LLM_API_KEY', ''),
                base_url=cfg.get('LLM_API_BASE_URL', '') or None,
                model=cfg.get('LLM_API_MODEL', '') or None,
            )
        else:
            self.llm = OllamaService(model=model or 'qwen2.5:7b')

    def is_available(self):
        return self.llm.is_available()

    def get_models(self):
        return self.llm.get_models()

    # ==================== 非流式分析 (保持兼容) ====================

    def analyze_experiment(self, user_id, experiment_id, model=None):
        """基于实验的AI漏洞分析 (非流式, 同步返回)"""
        analysis, prompt, model_name = self._prepare_experiment_analysis(user_id, experiment_id, model)
        if analysis is None:
            return None, prompt  # prompt此时是错误信息

        response_text, error = self.llm.chat(prompt, model=model_name)
        if error:
            analysis.status = AIAnalysis.STATUS_FAILED
            analysis.error_message = error
            db.session.commit()
            return analysis, error

        analysis.raw_output = response_text
        parsed = self._parse_json_output(response_text)
        self._apply_parsed_result(analysis, parsed)
        analysis.status = AIAnalysis.STATUS_COMPLETED
        db.session.commit()
        return analysis, None

    def analyze_scan(self, user_id, scan_task_id, model=None):
        """基于扫描任务的AI分析 (非流式)"""
        analysis, prompt, model_name = self._prepare_scan_analysis(user_id, scan_task_id, model)
        if analysis is None:
            return None, prompt

        response_text, error = self.llm.chat(prompt, model=model_name)
        if error:
            analysis.status = AIAnalysis.STATUS_FAILED
            analysis.error_message = error
            db.session.commit()
            return analysis, error

        analysis.raw_output = response_text
        parsed = self._parse_json_output(response_text)
        self._apply_parsed_result(analysis, parsed)
        analysis.status = AIAnalysis.STATUS_COMPLETED
        db.session.commit()
        return analysis, None

    def analyze_custom(self, user_id, input_data, model=None):
        """自定义文本AI分析 (非流式)"""
        analysis, prompt, model_name = self._prepare_custom_analysis(user_id, input_data, model)
        if analysis is None:
            return None, prompt

        response_text, error = self.llm.chat(prompt, model=model_name)
        if error:
            analysis.status = AIAnalysis.STATUS_FAILED
            analysis.error_message = error
            db.session.commit()
            return analysis, error

        analysis.raw_output = response_text
        parsed = self._parse_json_output(response_text)
        self._apply_parsed_result(analysis, parsed)
        analysis.status = AIAnalysis.STATUS_COMPLETED
        db.session.commit()
        return analysis, None

    # ==================== 流式分析 (SSE 用) ====================

    def stream_experiment_analysis(self, user_id, experiment_id, model=None):
        """
        流式分析: 准备分析记录 + 返回SSE生成器
        :return: SSE生成器 或 (None, 错误信息)
        """
        analysis, prompt, model_name = self._prepare_experiment_analysis(user_id, experiment_id, model)
        if analysis is None:
            return None, prompt
        return self._create_stream_generator(analysis, prompt, model_name), None

    def stream_scan_analysis(self, user_id, scan_task_id, model=None):
        """流式扫描分析"""
        analysis, prompt, model_name = self._prepare_scan_analysis(user_id, scan_task_id, model)
        if analysis is None:
            return None, prompt
        return self._create_stream_generator(analysis, prompt, model_name), None

    def stream_custom_analysis(self, user_id, input_data, model=None, scene=None, use_rag=False):
        """流式自定义分析"""
        analysis, prompt, model_name = self._prepare_custom_analysis(
            user_id, input_data, model, scene=scene, use_rag=use_rag)
        if analysis is None:
            return None, prompt
        return self._create_stream_generator(analysis, prompt, model_name), None

    def _create_stream_generator(self, analysis, prompt, model_name):
        """
        创建SSE流式生成器
        将 Ollama 的 token 流封装为 SSE 事件格式:
          data: {"type":"token","content":"xxx"}
          data: {"type":"done","analysis_id":123}
          data: {"type":"error","message":"xxx"}

        关键: 生成器在 lazy iteration 时执行，此时请求上下文可能已销毁，
        因此必须在生成器内部推入独立的 app context 以保证 DB 访问。
        """
        from flask import current_app
        app = current_app._get_current_object()
        analysis_id = analysis.id

        def generate():
            with app.app_context():
                full_text = []
                try:
                    for token in self.llm.chat_stream(prompt, model=model_name):
                        if token:
                            full_text.append(token)
                            yield f"data: {json.dumps({'type': 'token', 'content': token}, ensure_ascii=False)}\n\n"

                    # 流结束: 保存到数据库
                    raw_output = ''.join(full_text)
                    self._finalize_analysis(analysis_id, raw_output)

                    yield f"data: {json.dumps({'type': 'done', 'analysis_id': analysis_id})}\n\n"

                except Exception as e:
                    logger.error(f'流式分析异常: {e}', exc_info=True)
                    self._fail_analysis(analysis_id, str(e))
                    yield f"data: {json.dumps({'type': 'error', 'message': str(e)}, ensure_ascii=False)}\n\n"

        return generate()

    def _finalize_analysis(self, analysis_id, raw_output):
        """流式结束后保存完整输出并解析"""
        analysis = db.session.get(AIAnalysis, analysis_id)
        if not analysis:
            return
        analysis.raw_output = raw_output
        parsed = self._parse_json_output(raw_output)
        self._apply_parsed_result(analysis, parsed)
        analysis.status = AIAnalysis.STATUS_COMPLETED
        db.session.commit()

    def _fail_analysis(self, analysis_id, error_msg):
        """标记分析失败"""
        analysis = db.session.get(AIAnalysis, analysis_id)
        if not analysis:
            return
        analysis.status = AIAnalysis.STATUS_FAILED
        analysis.error_message = error_msg
        db.session.commit()

    # ==================== 准备阶段 (创建记录 + 构建Prompt) ====================

    def _prepare_experiment_analysis(self, user_id, experiment_id, model=None):
        """准备实验分析: 获取数据 → RAG → 构建Prompt → 创建DB记录"""
        experiment = db.session.get(Experiment, experiment_id)
        if not experiment:
            return None, '实验不存在', None
        if not experiment.is_owner(user_id):
            return None, '无权分析该实验', None

        vulnerability = None
        if experiment.vulnerability_id:
            vulnerability = db.session.get(Vulnerability, experiment.vulnerability_id)

        scan_results = None
        if hasattr(experiment, 'scan_tasks'):
            latest_task = ScanTask.query.filter_by(
                experiment_id=experiment_id
            ).order_by(ScanTask.created_time.desc()).first()
            if latest_task:
                scan_results = ScanResult.query.filter_by(
                    task_id=latest_task.id
                ).order_by(ScanResult.port).all()

        rag_context = ''
        if vulnerability:
            rag_context = self.rag.retrieve_vuln_context(vulnerability)
        if scan_results:
            scan_ctx = self.rag.retrieve_scan_context(scan_results)
            if scan_ctx:
                rag_context += '\n\n' + scan_ctx

        if vulnerability:
            prompt = self.prompt_builder.build_vuln_analysis_prompt(
                vulnerability=vulnerability, scan_results=scan_results,
                experiment=experiment, rag_context=rag_context
            )
        else:
            input_text = f'实验名称: {experiment.experiment_name}\n目标: {getattr(experiment, "target", "")}\nDVWA等级: {getattr(experiment, "dvwa_level", "")}'
            prompt = self.prompt_builder.build_custom_prompt(input_text)

        input_data = PromptBuilder.format_input_data(vulnerability, scan_results, experiment)
        model_name = model or self.llm.model

        analysis = AIAnalysis(
            user_id=user_id, experiment_id=experiment_id,
            vulnerability_id=experiment.vulnerability_id,
            scan_task_id=latest_task.id if hasattr(experiment, 'scan_tasks') and scan_results else None,
            input_data=input_data, prompt=prompt,
            model=model_name, status=AIAnalysis.STATUS_RUNNING
        )
        db.session.add(analysis)
        db.session.commit()

        return analysis, prompt, model_name

    def _prepare_scan_analysis(self, user_id, scan_task_id, model=None):
        """准备扫描分析"""
        task = db.session.get(ScanTask, scan_task_id)
        if not task:
            return None, '扫描任务不存在', None
        if not task.is_owner(user_id):
            return None, '无权分析该扫描任务', None

        scan_results = ScanResult.query.filter_by(task_id=scan_task_id).order_by(ScanResult.port).all()
        prompt = self.prompt_builder.build_scan_analysis_prompt(task.target, scan_results)

        rag_ctx = self.rag.retrieve_scan_context(scan_results)
        if rag_ctx:
            prompt += f'\n\n## 安全知识补充\n{rag_ctx}'

        input_data = f'扫描目标: {task.target}\n扫描类型: {task.scan_type}\n开放端口: {len(scan_results)}个'
        model_name = model or self.llm.model

        analysis = AIAnalysis(
            user_id=user_id, scan_task_id=scan_task_id,
            input_data=input_data, prompt=prompt,
            model=model_name, status=AIAnalysis.STATUS_RUNNING
        )
        db.session.add(analysis)
        db.session.commit()

        return analysis, prompt, model_name

    def _prepare_custom_analysis(self, user_id, input_data, model=None, scene=None, use_rag=False):
        """准备自定义分析"""
        if not input_data or not input_data.strip():
            return None, '输入数据不能为空', None

        # 场景归一化 (只允许白名单值, 其余视为 general)
        allowed_scenes = {'general', 'code', 'log', 'config', 'phishing'}
        if scene not in allowed_scenes:
            scene = 'general'

        prompt = self.prompt_builder.build_custom_prompt(input_data, scene=scene)

        # 可选: 结合安全知识库 (语义检索漏洞知识)
        if use_rag:
            rag_ctx = self.rag.retrieve_general_context(input_data)
            if rag_ctx:
                prompt += f'\n\n## 安全知识补充\n{rag_ctx}'

        model_name = model or self.llm.model

        analysis = AIAnalysis(
            user_id=user_id, input_data=input_data[:5000],
            prompt=prompt, model=model_name, scene=scene,
            status=AIAnalysis.STATUS_RUNNING
        )
        db.session.add(analysis)
        db.session.commit()

        return analysis, prompt, model_name

    # ==================== 查询接口 ====================

    def get_user_analyses(self, user_id, page=1, per_page=10, keyword=None,
                          source=None, risk_level=None, status=None,
                          sort_by='created_time', order='desc'):
        """获取用户AI分析历史 (支持搜索/筛选/排序)"""
        query = AIAnalysis.query.filter_by(user_id=user_id)

        if keyword:
            like = f'%{keyword}%'
            query = query.filter(db.or_(
                AIAnalysis.input_data.ilike(like),
                AIAnalysis.vulnerability_analysis.ilike(like),
                AIAnalysis.impact.ilike(like),
                AIAnalysis.risk_level.ilike(like),
                AIAnalysis.model.ilike(like),
            ))

        # 来源: experiment / scan / custom(两者皆空)
        if source == 'experiment':
            query = query.filter(AIAnalysis.experiment_id.isnot(None))
        elif source == 'scan':
            query = query.filter(AIAnalysis.scan_task_id.isnot(None))
        elif source == 'custom':
            query = query.filter(
                AIAnalysis.experiment_id.is_(None),
                AIAnalysis.scan_task_id.is_(None)
            )

        if risk_level:
            query = query.filter(AIAnalysis.risk_level == risk_level)
        if status:
            query = query.filter(AIAnalysis.status == status)

        # 排序 (风险按语义等级而非字母序)
        risk_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        if sort_by == 'risk':
            rank_expr = case(risk_rank, value=AIAnalysis.risk_level)
            if order == 'asc':
                query = query.order_by(rank_expr.asc(), AIAnalysis.created_time.desc())
            else:
                query = query.order_by(rank_expr.desc(), AIAnalysis.created_time.desc())
        else:
            col = AIAnalysis.created_time
            if order == 'asc':
                query = query.order_by(col.asc())
            else:
                query = query.order_by(col.desc())

        return query.paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_user_statistics(user_id):
        """统计当前用户 AI 分析概览: 总数/已完成/失败/高危+"""
        base = AIAnalysis.query.filter_by(user_id=user_id)
        total = base.count()
        completed = base.filter(AIAnalysis.status == AIAnalysis.STATUS_COMPLETED).count()
        failed = base.filter(AIAnalysis.status == AIAnalysis.STATUS_FAILED).count()
        high_risk = base.filter(
            AIAnalysis.risk_level.in_([AIAnalysis.RISK_CRITICAL, AIAnalysis.RISK_HIGH])
        ).count()
        return {
            'total': total,
            'completed': completed,
            'failed': failed,
            'high_risk': high_risk,
        }

    def get_analysis_by_id(self, analysis_id, user_id=None):
        analysis = db.session.get(AIAnalysis, analysis_id)
        if not analysis:
            return None, '分析结果不存在'
        if user_id is not None and not analysis.is_owner(user_id):
            return None, '无权访问该分析结果'
        return analysis, None

    def delete_analysis(self, analysis_id, user_id):
        analysis = db.session.get(AIAnalysis, analysis_id)
        if not analysis:
            return False, '分析结果不存在'
        if not analysis.is_owner(user_id):
            return False, '无权删除该分析结果'
        db.session.delete(analysis)
        db.session.commit()
        return True, None

    # ==================== 内部方法 ====================

    @staticmethod
    def _parse_json_output(text):
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass
        import re
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
        if json_match:
            try:
                return json.loads(json_match.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                pass
        brace_match = re.search(r'\{[\s\S]*\}', text)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    @staticmethod
    def _apply_parsed_result(analysis, parsed):
        valid_risks = {'Critical', 'High', 'Medium', 'Low'}
        if parsed and isinstance(parsed, dict):
            risk = parsed.get('risk_level', '')
            analysis.risk_level = risk if risk in valid_risks else 'Medium'
            analysis.vulnerability_analysis = str(parsed.get('vulnerability_analysis', ''))[:2000]
            analysis.possible_attack = str(parsed.get('possible_attack', ''))[:2000]
            analysis.impact = str(parsed.get('impact', ''))[:2000]
            analysis.fix_solution = str(parsed.get('fix_solution', ''))[:2000]
            analysis.security_advice = str(parsed.get('security_advice', ''))[:2000]
        else:
            analysis.risk_level = 'Medium'
            analysis.vulnerability_analysis = analysis.raw_output[:2000] if analysis.raw_output else ''
