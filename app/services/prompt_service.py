"""
Prompt工程服务模块 (可配置模板版)
PromptBuilder类负责构建安全分析Prompt
模板来源: 数据库 PromptTemplate 表 (管理员可编辑) > 硬编码默认值
"""

import logging

logger = logging.getLogger(__name__)


class PromptBuilder:
    """安全分析Prompt构建器 (支持DB可配置模板 + 场景化自动匹配)"""

    # 漏洞分类名称 → 场景标识 的映射 (用于自动选择场景化模板)
    CATEGORY_TO_SCENE = {
        'sql injection': 'sql_injection',
        'sqli': 'sql_injection',
        'sql': 'sql_injection',
        'xss': 'xss',
        'cross-site scripting': 'xss',
        'cross site scripting': 'xss',
        'file upload': 'file_upload',
        'file inclusion': 'file_upload',
        'file': 'file_upload',
        'command injection': 'command_injection',
        'command execution': 'command_injection',
        'rce': 'command_injection',
        'os command': 'command_injection',
    }

    # ==================== 硬编码默认模板 (DB不可用时的降级方案) ====================

    DEFAULT_TEMPLATES = {
        'vuln_analysis': """你是一名网络安全专家。
请分析以下Web安全实验数据，并输出严格的JSON格式分析结果。

## 漏洞信息
- 漏洞名称: {vulnerability_name}
- 漏洞描述: {vulnerability_description}
- 漏洞分类: {vulnerability_category}
- 严重程度: {vulnerability_severity}
- 修复方案: {vulnerability_solution}

## 参考资料
{rag_context}

## 扫描结果
{scan_results}

## 实验环境
- 目标: {target}
- DVWA安全等级: {dvwa_level}
- 实验名称: {experiment_name}

请输出严格的JSON格式，不要输出任何无关内容:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "详细的漏洞原理分析(200字以内)",
    "possible_attack": "可能的攻击方式和步骤",
    "impact": "漏洞影响范围和危害",
    "fix_solution": "具体的修复方案和代码示例",
    "security_advice": "安全加固建议和最佳实践"
}}""",

        'scan_analysis': """你是一名网络安全专家。
请分析以下端口扫描结果，评估目标系统的安全风险。

## 扫描目标
- IP地址: {target}

## 开放端口
{scan_results}

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "基于开放端口的安全风险分析(200字以内)",
    "possible_attack": "可能的攻击向量",
    "impact": "潜在安全影响",
    "fix_solution": "安全加固建议",
    "security_advice": "整体安全建议"
}}""",

        'custom_analysis': """你是一名网络安全专家。
请分析以下安全信息:

{input_data}

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "安全风险分析(200字以内)",
    "possible_attack": "可能的攻击方式",
    "impact": "安全影响",
    "fix_solution": "修复建议",
    "security_advice": "安全建议"
}}"""
    }

    def _get_template(self, template_key):
        """
        获取模板内容: 优先从数据库读取，降级使用硬编码默认值
        :param template_key: 模板标识 (vuln_analysis / scan_analysis / custom_analysis)
        :return: 模板字符串
        """
        try:
            from app.models.prompt_template import PromptTemplate
            tmpl = PromptTemplate.query.filter_by(
                template_key=template_key,
                is_active=True
            ).first()
            if tmpl:
                return tmpl.content
        except Exception as e:
            logger.debug(f'从数据库加载模板失败 ({template_key}): {e}')

        return self.DEFAULT_TEMPLATES.get(template_key, '')

    def _detect_scene(self, vulnerability):
        """
        根据漏洞分类自动检测场景
        :param vulnerability: Vulnerability 模型实例
        :return: 场景标识字符串 或 'general'
        """
        if not vulnerability:
            return 'general'
        cat_name = ''
        if hasattr(vulnerability, 'category') and vulnerability.category:
            cat_name = (vulnerability.category.name or '').lower()
        if not cat_name and vulnerability.name:
            cat_name = (vulnerability.name or '').lower()

        for keyword, scene in self.CATEGORY_TO_SCENE.items():
            if keyword in cat_name:
                return scene
        return 'general'

    def _get_scene_template(self, scene):
        """
        获取场景化模板: 优先匹配场景专用模板，降级到通用 vuln_analysis 模板
        :param scene: 场景标识 (sql_injection / xss / ...)
        :return: 模板字符串
        """
        if scene == 'general':
            return self._get_template('vuln_analysis')

        try:
            from app.models.prompt_template import PromptTemplate
            tmpl = PromptTemplate.query.filter_by(
                scene=scene,
                is_active=True
            ).first()
            if tmpl:
                logger.info(f'使用场景化模板: {scene} → {tmpl.name}')
                return tmpl.content
        except Exception as e:
            logger.debug(f'加载场景模板失败 ({scene}): {e}')

        # 降级到通用模板
        return self._get_template('vuln_analysis')

    def build_vuln_analysis_prompt(self, vulnerability, scan_results=None,
                                   experiment=None, rag_context=''):
        """构建漏洞分析Prompt"""
        vuln_name = vulnerability.name if vulnerability else '未知漏洞'
        vuln_desc = (vulnerability.description or '暂无描述')[:500] if vulnerability else '暂无描述'
        vuln_cat = ''
        if vulnerability and hasattr(vulnerability, 'category') and vulnerability.category:
            vuln_cat = vulnerability.category.name
        vuln_severity = ''
        if vulnerability and hasattr(vulnerability, 'severity'):
            vuln_severity = vulnerability.severity or 'Unknown'
        vuln_solution = (vulnerability.solution or '暂无修复方案')[:500] if vulnerability else '暂无修复方案'

        scan_text = self._format_scan_results(scan_results) if scan_results else '无扫描数据'

        target = ''
        dvwa_level = ''
        exp_name = ''
        if experiment:
            target = getattr(experiment, 'target', '') or ''
            dvwa_level = getattr(experiment, 'dvwa_level', '') or ''
            exp_name = getattr(experiment, 'experiment_name', '') or ''

        if not rag_context:
            rag_context = '无额外参考资料'

        # 场景化模板自动匹配: 根据漏洞分类选择专用模板
        scene = self._detect_scene(vulnerability)
        template = self._get_scene_template(scene)

        return template.format(
            vulnerability_name=vuln_name,
            vulnerability_description=vuln_desc,
            vulnerability_category=vuln_cat,
            vulnerability_severity=vuln_severity,
            vulnerability_solution=vuln_solution,
            rag_context=rag_context,
            scan_results=scan_text,
            target=target,
            dvwa_level=dvwa_level,
            experiment_name=exp_name
        )

    def build_scan_analysis_prompt(self, target, scan_results):
        """构建纯扫描结果分析Prompt"""
        scan_text = self._format_scan_results(scan_results)
        template = self._get_template('scan_analysis')
        return template.format(target=target, scan_results=scan_text)

    def build_custom_prompt(self, input_data, scene=None):
        """构建自定义分析Prompt

        scene: general(通用) / code(代码审计) / log(日志分析) /
               config(配置审查) / phishing(钓鱼研判)
        不同场景附加针对性的分析维度提示, 让模型输出更聚焦。
        """
        if len(input_data) > 5000:
            input_data = input_data[:5000] + '\n...(输入已截断)'
        template = self._get_template('custom_analysis')

        scene_hint = self._scene_hint(scene)
        if scene_hint:
            # 在 JSON 输出要求之前插入场景化引导
            template = template.replace(
                '请输出严格的JSON格式:',
                f'{scene_hint}\n\n请输出严格的JSON格式:'
            )
        return template.format(input_data=input_data)

    @staticmethod
    def _scene_hint(scene):
        """不同分析场景的针对性提示词片段"""
        hints = {
            'code': ('分析重点: 这是一段代码片段/漏洞利用代码。请聚焦代码层面的'
                     '漏洞原理、危险函数调用、可利用的触发路径, 并给出修复后的安全代码示例。'),
            'log': ('分析重点: 这是安全日志/流量记录。请聚焦异常行为识别、攻击痕迹'
                    '(如爆破/注入/反弹shell)、时间线还原, 以及是否需要进一步处置。'),
            'config': ('分析重点: 这是配置文件/策略。请聚焦错误的安全配置、过度授权、'
                       '缺失的安全加固项, 并给出最小化且可落地的配置修正。'),
            'phishing': ('分析重点: 这可能是钓鱼邮件/可疑链接样本。请聚焦社工手法识别、'
                         'URL/域名可疑特征、 payload 意图, 并给出判别与处置建议。'),
        }
        return hints.get(scene) if scene else None

    @staticmethod
    def _format_scan_results(scan_results):
        """格式化扫描结果为可读文本"""
        if not scan_results:
            return '无扫描数据'
        lines = []
        for r in scan_results:
            port = getattr(r, 'port', 0)
            protocol = getattr(r, 'protocol', 'TCP')
            state = getattr(r, 'state', 'open')
            service = getattr(r, 'service', '') or ''
            version = getattr(r, 'version', '') or ''
            banner = getattr(r, 'banner', '') or ''
            line = f'- {port}/{protocol} {state} {service}'
            if version:
                line += f' (版本: {version})'
            if banner:
                line += f' [Banner: {banner[:100]}]'
            lines.append(line)
        return '\n'.join(lines) if lines else '无开放端口'

    @staticmethod
    def format_input_data(vulnerability=None, scan_results=None, experiment=None):
        """格式化输入数据摘要 (用于保存到数据库)"""
        parts = []
        if vulnerability:
            parts.append(f'漏洞: {vulnerability.name}')
            if vulnerability.description:
                parts.append(f'描述: {vulnerability.description[:200]}')
        if experiment:
            parts.append(f'实验: {experiment.experiment_name}')
            parts.append(f'目标: {getattr(experiment, "target", "")}')
            parts.append(f'DVWA等级: {getattr(experiment, "dvwa_level", "")}')
        if scan_results:
            parts.append(f'扫描结果: {len(scan_results)}个开放端口')
        return '\n'.join(parts) if parts else '无输入数据'

    @classmethod
    def seed_default_templates(cls):
        """
        向数据库写入默认模板 (首次初始化时调用)
        :return: 创建的模板数量
        """
        from app.models.prompt_template import PromptTemplate
        from app.extensions import db
        import json

        templates_meta = {
            'vuln_analysis': {
                'name': '漏洞分析模板',
                'description': '基于漏洞信息和实验环境的综合分析Prompt',
                'variables': json.dumps({
                    'vulnerability_name': '漏洞名称',
                    'vulnerability_description': '漏洞描述',
                    'vulnerability_category': '漏洞分类',
                    'vulnerability_severity': '严重程度',
                    'vulnerability_solution': '修复方案',
                    'rag_context': 'RAG参考资料',
                    'scan_results': '扫描结果',
                    'target': '扫描目标',
                    'dvwa_level': 'DVWA安全等级',
                    'experiment_name': '实验名称',
                }, ensure_ascii=False),
            },
            'scan_analysis': {
                'name': '扫描分析模板',
                'description': '基于端口扫描结果的安全风险评估Prompt',
                'variables': json.dumps({
                    'target': '扫描目标IP',
                    'scan_results': '开放端口列表',
                }, ensure_ascii=False),
            },
            'custom_analysis': {
                'name': '自定义分析模板',
                'description': '通用安全信息分析Prompt',
                'variables': json.dumps({
                    'input_data': '用户输入数据',
                }, ensure_ascii=False),
            },
        }

        created = 0
        for key, content in cls.DEFAULT_TEMPLATES.items():
            existing = PromptTemplate.query.filter_by(template_key=key).first()
            if not existing:
                meta = templates_meta.get(key, {})
                tmpl = PromptTemplate(
                    template_key=key,
                    name=meta.get('name', key),
                    description=meta.get('description', ''),
                    content=content,
                    available_variables=meta.get('variables', '{}'),
                    is_default=True,
                    is_active=True,
                )
                db.session.add(tmpl)
                created += 1

        if created > 0:
            db.session.commit()

        # ===== 场景化专用模板 (SQL注入/XSS/文件上传/命令注入) =====
        scene_templates = {
            'vuln_sql_injection': {
                'name': 'SQL注入分析模板',
                'scene': 'sql_injection',
                'description': '针对SQL注入漏洞的专用分析Prompt，侧重注入类型识别和参数化查询修复',
                'content': """你是一名网络安全专家，专注于SQL注入漏洞分析。
请分析以下SQL注入漏洞数据，并输出严格的JSON格式分析结果。

## 漏洞信息
- 漏洞名称: {vulnerability_name}
- 漏洞描述: {vulnerability_description}
- 漏洞分类: {vulnerability_category}
- 严重程度: {vulnerability_severity}

## 参考资料
{rag_context}

## 扫描结果
{scan_results}

## 实验环境
- 目标: {target}
- DVWA安全等级: {dvwa_level}
- 实验名称: {experiment_name}

请重点分析以下SQL注入相关方面:
1. 注入类型判断 (联合查询/盲注/报错注入/时间盲注/堆叠注入)
2. 注入点识别和参数分析
3. 数据泄露风险评估
4. 参数化查询和预编译语句的修复方案

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "SQL注入原理和类型分析(200字以内)",
    "possible_attack": "SQL注入攻击步骤和Payload示例",
    "impact": "数据泄露和权限提升风险",
    "fix_solution": "参数化查询/预编译语句/WAF规则等修复方案(附代码示例)",
    "security_advice": "数据库安全加固建议"
}}""",
                'variables': json.dumps({
                    'vulnerability_name': '漏洞名称', 'vulnerability_description': '漏洞描述',
                    'vulnerability_category': '漏洞分类', 'vulnerability_severity': '严重程度',
                    'rag_context': '参考资料', 'scan_results': '扫描结果',
                    'target': '扫描目标', 'dvwa_level': 'DVWA等级', 'experiment_name': '实验名称',
                }, ensure_ascii=False),
            },
            'vuln_xss': {
                'name': 'XSS跨站脚本分析模板',
                'scene': 'xss',
                'description': '针对XSS漏洞的专用分析Prompt，侧重反射型/存储型/DOM型识别和CSP修复',
                'content': """你是一名网络安全专家，专注于XSS跨站脚本漏洞分析。
请分析以下XSS漏洞数据，并输出严格的JSON格式分析结果。

## 漏洞信息
- 漏洞名称: {vulnerability_name}
- 漏洞描述: {vulnerability_description}
- 漏洞分类: {vulnerability_category}
- 严重程度: {vulnerability_severity}

## 参考资料
{rag_context}

## 扫描结果
{scan_results}

## 实验环境
- 目标: {target}
- DVWA安全等级: {dvwa_level}
- 实验名称: {experiment_name}

请重点分析以下XSS相关方面:
1. XSS类型判断 (反射型/存储型/DOM型)
2. 输入输出点和上下文分析
3. 可利用的JavaScript Payload
4. 输出编码和CSP策略修复

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "XSS类型和原理分析(200字以内)",
    "possible_attack": "XSS攻击Payload和注入方式",
    "impact": "Cookie窃取/钓鱼/蠕虫传播等危害",
    "fix_solution": "输出编码/HttpOnly/CSP策略修复方案(附代码示例)",
    "security_advice": "前端安全加固和Content-Security-Policy建议"
}}""",
                'variables': json.dumps({
                    'vulnerability_name': '漏洞名称', 'vulnerability_description': '漏洞描述',
                    'vulnerability_category': '漏洞分类', 'vulnerability_severity': '严重程度',
                    'rag_context': '参考资料', 'scan_results': '扫描结果',
                    'target': '扫描目标', 'dvwa_level': 'DVWA等级', 'experiment_name': '实验名称',
                }, ensure_ascii=False),
            },
            'vuln_file_upload': {
                'name': '文件上传漏洞分析模板',
                'scene': 'file_upload',
                'description': '针对文件上传漏洞的专用分析Prompt，侧重文件类型验证绕过和WebShell防护',
                'content': """你是一名网络安全专家，专注于文件上传漏洞分析。
请分析以下文件上传漏洞数据，并输出严格的JSON格式分析结果。

## 漏洞信息
- 漏洞名称: {vulnerability_name}
- 漏洞描述: {vulnerability_description}
- 漏洞分类: {vulnerability_category}
- 严重程度: {vulnerability_severity}

## 参考资料
{rag_context}

## 扫描结果
{scan_results}

## 实验环境
- 目标: {target}
- DVWA安全等级: {dvwa_level}
- 实验名称: {experiment_name}

请重点分析以下文件上传相关方面:
1. 上传验证机制分析 (扩展名/MIME/内容类型/文件大小)
2. 绕过技术 (双扩展名/空字节截断/.htaccess上传)
3. WebShell上传和执行风险
4. 安全上传实现方案

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "文件上传漏洞原理和验证缺陷分析(200字以内)",
    "possible_attack": "绕过上传验证的攻击方式和Payload",
    "impact": "WebShell/远程代码执行/服务器控制风险",
    "fix_solution": "安全上传实现(白名单验证/随机文件名/隔离存储)(附代码示例)",
    "security_advice": "文件存储和Web服务器安全配置建议"
}}""",
                'variables': json.dumps({
                    'vulnerability_name': '漏洞名称', 'vulnerability_description': '漏洞描述',
                    'vulnerability_category': '漏洞分类', 'vulnerability_severity': '严重程度',
                    'rag_context': '参考资料', 'scan_results': '扫描结果',
                    'target': '扫描目标', 'dvwa_level': 'DVWA等级', 'experiment_name': '实验名称',
                }, ensure_ascii=False),
            },
            'vuln_command_injection': {
                'name': '命令注入漏洞分析模板',
                'scene': 'command_injection',
                'description': '针对命令注入漏洞的专用分析Prompt，侧重OS命令拼接和最小权限修复',
                'content': """你是一名网络安全专家，专注于OS命令注入漏洞分析。
请分析以下命令注入漏洞数据，并输出严格的JSON格式分析结果。

## 漏洞信息
- 漏洞名称: {vulnerability_name}
- 漏洞描述: {vulnerability_description}
- 漏洞分类: {vulnerability_category}
- 严重程度: {vulnerability_severity}

## 参考资料
{rag_context}

## 扫描结果
{scan_results}

## 实验环境
- 目标: {target}
- DVWA安全等级: {dvwa_level}
- 实验名称: {experiment_name}

请重点分析以下命令注入相关方面:
1. 命令拼接方式分析 (管道符/分号/反引号/$())
2. 输入过滤和转义缺陷
3. 远程代码执行和权限提升风险
4. 安全替代方案 (避免system/exec调用)

请输出严格的JSON格式:
{{
    "risk_level": "Critical/High/Medium/Low中的一个",
    "vulnerability_analysis": "命令注入原理和攻击面分析(200字以内)",
    "possible_attack": "命令注入Payload和链接符号利用",
    "impact": "远程代码执行/系统控制/数据泄露风险",
    "fix_solution": "安全替代方案(避免shell调用/参数白名单/最小权限)(附代码示例)",
    "security_advice": "系统安全加固和最小权限原则建议"
}}""",
                'variables': json.dumps({
                    'vulnerability_name': '漏洞名称', 'vulnerability_description': '漏洞描述',
                    'vulnerability_category': '漏洞分类', 'vulnerability_severity': '严重程度',
                    'rag_context': '参考资料', 'scan_results': '扫描结果',
                    'target': '扫描目标', 'dvwa_level': 'DVWA等级', 'experiment_name': '实验名称',
                }, ensure_ascii=False),
            },
        }

        # 种子场景模板
        for key, meta in scene_templates.items():
            existing = PromptTemplate.query.filter_by(template_key=key).first()
            if not existing:
                tmpl = PromptTemplate(
                    template_key=key,
                    name=meta['name'],
                    description=meta['description'],
                    scene=meta['scene'],
                    content=meta['content'],
                    available_variables=meta['variables'],
                    is_default=True,
                    is_active=True,
                )
                db.session.add(tmpl)
                created += 1

        if created > 0:
            db.session.commit()

        return created
