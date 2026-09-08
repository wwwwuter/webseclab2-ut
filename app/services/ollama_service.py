"""
Ollama本地大模型服务封装模块
通过HTTP API调用Ollama，支持generate和chat接口
新增: 流式输出 (stream) 支持SSE实时推送
"""

import json
import logging
import requests

logger = logging.getLogger(__name__)


class OllamaService:
    """Ollama API调用服务"""

    def __init__(self, base_url='http://localhost:11434', model='qwen2.5:7b'):
        """
        初始化Ollama服务
        :param base_url: Ollama服务地址
        :param model: 使用的模型名称
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = 180  # 模型推理超时时间(秒), 流式模式适当放宽

    def is_available(self):
        """检查Ollama服务是否可用"""
        try:
            resp = requests.get(f'{self.base_url}/api/tags', timeout=5)
            available = resp.status_code == 200
            if not available:
                logger.warning('Ollama服务不可用: HTTP %d', resp.status_code)
            return available
        except (requests.ConnectionError, requests.Timeout):
            logger.debug('Ollama服务连接失败: %s', self.base_url)
            return False

    def get_models(self):
        """获取已安装的模型列表"""
        try:
            resp = requests.get(f'{self.base_url}/api/tags', timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return [m['name'] for m in data.get('models', [])]
            return []
        except (requests.ConnectionError, requests.Timeout, ValueError):
            return []

    def chat(self, prompt, model=None):
        """
        发送Prompt到Ollama并获取完整回复 (非流式)
        :param prompt: 用户Prompt字符串
        :param model: 模型名称
        :return: (回复文本, 错误信息)
        """
        model_name = model or self.model

        if not prompt or not prompt.strip():
            return '', 'Prompt不能为空'
        if len(prompt) > 10000:
            prompt = prompt[:10000]

        payload = {
            'model': model_name,
            'prompt': prompt,
            'stream': False,
            'options': {
                'num_predict': 1500,
                'temperature': 0.3,
            }
        }

        try:
            logger.info('Ollama chat: model=%s, prompt_len=%d', model_name, len(prompt))
            resp = requests.post(
                f'{self.base_url}/api/generate',
                json=payload,
                timeout=self.timeout
            )

            if resp.status_code == 200:
                data = resp.json()
                response_text = data.get('response', '')
                if len(response_text) > 8000:
                    response_text = response_text[:8000]
                logger.info('Ollama chat 完成: response_len=%d', len(response_text))
                return response_text, None
            elif resp.status_code == 404:
                logger.warning('Ollama模型未找到: %s', model_name)
                return '', f'模型 {model_name} 未找到，请先安装: ollama pull {model_name}'
            else:
                logger.error('Ollama返回错误: HTTP %d', resp.status_code)
                return '', f'Ollama返回错误: HTTP {resp.status_code}'

        except requests.ConnectionError:
            logger.error('Ollama服务未启动')
            return '', 'Ollama服务未启动，请运行: ollama serve'
        except requests.Timeout:
            logger.error('Ollama推理超时 (>%ds)', self.timeout)
            return '', f'模型推理超时(>{self.timeout}秒)，请尝试更小的模型或更短的Prompt'
        except Exception as e:
            logger.error('Ollama调用异常: %s', e)
            return '', f'Ollama调用异常: {str(e)}'

    def chat_stream(self, prompt, model=None):
        """
        流式输出: 逐 token 生成器
        用于 SSE (Server-Sent Events) 实时推送给前端

        Ollama API stream=true 时返回 NDJSON (每行一个JSON对象):
        {"model":"qwen2.5","response":"你","done":false}
        {"model":"qwen2.5","response":"好","done":false}
        ...
        {"model":"qwen2.5","response":"","done":true,"total_duration":...}

        :param prompt: 用户Prompt字符串
        :param model: 模型名称
        :yield: token 字符串; 出错时 yield None
        """
        model_name = model or self.model

        if not prompt or not prompt.strip():
            return
        if len(prompt) > 10000:
            prompt = prompt[:10000]

        payload = {
            'model': model_name,
            'prompt': prompt,
            'stream': True,
            'options': {
                'num_predict': 1500,
                'temperature': 0.3,
            }
        }

        try:
            logger.info('Ollama stream: model=%s, prompt_len=%d', model_name, len(prompt))
            resp = requests.post(
                f'{self.base_url}/api/generate',
                json=payload,
                stream=True,  # 启用 requests 流式读取
                timeout=self.timeout
            )

            if resp.status_code != 200:
                # 尝试读取错误信息
                try:
                    error_data = resp.json()
                    error_msg = error_data.get('error', f'HTTP {resp.status_code}')
                except Exception:
                    error_msg = f'HTTP {resp.status_code}'
                logger.error('Ollama stream 错误: %s', error_msg)
                # 通过 yield 一个特殊标记传递错误 (生成器无法直接 return error)
                yield f'[ERROR] Ollama错误: {error_msg}'
                return

            # 逐行读取 NDJSON 流
            token_count = 0
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line.decode('utf-8'))
                    token = data.get('response', '')
                    if token:
                        token_count += 1
                        yield token
                    # done=true 时 Ollama 会返回统计信息，此时 response 为空
                    if data.get('done', False):
                        break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

            logger.info('Ollama stream 完成: tokens=%d', token_count)

        except requests.ConnectionError:
            logger.error('Ollama stream 连接失败')
            return
        except requests.Timeout:
            logger.error('Ollama stream 超时 (>%ds)', self.timeout)
            return
        except Exception as e:
            logger.error('Ollama stream 异常: %s', e)
            return

    def test_connection(self):
        """测试Ollama连接"""
        test_prompt = (
            '你是一名网络安全专家。请用一句话解释什么是SQL注入漏洞。'
            '要求：回答简洁，不超过50字。'
        )
        return self.chat(test_prompt)
