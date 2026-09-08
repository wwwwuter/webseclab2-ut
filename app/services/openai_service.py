"""
OpenAI 兼容 API 服务封装模块
支持 DeepSeek / DashScope / OpenAI 等所有 OpenAI 格式的 API

调用方式:
  POST {base_url}/chat/completions
  Header: Authorization: Bearer {api_key}
  Body: { "model": "...", "messages": [...], "stream": true/false }
"""

import json
import logging
import requests

logger = logging.getLogger(__name__)


class OpenAICompatibleService:
    """OpenAI 兼容 API 服务"""

    # 预置提供商配置
    PROVIDERS = {
        'deepseek': {
            'base_url': 'https://api.deepseek.com/v1',
            'model': 'deepseek-chat',
            'label': 'DeepSeek',
        },
        'dashscope': {
            'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
            'model': 'qwen-plus',
            'label': '阿里云百炼',
        },
        'openai': {
            'base_url': 'https://api.openai.com/v1',
            'model': 'gpt-4o-mini',
            'label': 'OpenAI',
        },
    }

    def __init__(self, base_url=None, api_key=None, model=None, provider='deepseek'):
        """
        初始化 API 服务
        :param base_url: API 基础地址 (不传则从 provider 推断)
        :param api_key: API Key
        :param model: 模型名称 (不传则用 provider 默认)
        :param provider: 提供商名称 (deepseek/dashscope/openai)
        """
        cfg = self.PROVIDERS.get(provider, self.PROVIDERS['deepseek'])
        self.base_url = (base_url or cfg['base_url']).rstrip('/')
        self.model = model or cfg['model']
        self.api_key = api_key or ''
        self.timeout = 120

    @property
    def headers(self):
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }

    def is_available(self):
        """检查 API 是否可用 (尝试列出模型)"""
        if not self.api_key:
            return False
        try:
            resp = requests.get(
                f'{self.base_url}/models',
                headers=self.headers,
                timeout=10
            )
            return resp.status_code == 200
        except (requests.ConnectionError, requests.Timeout):
            return False

    def get_models(self):
        """获取可用模型列表"""
        if not self.api_key:
            return []
        try:
            resp = requests.get(
                f'{self.base_url}/models',
                headers=self.headers,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                return [m['id'] for m in data.get('data', [])]
            return []
        except Exception:
            return []

    def chat(self, prompt, model=None):
        """
        非流式调用
        :param prompt: 用户 Prompt
        :param model: 模型名称
        :return: (回复文本, 错误信息)
        """
        model_name = model or self.model

        if not self.api_key:
            return '', '未配置 API Key'
        if not prompt or not prompt.strip():
            return '', 'Prompt 不能为空'
        if len(prompt) > 10000:
            prompt = prompt[:10000]

        payload = {
            'model': model_name,
            'messages': [
                {'role': 'system', 'content': '你是一名资深网络安全专家，擅长漏洞分析、渗透测试和安全评估。'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 1500,
            'temperature': 0.3,
            'stream': False,
        }

        try:
            logger.info('API chat: model=%s, prompt_len=%d', model_name, len(prompt))
            resp = requests.post(
                f'{self.base_url}/chat/completions',
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )

            if resp.status_code == 200:
                data = resp.json()
                text = data['choices'][0]['message']['content']
                logger.info('API chat 完成: response_len=%d', len(text))
                return text, None
            elif resp.status_code == 401:
                return '', 'API Key 无效或已过期'
            elif resp.status_code == 429:
                return '', 'API 调用频率超限，请稍后重试'
            else:
                error_msg = ''
                try:
                    error_msg = resp.json().get('error', {}).get('message', '')
                except Exception:
                    pass
                return '', f'API 返回错误: HTTP {resp.status_code} {error_msg}'

        except requests.ConnectionError:
            return '', '无法连接 API 服务，请检查网络'
        except requests.Timeout:
            return '', f'API 推理超时 (>{self.timeout}秒)'
        except Exception as e:
            return '', f'API 调用异常: {str(e)}'

    def chat_stream(self, prompt, model=None):
        """
        流式调用 (SSE 兼容)
        :param prompt: 用户 Prompt
        :param model: 模型名称
        :yield: token 字符串
        """
        model_name = model or self.model

        if not self.api_key:
            yield '[ERROR] 未配置 API Key'
            return
        if not prompt or not prompt.strip():
            return
        if len(prompt) > 10000:
            prompt = prompt[:10000]

        payload = {
            'model': model_name,
            'messages': [
                {'role': 'system', 'content': '你是一名资深网络安全专家，擅长漏洞分析、渗透测试和安全评估。'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 1500,
            'temperature': 0.3,
            'stream': True,
        }

        try:
            logger.info('API stream: model=%s, prompt_len=%d', model_name, len(prompt))
            resp = requests.post(
                f'{self.base_url}/chat/completions',
                headers=self.headers,
                json=payload,
                stream=True,
                timeout=self.timeout
            )

            if resp.status_code != 200:
                try:
                    err = resp.json().get('error', {}).get('message', f'HTTP {resp.status_code}')
                except Exception:
                    err = f'HTTP {resp.status_code}'
                yield f'[ERROR] API 错误: {err}'
                return

            # 解析 SSE 格式: "data: {...}\n\n"
            token_count = 0
            for line in resp.iter_lines():
                if not line:
                    continue
                decoded = line.decode('utf-8')
                if not decoded.startswith('data: '):
                    continue
                data_str = decoded[6:]
                if data_str.strip() == '[DONE]':
                    break
                try:
                    data = json.loads(data_str)
                    delta = data.get('choices', [{}])[0].get('delta', {})
                    content = delta.get('content', '')
                    if content:
                        token_count += 1
                        yield content
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue

            logger.info('API stream 完成: tokens=%d', token_count)

        except requests.ConnectionError:
            logger.error('API stream 连接失败')
        except requests.Timeout:
            logger.error('API stream 超时')
        except Exception as e:
            logger.error('API stream 异常: %s', e)
