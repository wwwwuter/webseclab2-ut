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
import time
import requests

logger = logging.getLogger(__name__)

# 模块级 TTL 缓存: 避免每次打开页面都发起网络请求 (API 不可用时超时 10s)
# key 为 base_url, 不同用户配置的地址互不影响
_availability_cache = {}  # {base_url: (ts, bool)}
_models_cache = {}        # {base_url: (ts, list)}
_CACHE_TTL = 30           # 秒


class OpenAICompatibleService:
    """OpenAI 兼容 API 服务"""

    @classmethod
    def clear_cache(cls):
        """清空模块级缓存 (测试/配置变更后调用)"""
        _availability_cache.clear()
        _models_cache.clear()

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
        """检查 API 是否可用 (尝试列出模型, 带 30s TTL 缓存)"""
        if not self.api_key:
            return False
        now = time.time()
        cached = _availability_cache.get(self.base_url)
        if cached and now - cached[0] < _CACHE_TTL:
            return cached[1]

        try:
            resp = requests.get(
                f'{self.base_url}/models',
                headers=self.headers,
                timeout=10
            )
            available = resp.status_code == 200
        except (requests.ConnectionError, requests.Timeout):
            available = False

        _availability_cache[self.base_url] = (now, available)
        return available

    def get_models(self):
        """获取可用模型列表 (带 30s TTL 缓存)"""
        if not self.api_key:
            return []
        now = time.time()
        cached = _models_cache.get(self.base_url)
        if cached and now - cached[0] < _CACHE_TTL:
            return cached[1]

        try:
            resp = requests.get(
                f'{self.base_url}/models',
                headers=self.headers,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [m['id'] for m in data.get('data', [])]
            else:
                models = []
        except Exception:
            models = []

        _models_cache[self.base_url] = (now, models)
        return models

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

    def chat_structured(self, prompt, schema=None, model=None):
        """
        结构化输出: 利用 OpenAI 兼容 API 的 response_format 强制模型输出合法 JSON。

        :param prompt: 用户 Prompt
        :param schema: JSON schema 对象 (严格约束) 或 None (仅 JSON mode)
        :param model: 模型名称
        :return: (dict, 错误信息)
        """
        model_name = model or self.model

        if not self.api_key:
            return None, '未配置 API Key'
        if not prompt or not prompt.strip():
            return None, 'Prompt 不能为空'
        if len(prompt) > 10000:
            prompt = prompt[:10000]

        if schema:
            response_format = {
                'type': 'json_schema',
                'json_schema': {
                    'name': 'structured_output',
                    'strict': True,
                    'schema': schema,
                },
            }
        else:
            response_format = {'type': 'json_object'}

        payload = {
            'model': model_name,
            'messages': [
                {'role': 'system', 'content': '你是一名资深网络安全专家，擅长漏洞分析、渗透测试和安全评估。请严格按要求的 JSON 格式输出。'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 1500,
            'temperature': 0.0,
            'stream': False,
            'response_format': response_format,
        }

        try:
            logger.info('API chat_structured: model=%s, prompt_len=%d', model_name, len(prompt))
            resp = requests.post(
                f'{self.base_url}/chat/completions',
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )

            if resp.status_code == 200:
                data = resp.json()
                text = data['choices'][0]['message']['content']
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict):
                        logger.info('API chat_structured 完成: keys=%s', list(parsed.keys()))
                        return parsed, None
                    return None, '结构化输出不是 JSON 对象'
                except (json.JSONDecodeError, ValueError):
                    logger.warning('API 结构化输出解析失败, 返回原始文本')
                    return None, '结构化输出解析失败'
            elif resp.status_code == 401:
                return None, 'API Key 无效或已过期'
            elif resp.status_code == 429:
                return None, 'API 调用频率超限，请稍后重试'
            else:
                error_msg = ''
                try:
                    error_msg = resp.json().get('error', {}).get('message', '')
                except Exception:
                    pass
                return None, f'API 返回错误: HTTP {resp.status_code} {error_msg}'

        except requests.ConnectionError:
            return None, '无法连接 API 服务，请检查网络'
        except requests.Timeout:
            return None, f'API 推理超时 (>{self.timeout}秒)'
        except Exception as e:
            return None, f'API 调用异常: {str(e)}'

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
