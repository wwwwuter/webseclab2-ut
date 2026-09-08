"""
Ollama连接测试脚本
运行方式: python scripts/test_ollama.py
功能: 检查Ollama服务是否正常，发送测试Prompt
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app.services.ollama_service import OllamaService


def test_ollama():
    """测试Ollama服务"""
    print('========== Ollama 连接测试 ==========')

    ollama = OllamaService()

    # 1. 检查服务可用性
    print('[1] 检查Ollama服务...')
    available = ollama.is_available()
    if not available:
        print('    [失败] Ollama服务不可用')
        print('    请确保已安装并启动: ollama serve')
        print('    默认地址: http://localhost:11434')
        return
    print('    [成功] Ollama服务已连接')

    # 2. 获取模型列表
    print('[2] 获取已安装模型...')
    models = ollama.get_models()
    if models:
        print(f'    已安装模型: {", ".join(models)}')
    else:
        print('    [警告] 未检测到已安装模型')
        print('    请安装模型: ollama pull qwen2.5')

    # 3. 发送测试Prompt
    print('[3] 发送测试Prompt...')
    response, error = ollama.test_connection()

    if error:
        print(f'    [失败] {error}')
        return

    print(f'    [成功] 模型回复:')
    print(f'    {response[:200]}')

    # 4. 测试JSON输出解析
    print('[4] 测试结构化Prompt...')
    json_prompt = """分析SQL注入漏洞，输出JSON格式:
{"risk_level":"High/Medium/Low","vulnerability_analysis":"分析","fix_solution":"修复方案"}"""

    response2, error2 = ollama.chat(json_prompt)
    if error2:
        print(f'    [失败] {error2}')
    else:
        print(f'    [成功] 模型输出 ({len(response2)} 字符)')
        print(f'    {response2[:300]}...')

    print('========== 测试完成 ==========')


if __name__ == '__main__':
    test_ollama()
