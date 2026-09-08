"""
实验Token生成工具模块
生成随机、唯一、不可预测的实验Token
格式: EXP-XXXXXXXXXX (10位十六进制)
"""

import secrets


def generate_experiment_token():
    """
    生成唯一实验Token
    使用secrets模块保证密码学安全随机性
    :return: 格式为 EXP-XXXXXXXXXX 的字符串
    """
    random_hex = secrets.token_hex(5).upper()
    return f'EXP-{random_hex}'
