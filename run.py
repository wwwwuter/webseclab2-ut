"""
WebSecLab 应用入口文件
启动命令: python run.py
"""

from dotenv import load_dotenv
load_dotenv()

from app import create_app

# 创建Flask应用实例
app = create_app()

if __name__ == '__main__':
    # debug 由配置驱动, 避免硬编码 True 在生产环境误开启 (Werkzeug 调试器 RCE 风险)
    app.run(host='127.0.0.1', port=5000, debug=app.config.get('DEBUG', False))
