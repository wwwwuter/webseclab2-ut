"""
数据库迁移脚本: 创建 prompt_templates 表
运行方式: python scripts/migrate_add_prompt_templates.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'webseclab.db')


def migrate():
    if not os.path.exists(DB_PATH):
        print(f'数据库不存在: {DB_PATH}')
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 检查表是否已存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prompt_templates'")
    if cursor.fetchone():
        print('prompt_templates 表已存在, 无需迁移')
        conn.close()
        return

    # 创建 prompt_templates 表
    cursor.execute('''
        CREATE TABLE prompt_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_key VARCHAR(64) UNIQUE NOT NULL,
            name VARCHAR(128) NOT NULL,
            description TEXT DEFAULT '',
            content TEXT NOT NULL,
            available_variables TEXT DEFAULT '{}',
            is_default BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建索引
    cursor.execute('CREATE INDEX ix_prompt_templates_template_key ON prompt_templates(template_key)')

    conn.commit()
    conn.close()
    print('迁移完成: 已创建 prompt_templates 表')


if __name__ == '__main__':
    print(f'数据库路径: {DB_PATH}')
    migrate()
