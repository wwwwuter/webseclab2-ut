"""
迁移脚本: 为 prompt_templates 表添加 scene 和 version 字段
幂等操作: 先检查列是否存在，不存在才添加
"""
import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'webseclab.db')


def migrate():
    if not os.path.exists(DB_PATH):
        print(f'数据库不存在: {DB_PATH}')
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 获取现有列
    cursor.execute("PRAGMA table_info(prompt_templates)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    added = []

    if 'scene' not in existing_columns:
        cursor.execute("ALTER TABLE prompt_templates ADD COLUMN scene VARCHAR(32) DEFAULT 'general'")
        cursor.execute("CREATE INDEX ix_prompt_templates_scene ON prompt_templates(scene)")
        added.append('scene')

    if 'version' not in existing_columns:
        cursor.execute("ALTER TABLE prompt_templates ADD COLUMN version INTEGER DEFAULT 1")
        added.append('version')

    if added:
        conn.commit()
        print(f'已添加列: {", ".join(added)}')
    else:
        print('prompt_templates 表已是最新, 无需迁移')

    conn.close()


if __name__ == '__main__':
    migrate()
