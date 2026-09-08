"""
数据库迁移脚本: 为 scan_tasks 表添加进度跟踪字段
运行方式: python scripts/migrate_add_scan_progress.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'webseclab.db')

# 需要新增的字段: (列名, SQL类型, 默认值)
NEW_COLUMNS = [
    ('progress', 'INTEGER', '0'),
    ('progress_message', 'VARCHAR(256)', "''"),
    ('total_ports', 'INTEGER', '0'),
    ('scanned_ports', 'INTEGER', '0'),
]


def migrate():
    if not os.path.exists(DB_PATH):
        print(f'数据库不存在: {DB_PATH}')
        print('请先启动应用让数据库自动创建，或手动运行 init 脚本')
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 获取现有列名
    cursor.execute('PRAGMA table_info(scan_tasks)')
    existing_cols = {row[1] for row in cursor.fetchall()}

    added = []
    for col_name, col_type, default in NEW_COLUMNS:
        if col_name not in existing_cols:
            sql = f"ALTER TABLE scan_tasks ADD COLUMN {col_name} {col_type} DEFAULT {default}"
            cursor.execute(sql)
            added.append(col_name)
            print(f'  + 添加字段: {col_name} ({col_type})')
        else:
            print(f'  ~ 字段已存在: {col_name}')

    conn.commit()
    conn.close()

    if added:
        print(f'\n迁移完成: 新增 {len(added)} 个字段 ({", ".join(added)})')
    else:
        print('\n无需迁移: 所有字段已存在')


if __name__ == '__main__':
    print(f'数据库路径: {DB_PATH}')
    migrate()
