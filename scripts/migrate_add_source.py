"""
数据库迁移脚本: 为 vulnerabilities 表添加 source 字段
标记漏洞数据来源 (manual = 手动录入, nvd = NVD同步)

用法: python scripts/migrate_add_source.py
幂等: 已存在 source 列时自动跳过
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import create_app
from app.extensions import db

app = create_app()
with app.app_context():
    # 检查 source 列是否已存在
    result = db.session.execute(db.text("PRAGMA table_info(vulnerabilities)"))
    columns = [row[1] for row in result]

    if 'source' in columns:
        print('[SKIP] source 列已存在, 无需迁移')
    else:
        db.session.execute(db.text(
            "ALTER TABLE vulnerabilities ADD COLUMN source VARCHAR(16) DEFAULT 'manual'"
        ))
        db.session.commit()
        print('[OK] 已添加 source 列 (默认值: manual)')

    # 统计
    total = db.session.execute(db.text("SELECT COUNT(*) FROM vulnerabilities")).scalar()
    print(f'[INFO] vulnerabilities 表共 {total} 条记录')
