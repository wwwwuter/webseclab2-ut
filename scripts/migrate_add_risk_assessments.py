"""
迁移脚本: 创建 risk_assessments 风险评估表
幂等操作: 先检查表是否存在，不存在才创建
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

    # 检查表是否已存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='risk_assessments'")
    if cursor.fetchone():
        print('risk_assessments 表已存在, 无需迁移')
        conn.close()
        return

    print('创建 risk_assessments 表...')
    cursor.execute('''
        CREATE TABLE risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            experiment_id INTEGER,
            scan_id INTEGER,
            ai_analysis_id INTEGER,
            vulnerability_id INTEGER,
            cvss_score REAL DEFAULT 0.0,
            asset_score REAL DEFAULT 0.0,
            exploit_score REAL DEFAULT 0.0,
            exposure_score REAL DEFAULT 0.0,
            ai_score REAL DEFAULT 0.0,
            final_score REAL DEFAULT 0.0,
            risk_level VARCHAR(16) DEFAULT 'Low',
            scoring_detail TEXT DEFAULT '{}',
            source VARCHAR(16) DEFAULT 'auto',
            created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (experiment_id) REFERENCES experiments(id),
            FOREIGN KEY (scan_id) REFERENCES scan_tasks(id),
            FOREIGN KEY (ai_analysis_id) REFERENCES ai_analyses(id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
    ''')

    # 创建索引
    cursor.execute('CREATE INDEX ix_risk_assessments_user_id ON risk_assessments(user_id)')

    conn.commit()
    conn.close()
    print('risk_assessments 表创建成功!')


if __name__ == '__main__':
    migrate()
