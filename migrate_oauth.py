#!/usr/bin/env python3
"""
数据库迁移脚本 - 添加 OAuth 相关字段到 email_accounts 表
运行: python migrate_oauth.py
"""

import sqlite3
import os

DB_PATH = "data/luo_one.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"数据库文件不存在: {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 检查并添加 OAuth 相关字段
    columns_to_add = [
        ("auth_type", "TEXT DEFAULT 'password'"),
        ("oauth_provider", "TEXT DEFAULT ''"),
        ("oauth_access_token", "TEXT DEFAULT ''"),
        ("oauth_refresh_token", "TEXT DEFAULT ''"),
        ("oauth_token_expiry", "DATETIME"),
    ]
    
    # 获取现有列
    cursor.execute("PRAGMA table_info(email_accounts)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    
    print(f"现有列: {existing_columns}")
    
    for col_name, col_def in columns_to_add:
        if col_name not in existing_columns:
            sql = f"ALTER TABLE email_accounts ADD COLUMN {col_name} {col_def}"
            print(f"执行: {sql}")
            try:
                cursor.execute(sql)
                print(f"  ✓ 添加列 {col_name} 成功")
            except sqlite3.OperationalError as e:
                print(f"  ✗ 添加列 {col_name} 失败: {e}")
        else:
            print(f"  - 列 {col_name} 已存在，跳过")
    
    conn.commit()
    conn.close()
    print("\n迁移完成!")

if __name__ == "__main__":
    migrate()
