#!/usr/bin/env python3
"""
洛一邮箱 - 数据库迁移脚本
添加 Google OAuth 相关字段到 user_settings 表
"""

import sqlite3
import os
import sys

DB_PATH = "data/luo_one.db"

# 需要添加的字段
NEW_COLUMNS = [
    ("google_client_id", "TEXT"),
    ("google_client_secret", "TEXT"),
    ("google_redirect_url", "TEXT"),
]

def get_existing_columns(cursor, table_name):
    """获取表的现有字段列表"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return [row[1] for row in cursor.fetchall()]

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"错误: 数据库文件不存在: {DB_PATH}")
        sys.exit(1)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("=== 洛一邮箱数据库迁移 ===\n")
    
    # 检查 user_settings 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_settings'")
    if not cursor.fetchone():
        print("错误: user_settings 表不存在")
        conn.close()
        sys.exit(1)
    
    # 获取现有字段
    existing_columns = get_existing_columns(cursor, "user_settings")
    print(f"现有字段: {', '.join(existing_columns)}\n")
    
    # 添加缺失的字段
    added = []
    skipped = []
    
    for col_name, col_type in NEW_COLUMNS:
        if col_name in existing_columns:
            skipped.append(col_name)
        else:
            try:
                cursor.execute(f"ALTER TABLE user_settings ADD COLUMN {col_name} {col_type}")
                added.append(col_name)
                print(f"✓ 添加字段: {col_name} ({col_type})")
            except sqlite3.Error as e:
                print(f"✗ 添加字段 {col_name} 失败: {e}")
    
    conn.commit()
    
    # 显示结果
    print("\n=== 迁移完成 ===")
    if added:
        print(f"新增字段: {', '.join(added)}")
    if skipped:
        print(f"已存在(跳过): {', '.join(skipped)}")
    
    # 显示最终表结构
    print("\n最终表结构:")
    final_columns = get_existing_columns(cursor, "user_settings")
    for col in final_columns:
        print(f"  - {col}")
    
    conn.close()
    print("\n请重启后端服务使更改生效。")

if __name__ == "__main__":
    migrate()
