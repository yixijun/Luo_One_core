import sqlite3

conn = sqlite3.connect('data/luo_one.db')
cursor = conn.cursor()

# 查看所有表
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables:", cursor.fetchall())

# 查看邮件账户
cursor.execute("SELECT id, email, last_sync_at FROM email_accounts")
accounts = cursor.fetchall()
print("\nEmail accounts:")
for acc in accounts:
    print(f"  ID: {acc[0]}, Email: {acc[1]}, LastSync: {acc[2]}")

# 查看邮件数量
cursor.execute("SELECT COUNT(*) FROM emails")
print(f"\nTotal emails: {cursor.fetchone()[0]}")

# 查看最新的邮件
cursor.execute("SELECT id, subject, has_attachments, raw_file_path FROM emails ORDER BY id DESC LIMIT 5")
emails = cursor.fetchall()
print("\nLatest emails:")
for email in emails:
    print(f"  ID: {email[0]}, Subject: {email[1]}, HasAttachments: {email[2]}, RawPath: {email[3]}")

conn.close()
