#!/usr/bin/env python3
import sqlite3, os
from pathlib import Path

DB_PATH = Path("vuln-db/std/vuln.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(DB_PATH)

# 主表
conn.execute("""
CREATE TABLE IF NOT EXISTS vuln(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve         TEXT UNIQUE,
    cvss        REAL,
    description TEXT,
    patch_commit TEXT,
    exp_url     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
)""")

# 资产表（与 recon.py 共用）
conn.execute("""
CREATE TABLE IF NOT EXISTS assets(
    ip      TEXT,
    port    TEXT,
    protocol TEXT,
    host    TEXT,
    title   TEXT,
    banner  TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)""")

conn.commit()
conn.close()
print(f"✅ 数据库已生成：{DB_PATH}")