#!/usr/bin/env python3
import sqlite3, json
from pathlib import Path

DB = Path("vuln-db/std/vuln.db")
RAW = Path("vuln-db/raw/mini_cve.jsonl")

conn = sqlite3.connect(DB)
with open(RAW, encoding="utf-8") as f:
    for line in f:
        j = json.loads(line)
        conn.execute("""
        INSERT OR IGNORE INTO vuln(cve, cvss, description, patch_commit, exp_url)
        VALUES (?,?,?,?,?)
        """, (j["cve"], j["cvss"], j["description"], j.get("patch_commit"), j.get("exp_url")))
conn.commit()
conn.close()
print("✅ mini-CVE 已入库")