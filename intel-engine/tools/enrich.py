#!/usr/bin/env python3
import sqlite3, json
from pathlib import Path

ROOT = Path(__file__).parent
DB = ROOT / ".." / "intel.db"  
OUT = ROOT / ".." / "clean" / "enriched.json"

conn = sqlite3.connect(DB)
cur = conn.cursor()

# 根据 banner 匹配 CVE 字典（示例）
banner_map = {
    "thinkphp": ["CVE-2021-46379"],
    "grafana":  ["CVE-2021-43798"],
}

results = []
for row in cur.execute("SELECT ip,port,banner FROM assets"):
    ip, port, banner = row
    keywords = [k for k in banner_map if k in banner.lower()]
    for kw in keywords:
        for cve in banner_map[kw]:
            results.append({"ip": ip, "port": port, "banner": banner, "cve": cve})

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"✅ 已补全 {len(results)} 条 CVE 关联 → {OUT}")