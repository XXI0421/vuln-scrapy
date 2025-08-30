#!/usr/bin/env python3
import json, requests, os, datetime
from pathlib import Path

ROOT = Path(__file__).parent
vuln_json = ROOT / "clean" / "final_vulns.json"
webhook = "https://open.feishu.cn/open-apis/bot/v2/hook/你的token"

def push():
    if not vuln_json.exists():
        return
    with open(vuln_json, encoding="utf-8") as f:
        vulns = json.load(f)
    if not vulns:
        return
    msg = {
        "msg_type": "text",
        "content": {
            "text": f"🚨 {datetime.datetime.now():%m-%d %H:%M} 发现 {len(vulns)} 条新漏洞"
        }
    }
    requests.post(webhook, json=msg, timeout=5)

if __name__ == "__main__":
    push()