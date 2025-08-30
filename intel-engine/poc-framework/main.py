#!/usr/bin/env python3
import json, pathlib, sys

ROOT = pathlib.Path(__file__).parent.parent
json_lines = ROOT / "clean" / "nuclei.json"
final_json = ROOT / "clean" / "final_vulns.json"

if final_json.exists():
    try:
        old_vulns = json.loads(final_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        old_vulns = []
else:
    old_vulns = []

if not json_lines.exists():
    print("❌ 找不到 nuclei.json")
    sys.exit(0)

new_vulns = []
with open(json_lines, encoding="utf-8-sig") as f:
    for lineno, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)

            # 兼容 list / dict 两种格式
            if isinstance(raw, list):
                for item in raw:
                    new_vulns.append({
                        "template-id": item.get("template-id"),
                        "host": item.get("host"),
                        "severity": item.get("info", {}).get("severity")
                    })
            else:
                new_vulns.append({
                    "template-id": raw.get("template-id"),
                    "host": raw.get("host"),
                    "severity": raw.get("info", {}).get("severity")
                })
        except json.JSONDecodeError as e:
            print(f"⚠️ 第 {lineno} 行解析失败：{e}")
            continue

# 去重（host + template-id）
seen = {(v["host"], v["template-id"]) for v in old_vulns if v.get("host") and v.get("template-id")}
merged = old_vulns + [v for v in new_vulns
                      if (v.get("host"), v.get("template-id")) not in seen
                      and v.get("host") and v.get("template-id")]

with open(final_json, "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2, ensure_ascii=False)

print(f"✅ 已写入 final_vulns.json，共 {len(merged)} 条漏洞（新增 {len(merged) - len(old_vulns)} 条）")