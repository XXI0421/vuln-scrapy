#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon-lite.py  ——  只读 SQLite 的轻量版本
运行：python recon-lite.py
"""
import os, json, yaml, sqlite3, subprocess, time
from pathlib import Path

ROOT = Path(__file__).parent
cfg  = yaml.safe_load(open(ROOT / "config.yaml", encoding="utf-8"))

TOOLS = ROOT / cfg["paths"]["tools_dir"]
NUCLEI = TOOLS / "nuclei.exe"
HTTPX  = TOOLS / "httpx.exe"
OUT    = ROOT / cfg["paths"]["output_dir"]
OUT.mkdir(exist_ok=True)

DB_PATH = ROOT / cfg.get("sqlite", {}).get("db", "intel.db")
TABLE   = cfg.get("sqlite", {}).get("table", "assets")

def log(msg): print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# ---------- 1. 读库 ----------
def load_hosts():
    if not DB_PATH.exists():
        log("数据库不存在"); return []
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 先看表里有什么列
    cur.execute(f"PRAGMA table_info({TABLE})")
    cols = [c[1] for c in cur.fetchall()]

    # 优先用 host 列（已经是 ip:port）
    if "host" in cols:
        sql = f"SELECT DISTINCT host FROM {TABLE}"
        hosts = [r[0] for r in cur.execute(sql)]
        log(f"从 host 列取出 {len(hosts)} 条")
    else:
        # fallback 到 ip+port
        sql = f"SELECT DISTINCT ip,port FROM {TABLE}"
        hosts = [f"{ip}:{port}" for ip, port in cur.execute(sql)]
        log(f"从 ip+port 拼接 {len(hosts)} 条")
    conn.close()
    return hosts

# ---------- 2. httpx ----------
def httpx_probe(hosts):
    host_file = OUT / "hosts.txt"
    host_file.write_text("\n".join(hosts))

    cmd = f"{HTTPX} -l {host_file} -sc -title -silent -no-color -json -o {OUT}/alive.json"
    log(cmd)
    subprocess.run(cmd, shell=True)

    # 显式指定 UTF-8 读取
    alive = []
    if (OUT / "alive.json").exists():
        with open(OUT / "alive.json", encoding="utf-8") as f:
            alive = [json.loads(l)["url"] for l in f if l.strip()]

    (OUT / "alive.txt").write_text("\n".join(alive))
    log(f"存活 {len(alive)} 个")
    return alive
# ---------- 3. nuclei ----------
def nuclei_scan():
    tpl = ROOT / cfg["nuclei"]["templates"]
    cmd = (f"{NUCLEI} -l {OUT}/alive.txt "
           f"-t {tpl} -severity {cfg['nuclei']['severity']} "
           f"-c {cfg['nuclei']['threads']} -rate-limit {cfg['nuclei']['rate_limit']} "
           f"-o {OUT}/nuclei_raw.txt")
    log(cmd); subprocess.run(cmd, shell=True)

    vulns = []
    for line in open(OUT / "nuclei_raw.txt"):
        if not line.strip(): continue
        sev, url, tmpl = line.split(maxsplit=2)
        vulns.append({"severity": sev.strip("[]"), "url": url, "template": tmpl})
    (OUT / "vulns.csv").write_text(
        "\n".join([f"{v['severity']},{v['url']},{v['template']}" for v in vulns])
    )
    log(f"PoC 命中 {len(vulns)} 条")

# ---------- main ----------
def main():
    hosts = load_hosts()
    if not hosts:
        log("没有可用资产，终止"); return
    alive = httpx_probe(hosts)
    if alive:
        nuclei_scan()
    log("全部完成 ✅")

if __name__ == "__main__":
    main()