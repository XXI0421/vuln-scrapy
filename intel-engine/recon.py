#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon.py – 完全适配你的 config.yaml
"""
import os, sys, json, base64, yaml, sqlite3, logging, time, requests, subprocess
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import argparse
from dotenv import load_dotenv

ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")          # 允许 .env 覆盖
cfg = yaml.safe_load(open(ROOT / "config.yaml", encoding="utf-8"))

# ---------- 日志 ----------
LOG_FMT = "[%(asctime)s] [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT, handlers=[
    logging.FileHandler(ROOT / "clean" / "recon.log", encoding="utf-8"),
    logging.StreamHandler(sys.stdout)
])
log = logging.getLogger("recon")

# ---------- 路径 ----------
TOOLS  = ROOT / cfg["paths"]["tools_dir"]
NUCLEI = TOOLS / ("nuclei.exe" if os.name == "nt" else "nuclei")
HTTPX  = TOOLS / ("httpx.exe"  if os.name == "nt" else "httpx")
CLEAN  = ROOT / cfg["paths"]["output_dir"]
CLEAN.mkdir(exist_ok=True)

# ---------- SQLite ----------
DB = ROOT / cfg["sqlite"]["db"]
def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {cfg["sqlite"]["table"]}(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {cfg["sqlite"]["col_ip"]} TEXT,
            {cfg["sqlite"]["col_port"]} TEXT,
            protocol TEXT,
            host TEXT,
            title TEXT,
            banner TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
init_db()

# ---------- FOFA ----------
def fofa_fetch():
    api = "https://fofa.info/api/v1/search/all"
    params = {
        "email": cfg["fofa"]["email"],
        "key":   cfg["fofa"]["key"],
        "qbase64": base64.b64encode(cfg["fofa"]["query"].encode()).decode(),
        "fields": cfg["fofa"]["fields"],
        "size": cfg["fofa"]["size"]
    }
    r = requests.get(api, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        log.error(f"FOFA 错误: {data.get('errmsg')}")
        return []

    flds = cfg["fofa"]["fields"].split(",")
    rows = data.get("results", [])
    if not rows:
        log.warning("FOFA 无结果")
        return []

    # 写入 SQLite
    with sqlite3.connect(DB) as conn:
        conn.executemany(f"""
        INSERT INTO {cfg["sqlite"]["table"]}
        ({cfg["sqlite"]["col_ip"]}, {cfg["sqlite"]["col_port"]}, protocol, host, title, banner)
        VALUES (?,?,?,?,?,?)
        """, rows)

    # 拼装 URL（已修复）
    urls = []
    for row in rows:
        d = dict(zip(flds, row))
        host_or_ip = d.get("host") or f"{d['ip']}:{d['port']}"
        if "://" in host_or_ip:
            url = host_or_ip
        else:
            scheme = d.get("protocol", "http")
            url = f"{scheme}://{host_or_ip}".rstrip("/")
        urls.append(url)
    urls = list(dict.fromkeys(urls))
    log.info(f"FOFA 拉取 & 入库完成，共 {len(urls)} 个 URL")
    return urls
# ---------- httpx ----------
def httpx_probe(urls):
    host_path = CLEAN / "hosts.txt"
    host_path.write_text("\n".join(urls), encoding="utf-8")
    alive_path = CLEAN / "alive.json"
    cmd = [
        str(HTTPX), "-l", str(host_path),
        "-sc", "-title", "-tech-detect", "-silent", "-no-color", "-json",
        "-o", str(alive_path)
    ]
    log.info("httpx 探测中…")
    subprocess.run(cmd, check=False)

    alive = []
    if alive_path.exists():
        with open(alive_path, encoding="utf-8") as f:
            alive = [json.loads(l)["url"] for l in f if l.strip()]
    (ROOT / cfg["paths"]["alive_txt"]).write_text("\n".join(alive), encoding="utf-8")
    log.info(f"存活 {len(alive)} 个")
    return alive

# ---------- nuclei ----------
def nuclei_scan():
    tpl_path   = ROOT / cfg["nuclei"]["templates"]
    alive_path = ROOT / cfg["paths"]["alive_txt"]
    if not alive_path.exists() or alive_path.stat().st_size == 0:
        log.warning("无存活目标，跳过 PoC")
        return

    json_out = CLEAN / "nuclei.json"

    cmd = [
        str(NUCLEI), "-l", str(alive_path),
        "-t", str(tpl_path),
        "-severity", cfg["nuclei"]["severity"],
        "-c", str(cfg["nuclei"]["threads"]),
        "-rate-limit", str(cfg["nuclei"]["rate_limit"]),
        "-je", str(json_out)   # ← 只保留 JSON
    ]
    log.info("生成 nuclei.json")
    subprocess.run(cmd, check=False)

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="调试日志")
    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    urls = fofa_fetch()
    if not urls:
        log.error("无资产，终止")
        return
    alive = httpx_probe(urls)
    if alive:
        nuclei_scan()
    log.info("全部完成 ✅")

if __name__ == "__main__":
    main()