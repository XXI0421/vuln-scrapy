#!/usr/bin/env python3
import subprocess, os, sys, time, colorama
from colorama import Fore, Style

colorama.init()

os.chdir(os.path.dirname(__file__))
venv_python = sys.executable

def step(msg):
    print(f"{Fore.GREEN}🚀 {msg}{Style.RESET_ALL}")

def ok(msg):
    print(f"{Fore.CYAN}✅ {msg}{Style.RESET_ALL}")

step("1/5 资产发现 + nuclei")
subprocess.run([venv_python, "recon.py"])

step("2/5 PoC 框架去重 / 二次验证")
subprocess.run([venv_python, "poc-framework/main.py"])

step("3/5 模型训练")
subprocess.run([venv_python, "train.py"])                              

step("4/5 风险预测")
import subprocess, pathlib as pl

base = pl.Path(r"D:\pythonProject1")
venv_python = base / ".venv/Scripts/python.exe"
script      = base / "intel-engine/predict.py"
json_file   = base / "intel-engine/clean/final_vulns.json"

subprocess.run([str(venv_python), str(script), str(json_file)], check=True)

step("5/5 打开 Streamlit 看板")
# 自动用 localhost，避免 0.0.0.0 网络解析失败
subprocess.Popen([venv_python, "-m", "streamlit", "run",
                  "streamlit_report.py", "--server.address=127.0.0.1", "--server.port=8501"])

time.sleep(2)
ok("浏览器请打开： http://localhost:8501")