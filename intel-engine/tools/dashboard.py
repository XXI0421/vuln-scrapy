import streamlit as st, pandas as pd, sqlite3
from pathlib import Path

ROOT = Path(__file__).parent
DB = ROOT / ".."/ "intel.db"           # ← 指向 FOFA 资产库
NUCLEI_JSON = ROOT / ".." / "clean" / "final_vulns.json"

st.set_page_config(page_title="FOFA 资产 & 漏洞总览", layout="wide")
st.title("📊 FOFA 资产 + nuclei 漏洞总览")

# 1️⃣ 资产清单（来自 FOFA）
with st.expander("🗂 FOFA 资产"):
    conn = sqlite3.connect(DB)
    assets = pd.read_sql("SELECT ip,port,protocol,host,title,banner FROM assets", conn)
    conn.close()
    st.metric("资产数量", len(assets))
    st.dataframe(assets, use_container_width=True)

# 2️⃣ 漏洞清单（来自 nuclei）
with st.expander("🚨 漏洞清单"):
    if NUCLEI_JSON.exists():
        vulns = pd.read_json(NUCLEI_JSON)
        st.metric("漏洞数量", len(vulns))
        st.dataframe(vulns, use_container_width=True)
    else:
        st.info("暂无漏洞")

# 3️⃣ 一键下载
if NUCLEI_JSON.exists():
    with open(NUCLEI_JSON, "rb") as f:
        st.download_button("📥 导出漏洞 JSON", f, "final_vulns.json", "application/json")