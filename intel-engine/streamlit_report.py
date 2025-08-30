# streamlit_report.py
import streamlit as st
import pandas as pd
from pathlib import Path
import json

ROOT = Path(__file__).parent
JSON_PATH = ROOT / "clean" / "final_vulns.json"

st.set_page_config(
    page_title="实时漏洞扫描看板",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .main .block-container{padding-top:1.5rem;}
    h1{text-align:center;color:#0e1116;margin-bottom:.25rem;}
    div[data-testid="stMetric"]{
        background:#fff;border-radius:8px;
        box-shadow:0 2px 8px rgba(0,0,0,.05);
        padding:8px 16px;
    }
    .dataframe th{background:#f5f5f5;color:#333;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<h1>📊 实时漏洞扫描看板</h1>"
    "<p style='text-align:center;color:#6e6e6e;margin-top:-10px;'>"
    f"Latest scan: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}</p>",
    unsafe_allow_html=True,
)

if not JSON_PATH.exists():
    st.info("🎉 当前未发现任何漏洞，请稍后再试")
    st.stop()

# ---------- 读取 & 拉平 ----------
with open(JSON_PATH, "r", encoding="utf-8") as f:
    raw = json.load(f)

records = []
for item in raw:
    if isinstance(item, list):
        records.extend(item)
    elif isinstance(item, dict):
        records.append(item)

# ---------- 统一字段 ----------
rows = []
for r in records:
    rows.append({
        "Host": r.get("host") or r.get("matched-at") or "-",
        "Name": r.get("info", {}).get("name") or r.get("template-id") or "-",
        "Severity": r.get("severity") or "unknown",
        "Matched-At": r.get("matched-at") or r.get("host") or "-",
        "Timestamp": r.get("timestamp") or pd.Timestamp.now().isoformat(),
        "RiskScore": round(r.get("risk_score", 0), 3),
    })

df_vis = pd.DataFrame(rows)

# ---------- 顶部指标 ----------
total = len(df_vis)
critical = (df_vis["Severity"].str.lower() == "critical").sum()
high = (df_vis["Severity"].str.lower() == "high").sum()
max_risk = df_vis["RiskScore"].max()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("漏洞总数", total)
with col2:
    st.metric("严重级", critical)
with col3:
    st.metric("高危级", high)
with col4:
    st.metric("GNN 风险分", f"{max_risk:.3f}")

# ---------- 明细表 ----------
st.markdown("### 🔎 漏洞明细")
with st.expander("点击展开 / 折叠", expanded=True):

    def color_severity(val):
        cmap = {
            "critical": "#d32f2f",
            "high": "#ff9800",
            "medium": "#fbc02d",
            "low": "#388e3c",
        }
        color = cmap.get(str(val).lower(), "#9e9e9e")
        return f"background-color:{color};color:#fff;border-radius:4px;padding:2px 6px;"

    styled = (
        df_vis.style.map(color_severity, subset=["Severity"])
        .set_properties(**{"text-align": "left"})
        .set_table_styles([{"selector": "th", "props": [("text-align", "left")]}])
    )
    st.dataframe(styled, use_container_width=True, height=420)

# ---------- 下载 ----------
with open(JSON_PATH, "rb") as f:
    st.download_button(
        label="📥 下载 JSON",
        data=f,
        file_name="final_vulns.json",
        mime="application/json",
    )


# graph_view.py
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import networkx as nx
from pyvis.network import Network
import json, ipaddress
from pathlib import Path

ROOT = Path(__file__).parent
JSON_PATH = ROOT / "clean" / "final_vulns.json"

st.set_page_config(page_title="漏洞关系图", layout="wide")
st.markdown("## 🔗 漏洞-主机 关系图")

if not JSON_PATH.exists():
    st.warning("暂无漏洞数据")
    st.stop()

# 1. 读 JSON
with open(JSON_PATH, encoding="utf-8") as f:
    vulns = json.load(f)

# 2. 建图
G = nx.Graph()
SEV_COLOR = {
    "critical": "#d32f2f",
    "high": "#ff9800",
    "medium": "#fbc02d",
    "low": "#388e3c",
    "info": "#17a2b8",
    "unknown": "#9e9e9e"
}

for v in vulns:
    host = v.get("host") or v.get("matched-at", "-")
    ip   = host.split(":")[0]
    sev  = v.get("severity", "unknown").lower()
    title = v.get("info", {}).get("name") or v.get("template-id", "-")
    G.add_node(ip,
               label=ip,
               color=SEV_COLOR.get(sev, "#ccc"),
               title=f"{title}\n{sev.upper()}")
    # 同 /24 建边
    for other in list(G.nodes):
        if other != ip and ipaddress.ip_network(f"{ip}/24", strict=False) == \
                          ipaddress.ip_network(f"{other}/24", strict=False):
            G.add_edge(ip, other)

# 3. 生成 HTML
net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
net.from_nx(G)
net.save_graph(str(ROOT / "clean" / "vuln_graph.html"))

# 4. 嵌入 Streamlit
HtmlFile = open(ROOT / "clean" / "vuln_graph.html", "r", encoding="utf-8")
source_code = HtmlFile.read()
components.html(source_code, height=650, scrolling=True)