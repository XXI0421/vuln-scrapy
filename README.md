# vuln-scrapy
# intel-engine  
**一站式漏洞风险评估 & 自动化处置管线**

---

## 📌 项目简介  
`intel-engine` 把「资产发现 → 漏洞扫描 → 图神经网络风险打分 → 可视化报告 → 联动封禁」串成一条命令即可跑完的闭环流程。  
- **资产发现**：fofa / nuclei / 自定义 POC  
- **风险模型**：PyTorch Geometric 图神经网络  
- **实时推理**：单文件即可输出每条 IP 的 0-1 风险概率  
- **可视化**：Streamlit 仪表盘一键打开  
- **联动处置**：自动生成 CSV、防火墙黑名单脚本  

---

## 🗂️ 目录速览  

| 文件 | 作用 |
|---|---|
| `recon.py` / `recon-lite.py` | 资产发现 & 漏洞扫描 |
| `gen_dummy.py` | 生成训练/测试用的假数据 |
| `train.py` | 读取 `clean/vuln_*.json` → 训练 GNN → 保存 `risk_gnn_final.pt` |
| `predict.py` | 对任意 JSON 实时输出风险概率 |
| `streamlit_report.py` | Web 仪表盘展示风险热力图 |
| `run_all.py` | 一键跑完整管线 |
| `clean/` | 存放扫描结果 JSON（训练+推理） |
| `config.yaml` | 资产发现配置 |

---

## 🚀 5 分钟上手  

### 1️⃣ 环境
```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt   # 若缺失手动补依赖
```

### 2️⃣ 生成训练数据（可选）
```bash
python gen_dummy.py        # 生成 clean/vuln_*.json
```

### 3️⃣ 训练模型
```bash
python train.py            # 输出 risk_gnn_final.pt
```

### 4️⃣ 实时推理
```bash
python predict.py clean/final_vulns.json
```
示例输出：  
```
139.162.244.247  风险概率: 0.9214
110.41.48.28     风险概率: 0.9152
...
```

### 5️⃣ 可视化看板
```bash
streamlit run streamlit_report.py
# 浏览器自动打开 http://localhost:8501
```

### 6️⃣ 一键全流程（推荐）
```bash
python run_all.py
```

---

## ⚙️ 配置文件 `config.yaml`
```yaml
targets:
  - 192.168.1.0/24
  - 10.0.0.0/16
fofa_token: "YOUR_FOFA_TOKEN"
nuclei_templates_path: "./nuclei-templates"
```

---

## 📊 风险阈值建议

| 风险概率 | 建议动作 |
|---|---|
| ≥0.90 | 立即封禁 / 紧急工单 |
| 0.70–0.89 | 高优处置 |
| 0.50–0.69 | 中优跟进 |
| <0.50 | 低优观察 |

---

## 🛠️ 常见问题 FAQ

| 现象 | 解决 |
|---|---|
| `节点数: 0` | 检查 `clean/` 是否有 `vuln_*.json` |
| `AUC=nan` | 训练集正负样本极度不平衡 → 使用 `train_test_split(..., stratify=data.y)` |
| `size mismatch` | 确保推理脚本与训练脚本建图逻辑完全一致 |

---

## 🤝 贡献 & 反馈
欢迎提 Issue / PR，一起把风险打得更准！
