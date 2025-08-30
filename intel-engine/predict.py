#!/usr/bin/env python3
"""
predict.py  -- 单文件推理
用法：python predict.py D:\pythonProject1\intel-engine\clean\final_vulns.json
"""
import json, pathlib as pl, sys, tempfile
import torch
import networkx as nx
from torch_geometric.utils import from_networkx

# 与 train.py 完全一致的特征与网络定义
def load_json(fp):
    raw = json.load(open(fp, encoding="utf-8"))
    return json.loads(raw) if isinstance(raw, str) else (raw if isinstance(raw, list) else [raw])

def ip_subnet(ip):   # 训练时同 /24 连边
    return '.'.join(ip.split('.')[:3])

class GNN(torch.nn.Module):
    def __init__(self, in_dim=4, hid=64, out=2):
        super().__init__()
        from torch_geometric.nn import GCNConv
        self.conv1 = GCNConv(in_dim, hid)
        self.conv2 = GCNConv(hid, hid)
        self.conv3 = GCNConv(hid, out)

    def forward(self, x, edge_index):
        x = torch.relu(self.conv1(x, edge_index))
        x = torch.dropout(x, p=0.5, train=self.training)
        x = torch.relu(self.conv2(x, edge_index))
        x = torch.dropout(x, p=0.5, train=self.training)
        return self.conv3(x, edge_index)

# ---------- 与训练完全一致的建图 ----------
def build_graph_from_records(records):
    import numpy as np
    import networkx as nx

    # 统计字典
    ip_info, templates = {}, set()
    for r in records:
        host   = (r.get("host") or r.get("matched-at") or "0.0.0.0:0") if isinstance(r, dict) else str(r)
        ip     = host.split(":")[0]
        port   = int(host.split(":")[1]) if ":" in host else 8983
        sev    = r.get("severity","unknown").lower() if isinstance(r, dict) else "unknown"
        cvss   = r.get("info",{}).get("classification",{}).get("cvss-score", 0.218) if isinstance(r, dict) else 0.218
        tmpl   = r.get("template-id","unknown") if isinstance(r, dict) else "unknown"
        templates.add(tmpl)
        ip_info[ip] = {"sev": sev, "cvss": cvss, "port": port, "tmpl": tmpl}

    # 编码
    sev2id  = {s:i for i,s in enumerate(["critical","high","medium","low","info","unknown"])}
    tmpl2id = {t:i for i,t in enumerate(sorted(templates))}

    G = nx.Graph()
    for ip, info in ip_info.items():
        sev_id   = sev2id[info["sev"]]
        tmpl_id  = tmpl2id[info["tmpl"]]
        feat = [float(info["cvss"]),
                info["port"]/65535.0,
                float(sev_id),
                float(tmpl_id)]
        label = 1 if info["sev"] in {"critical","high"} else 0
        G.add_node(ip, x=feat, y=label)

    # 同 /24 连边
    subnets = {}
    for ip in G.nodes:
        subnets.setdefault(ip_subnet(ip), []).append(ip)
    for ip_list in subnets.values():
        if len(ip_list) >= 2:
            for i in range(len(ip_list)):
                for j in range(i+1, len(ip_list)):
                    G.add_edge(ip_list[i], ip_list[j])

    data = from_networkx(G)
    data.x = torch.tensor(list(nx.get_node_attributes(G, "x").values()), dtype=torch.float)
    data.y = torch.tensor(list(nx.get_node_attributes(G, "y").values()), dtype=torch.long)
    return data, list(G.nodes)

# ---------- 推理 ----------
def predict(json_file):
    records = load_json(json_file)
    data, nodes = build_graph_from_records(records)
    data = data.to("cpu")

    model = GNN().to("cpu")
    model.load_state_dict(torch.load(ROOT / "risk_gnn_final.pt", map_location="cpu"))
    model.eval()

    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        probs  = torch.softmax(logits, dim=1)[:, 1]

    for ip, p in zip(nodes, probs.tolist()):
        print(f"{ip:<15}  风险概率: {p:.4f}")

if __name__ == "__main__":
    ROOT = pl.Path(__file__).parent / "clean"
    predict(sys.argv[1])