#!/usr/bin/env python3
# train_v2.py
import json, random, pathlib as pl, numpy as np
import torch, torch.nn.functional as F
from torch_geometric.nn import GCNConv
from sklearn.metrics import roc_auc_score

SEED = 42
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)

ROOT = pl.Path(__file__).parent / "clean"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ---------- utils ----------
def load_json(fp):
    raw = json.load(open(fp, encoding="utf-8"))
    return json.loads(raw) if isinstance(raw, str) else (raw if isinstance(raw, list) else [raw])

def ip_subnet(ip):   # 10.0.123.45 -> 10.0.123
    return '.'.join(ip.split('.')[:3])

# ---------- build graph ----------
def build_graph(root_dir):
    import networkx as nx
    records = [r for fp in root_dir.glob("final_vulns.json") for r in load_json(fp)]

    ip_info, template_set = {}, set()
    for r in records:
        host   = (r.get("host") or r.get("matched-at") or "0.0.0.0:0") if isinstance(r, dict) else str(r)
        ip     = host.split(":")[0]
        port   = int(host.split(":")[1]) if ":" in host else random.randint(8000, 9000)
        sev    = r.get("severity","unknown").lower() if isinstance(r, dict) else "unknown"
        risk_score   = r.get("info",{}).get("classification",{}).get("risk-score", random.randint(0,9)) if isinstance(r, dict) else random.randint(0,9)
        template = r.get("template-id", "unknown") if isinstance(r, dict) else "unknown"
        template_set.add(template)
        ip_info[ip] = {"sev": sev, "risk-score": risk_score, "port": port, "template": template}

    # 编码
    sev2id   = {s:i for i,s in enumerate(["critical","high","medium","low","info","unknown"])}
    tmpl2id  = {t:i for i,t in enumerate(sorted(template_set))}

    G = nx.Graph()
    for ip, info in ip_info.items():
        sev_emb   = sev2id[info["sev"]]
        tmpl_emb  = tmpl2id[info["template"]]
        # 特征：risk-score, port/10000, sev_embed, tmpl_embed
        feat = [float(info["risk-score"]), info["port"]/65535.0, float(sev_emb), float(tmpl_emb)]
        label = 1 if info["sev"] in {"critical","high"} else 0
        G.add_node(ip, x=feat, y=label)

    # 边：同 /24 子网互联，稀疏且带结构
    subnets = {}
    for ip in G.nodes:
        subnets.setdefault(ip_subnet(ip), []).append(ip)
    for ip_list in subnets.values():
        if len(ip_list) >= 2:
            for i in range(len(ip_list)):
                for j in range(i+1, len(ip_list)):
                    G.add_edge(ip_list[i], ip_list[j])

    from torch_geometric.utils import from_networkx
    data = from_networkx(G)
    data.x = torch.tensor(list(nx.get_node_attributes(G, "x").values()), dtype=torch.float)
    data.y = torch.tensor(list(nx.get_node_attributes(G, "y").values()), dtype=torch.long)
    return data

# ---------- model ----------
class GNN(torch.nn.Module):
    def __init__(self, in_dim=4, hid=64, out=2, drop=0.5):
        super().__init__()
        self.conv1 = GCNConv(in_dim, hid)
        self.conv2 = GCNConv(hid, hid)
        self.conv3 = GCNConv(hid, out)
        self.drop = drop

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=self.drop, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=self.drop, training=self.training)
        return self.conv3(x, edge_index)

# ---------- main ----------
def main():
    data = build_graph(ROOT).to(DEVICE)
    print("节点数:", data.num_nodes, "正样本比例:", data.y.float().mean().item())

    from sklearn.model_selection import train_test_split

    idx = torch.arange(data.num_nodes)
    train_idx, val_idx = train_test_split(
        idx,
        test_size=0.2,
        stratify=data.y.cpu(),      # 保持正负比例
        random_state=42
    )

    model = GNN().to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=1e-4)

    for epoch in range(1, 401):
        model.train()
        out = model(data.x, data.edge_index)[train_idx]
        loss = F.cross_entropy(out, data.y[train_idx])
        opt.zero_grad(); loss.backward(); opt.step()

        if epoch % 20 == 0 or epoch == 1:
            model.eval()
            with torch.no_grad():
                pred = F.softmax(model(data.x, data.edge_index)[val_idx], 1)[:, 1]
                auc = roc_auc_score(data.y[val_idx].cpu(), pred.cpu())
                print(f"Epoch {epoch:03d} | loss={loss:.4f} | val_AUC={auc:.4f}")

    torch.save(model.state_dict(), ROOT / "risk_gnn_final.pt")
    print("✅ 训练完成")

if __name__ == "__main__":
    main()