# vuln_graph.py  (方案 B 完整版)
import json, torch, ipaddress
import networkx as nx
from torch_geometric.data import Data
from pathlib import Path

ROOT = Path(__file__).parent
JSON_PATH = ROOT / "clean" / "final_vulns.json"

# 统一把 severity 映射成数值
SEV2IDX = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def build_graph() -> Data | None:
    if not JSON_PATH.exists():
        return None

    with open(JSON_PATH, encoding="utf-8") as f:
        vulns = json.load(f)

    G = nx.Graph()  # 无向图即可

    # 1. 建节点
    for v in vulns:
        host = v.get("host") or v.get("matched-at", "-")
        sev  = v.get("severity", "unknown").lower()
        # 提取纯 IP（去掉端口）
        ip = host.split(":")[0] if ":" in host else host
        G.add_node(ip, sev_idx=SEV2IDX[sev])

    if len(G) == 0:
        return None

    # 2. 建边
    # 2-a 自环
    for n in G.nodes:
        G.add_edge(n, n)

    # 2-b 同 /24 网段边
    nodes = list(G.nodes)
    for i, a in enumerate(nodes):
        for j, b in enumerate(nodes):
            if i >= j:  # 避免重复
                continue
            try:
                net_a = ipaddress.ip_network(f"{a}/24", strict=False)
                net_b = ipaddress.ip_network(f"{b}/24", strict=False)
                if net_a == net_b:
                    G.add_edge(a, b)
            except ValueError:
                continue  # 非 IP 跳过

    # 3. 转 tensor
    node2id = {ip: idx for idx, ip in enumerate(G.nodes)}
    x = torch.tensor([[G.nodes[n]["sev_idx"]] for n in G.nodes], dtype=torch.float)

    edges = [(node2id[u], node2id[v]) for u, v in G.edges]
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

    return Data(x=x, edge_index=edge_index)


if __name__ == "__main__":
    g = build_graph()
    print(g)