"""Infrastructure knowledge graph using the schema from the project outline.

Nodes: Host, User, CVE, Subnet, Internet.
Edges: EXPOSED_TO, HAS_VULN, CAN_ACCESS, HAS_SESSION, IN_SUBNET.
This is the model that later gets loaded into Neo4j (one node/edge -> one Cypher MERGE);
the attack graph in attackgraph.py is derived from the same Network object.
"""
from __future__ import annotations

import networkx as nx

from apg.attackgraph import INTERNET
from apg.model import Network


def build_infrastructure_graph(net: Network) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()
    G.add_node(INTERNET, label="Internet")
    zones = {h.zone for h in net.hosts.values()}
    for z in zones:
        G.add_node(f"subnet:{z}", label="Subnet", name=z)
    for h in net.hosts.values():
        G.add_node(h.id, label="Host", role=h.role, criticality=h.criticality)
        G.add_edge(h.id, f"subnet:{h.zone}", type="IN_SUBNET")
        for s in h.services:
            for cve in s.cve_ids:
                G.add_node(cve, label="CVE")
                G.add_edge(h.id, cve, type="HAS_VULN", port=s.port)
            if net.allows("internet", h.zone, s.port):
                G.add_edge(INTERNET, h.id, type="EXPOSED_TO", port=s.port)
    for u in net.users.values():
        G.add_node(u.id, label="User", privilege=u.privilege)
    for u, h in net.sessions:
        G.add_edge(u, h, type="HAS_SESSION")
    for u, h in net.admin_of:
        G.add_edge(u, h, type="CAN_ACCESS", level="admin")
    for (src, dst), ports in net.firewall.items():
        if src in zones and dst in zones and src != dst:
            G.add_edge(f"subnet:{src}", f"subnet:{dst}", type="CAN_ACCESS", ports=sorted(ports))
    return G
