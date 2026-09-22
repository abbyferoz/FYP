"""Streamlit dashboard: streamlit run app.py"""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st
from pyvis.network import Network as PyvisNetwork

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.chokepoints import path_participation
from apg.generator import generate_network
from apg.infragraph import build_infrastructure_graph
from apg.paths import paths_to_all, top_paths
from apg.remediation import baseline_risk, cvss_plan, greedy_plan, rank_single_patches

ZONE_COLOR = {"internet": "#8b949e", "dmz": "#e3a008", "corp": "#3b82f6",
              "servers": "#8b5cf6", "data": "#ef4444"}
ZONE_LEVEL = {"internet": 0, "dmz": 1, "corp": 2, "servers": 3, "data": 4}   # left-to-right layout columns

st.set_page_config(page_title="Attack-Path Intelligence", layout="wide")
st.title("Enterprise Cyber Attack-Path Intelligence")
st.caption("Milestone 1 demonstrator: synthetic enterprise network, attack-path discovery, "
           "risk scoring, chokepoints and patch prioritisation.")

with st.sidebar:
    st.header("Synthetic network")
    seed = st.number_input("Random seed", 0, 10_000, 7)
    workstations = st.slider("Workstations", 10, 150, 30)
    vuln_rate = st.slider("Chance a service is vulnerable", 0.05, 0.8, 0.35, 0.05)
    k = st.slider("Paths kept per crown jewel", 5, 100, 50)


@st.cache_resource(show_spinner="Building network and attack graph...")
def build(seed: int, workstations: int, vuln_rate: float, k: int):
    net = generate_network(seed, workstations, vuln_rate=vuln_rate)
    A = derive_attack_graph(net)
    G = build_infrastructure_graph(net)
    by_jewel = paths_to_all(A, INTERNET, net.crown_jewels(), k)
    return net, A, G, by_jewel


net, A, G, by_jewel = build(seed, workstations, vuln_rate, k)
baseline = [p for ps in by_jewel.values() for p in ps]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Hosts", len(net.hosts))
c2.metric("Knowledge-graph edges", G.number_of_edges())
c3.metric("Attack-graph edges", A.number_of_edges())
c4.metric("Attack paths kept", len(baseline))

if not baseline:
    st.warning("No attack path from the internet reaches any crown jewel in this network. "
               "Try another seed or raise the vulnerability chance.")
    st.stop()


def render_graph(jewel: str, highlight: list[str], shown: list) -> None:
    nodes = {n for p in shown for n in p.nodes}
    edges = {(u, v) for p in shown for u, v in zip(p.nodes, p.nodes[1:])}
    hl_edges = set(zip(highlight, highlight[1:]))
    g = PyvisNetwork(height="520px", width="100%", directed=True, cdn_resources="in_line",
                     bgcolor="#0e1117", font_color="#e6edf3")
    for n in nodes:
        d = A.nodes[n]
        g.add_node(n, label=n, color=ZONE_COLOR.get(d["zone"], "#888"), level=ZONE_LEVEL.get(d["zone"], 2),
                   size=32 if n == jewel else 22, font={"size": 18, "color": "#e6edf3"},
                   title=f"{n} ({d['zone']}) criticality {d['criticality']}",
                   borderWidth=4 if n in highlight else 1)
    for u, v in edges:
        hot = (u, v) in hl_edges
        g.add_edge(u, v, color="#ff4b4b" if hot else "#6e7681", width=4 if hot else 1,
                   title=f"p={A[u][v]['p']:.2f}")
    g.set_options(json.dumps({"layout": {"hierarchical": {"enabled": True, "direction": "LR",
                                                          "levelSeparation": 220, "nodeSpacing": 90}},
                              "physics": {"enabled": False}}))
    html = g.generate_html()
    if hasattr(st, "iframe"):                 # newer Streamlit: components.html is deprecated
        st.iframe(html, height=540)
    else:
        import streamlit.components.v1 as components
        components.html(html, height=540)


tab_paths, tab_choke, tab_patch, tab_kg = st.tabs(
    ["Attack paths", "Chokepoints", "Patch plan", "Knowledge graph"])

with tab_paths:
    jewel = st.selectbox("Crown jewel", list(by_jewel), format_func=lambda j: f"{j}  (criticality {net.hosts[j].criticality})")
    paths = by_jewel[jewel]
    if not paths:
        st.info(f"{jewel} is not reachable from the internet in this network.")
    else:
        df = pd.DataFrame([{"rank": i + 1, "probability": round(p.probability, 3), "risk": round(p.risk, 2),
                            "route": " -> ".join(p.nodes)} for i, p in enumerate(paths)])
        left, right = st.columns([3, 2])
        with left:
            rank = st.slider("Highlight path rank", 1, len(paths), 1)
            render_graph(jewel, paths[rank - 1].nodes, paths[:10])
            st.caption("Graph shows the 10 most probable paths; the selected path is in red. "
                       "Colours: orange DMZ, blue corporate, purple servers, red data tier.")
        with right:
            sel = paths[rank - 1]
            st.subheader(f"Path {rank}: p = {sel.probability:.2f}, risk = {sel.risk:.2f}")
            for i, s in enumerate(sel.steps, 1):
                st.write(f"{i}. {s}")
            st.dataframe(df, hide_index=True, height=300)

with tab_choke:
    st.write("Hosts that appear on the most (risk-weighted) attack paths. Fixing or isolating these cuts the most routes.")
    rows = path_participation(baseline)[:10]
    st.dataframe(pd.DataFrame(rows, columns=["host", "summed path risk", "paths through it"]), hide_index=True)

with tab_patch:
    base = baseline_risk(A, baseline)
    st.write("Which patches remove the most attack risk? Residual risk is measured over the "
             f"{len(baseline)} baseline paths and shown as a percentage of the unpatched total.")
    singles = rank_single_patches(A, baseline)[:8]
    st.subheader("Best single patches")
    st.dataframe(pd.DataFrame([{"CVE": s.patch[1], "host": s.patch[0], "CVSS": s.cvss,
                                "paths broken": f"{s.paths_broken}/{len(baseline)}",
                                "risk removed %": round(100 * (1 - s.residual_risk / base), 1)}
                               for s in singles]), hide_index=True)
    n = st.slider("Patch budget (number of patches)", 1, 10, 5)
    g, c = greedy_plan(A, baseline, n), cvss_plan(net, A, baseline, n)
    chart = pd.DataFrame({"patches applied": range(1, n + 1),
                          "graph-aware plan": [100 * (g[min(i, len(g) - 1)].residual_risk / base) for i in range(n)],
                          "highest CVSS first": [100 * (c[i].residual_risk / base) for i in range(n)]}
                         ).set_index("patches applied")
    st.subheader("Residual risk (% of baseline) vs patch budget")
    st.line_chart(chart)
    st.caption("Caveat: the graph-aware plan directly optimises this metric on the same model, so it is "
               "expected to win. The M4 validation must use real scan data and stronger baselines "
               "(CVSS + KEV, EPSS, internet-facing first).")
    st.subheader("Graph-aware patch order")
    st.dataframe(pd.DataFrame([{"step": i + 1, "patch CVE": s.patch[1], "on host": s.patch[0],
                                "residual risk %": round(100 * s.residual_risk / base, 1)}
                               for i, s in enumerate(g)]), hide_index=True)

with tab_kg:
    st.write("The infrastructure knowledge graph (Host, User, CVE, Subnet nodes) that will be loaded into Neo4j.")
    labels = pd.Series([d["label"] for _, d in G.nodes(data=True)]).value_counts().rename("nodes")
    types = pd.Series([d["type"] for _, _, d in G.edges(data=True)]).value_counts().rename("edges")
    a, b = st.columns(2)
    a.dataframe(labels)
    b.dataframe(types)
