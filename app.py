"""Streamlit dashboard: streamlit run app.py

Two data sources, the same engine behind both:
  - a seeded synthetic enterprise network (reproducible, good for experiments)
  - a real `nmap -oX` scan you upload (what makes this a demonstrator, not a simulation)
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from pyvis.network import Network as PyvisNetwork

from apg import cvss
from apg.attackgraph import INTERNET, derive_attack_graph
from apg.catalog import FEED_META, VULNS
from apg.chokepoints import path_participation
from apg.generator import generate_network
from apg.infragraph import build_infrastructure_graph
from apg.nmap_import import network_from_scan, parse_nmap_xml
from apg.paths import paths_to_all
from apg.remediation import baseline_risk, cvss_plan, greedy_plan, rank_single_patches

ZONE_COLOR = {"internet": "#8b949e", "dmz": "#e3a008", "corp": "#3b82f6",
              "servers": "#8b5cf6", "data": "#ef4444"}
ZONE_LEVEL = {"internet": 0, "dmz": 1, "corp": 2, "servers": 3, "data": 4}
FALLBACK_COLOR, FALLBACK_LEVEL = "#888888", 2

st.set_page_config(page_title="Attack-Path Intelligence", layout="wide")
st.title("Enterprise Cyber Attack-Path Intelligence")
st.caption("Milestone 1 demonstrator: attack-path discovery, risk scoring, chokepoint "
           "analysis and patch prioritisation, on synthetic or real scan data.")

if FEED_META.source == "cache":
    st.success(f"Vulnerability data: {FEED_META.summary()}", icon=":material/verified:")
else:
    st.warning(f"Vulnerability data: {FEED_META.summary()} - numbers shown are "
               "ILLUSTRATIVE, not real.", icon=":material/warning:")

with st.sidebar:
    st.header("Data source")
    source = st.radio("Analyse", ["Synthetic network", "Real nmap scan"],
                      label_visibility="collapsed")
    if source == "Synthetic network":
        seed = st.number_input("Random seed", 0, 10_000, 7)
        workstations = st.slider("Workstations", 10, 150, 30)
        vuln_rate = st.slider("Chance a service is vulnerable", 0.05, 0.8, 0.35, 0.05)
        upload = None
    else:
        st.caption("Upload `nmap -sV --script vulners -oX out.xml` output. "
                   "**Only scan networks you own.**")
        upload = st.file_uploader("nmap XML", type=["xml"])
        zone_text = st.text_area(
            "Zone map (one CIDR=zone per line)",
            "192.168.56.0/24=dmz\n192.168.57.0/24=servers\n192.168.58.0/24=data",
            help="nmap cannot see your segmentation. Without this, every subnet becomes "
                 "its own zone and reachability between them is assumed open.")
        vantage = st.text_input("Scan was run from zone", "internet")
    k = st.slider("Paths kept per crown jewel", 5, 100, 50)
    min_crit = st.slider("Crown-jewel threshold (criticality)", 1, 10, 8)


@st.cache_resource(show_spinner="Building network and attack graph...")
def build_synthetic(seed: int, workstations: int, vuln_rate: float):
    return generate_network(seed, workstations, vuln_rate=vuln_rate), []


@st.cache_resource(show_spinner="Parsing scan and building attack graph...")
def build_from_scan(xml_bytes: bytes, zone_text: str, vantage: str):
    zone_map = dict(line.split("=", 1) for line in zone_text.splitlines()
                    if "=" in line)
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        f.write(xml_bytes)
        tmp = Path(f.name)
    try:
        scan = parse_nmap_xml(tmp, vantage=vantage)
        return network_from_scan(scan, zone_map=zone_map, known_cves=set(VULNS))
    finally:
        tmp.unlink(missing_ok=True)


if source == "Real nmap scan":
    if upload is None:
        st.info("Upload an nmap XML file in the sidebar to analyse a real network. "
                "`tests/fixtures/lab_scan.xml` in this repo is a ready-made example.")
        st.stop()
    try:
        net, warnings = build_from_scan(upload.getvalue(), zone_text, vantage)
    except (ValueError, KeyError) as e:
        st.error(f"Could not import that scan: {e}")
        st.stop()
else:
    net, warnings = build_synthetic(seed, workstations, vuln_rate)


@st.cache_resource(show_spinner="Deriving attack graph...")
def analyse(_net, k: int, min_crit: int, key: str):
    A = derive_attack_graph(_net)
    G = build_infrastructure_graph(_net)
    return A, G, paths_to_all(A, INTERNET, _net.crown_jewels(min_crit), k)


A, G, by_jewel = analyse(net, k, min_crit,
                         key=f"{source}{k}{min_crit}{len(net.hosts)}{id(net)}")
baseline = [p for ps in by_jewel.values() for p in ps]

if warnings:
    with st.expander(f":material/report: {len(warnings)} modelling assumption(s) - "
                     "read these before quoting any number", expanded=True):
        for w in warnings:
            st.write(f"- {w}")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Hosts", len(net.hosts))
c2.metric("Knowledge-graph edges", G.number_of_edges())
c3.metric("Attack-graph edges", A.number_of_edges())
c4.metric("Crown jewels", len(net.crown_jewels(min_crit)))
c5.metric("Attack paths kept", len(baseline))

if not baseline:
    st.warning("No attack path from the internet reaches any crown jewel. For a synthetic "
               "network, try another seed or raise the vulnerability chance. For a scan, "
               "check the scan found CVEs (use `--script vulners`) and that a host is "
               "above the crown-jewel threshold.")
    st.stop()


def render_graph(jewel: str, highlight: list[str], shown: list) -> None:
    nodes = {n for p in shown for n in p.nodes}
    edges = {(u, v) for p in shown for u, v in zip(p.nodes, p.nodes[1:])}
    hl_edges = set(zip(highlight, highlight[1:]))
    g = PyvisNetwork(height="520px", width="100%", directed=True, cdn_resources="in_line",
                     bgcolor="#0e1117", font_color="#e6edf3")
    for n in nodes:
        d = A.nodes[n]
        zone = d.get("zone", "")
        g.add_node(n, label=n, color=ZONE_COLOR.get(zone, FALLBACK_COLOR),
                   level=ZONE_LEVEL.get(zone, FALLBACK_LEVEL),
                   size=32 if n == jewel else 22, font={"size": 18, "color": "#e6edf3"},
                   title=f"{n} ({zone}) criticality {d.get('criticality', 0)}",
                   borderWidth=4 if n in highlight else 1)
    for u, v in edges:
        hot = (u, v) in hl_edges
        g.add_edge(u, v, color="#ff4b4b" if hot else "#6e7681", width=4 if hot else 1,
                   title=f"p={A[u][v]['p']:.2f}")
    g.set_options(json.dumps({"layout": {"hierarchical": {"enabled": True, "direction": "LR",
                                                          "levelSeparation": 220,
                                                          "nodeSpacing": 90}},
                              "physics": {"enabled": False}}))
    html = g.generate_html()
    if hasattr(st, "iframe"):                 # newer Streamlit: components.html is deprecated
        st.iframe(html, height=540)
    else:
        import streamlit.components.v1 as components
        components.html(html, height=540)


tab_paths, tab_choke, tab_patch, tab_kg, tab_data = st.tabs(
    ["Attack paths", "Chokepoints", "Patch plan", "Knowledge graph", "Vulnerability data"])

with tab_paths:
    jewel = st.selectbox("Crown jewel", list(by_jewel),
                         format_func=lambda j: f"{j}  (criticality {net.hosts[j].criticality})")
    paths = by_jewel[jewel]
    if not paths:
        st.info(f"{jewel} is not reachable from the internet in this network.")
    else:
        df = pd.DataFrame([{"rank": i + 1, "probability": round(p.probability, 3),
                            "risk": round(p.risk, 2), "hops": len(p.nodes) - 1,
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
    st.write("Hosts that appear on the most (risk-weighted) attack paths. Fixing or "
             "isolating these cuts the most routes.")
    rows = path_participation(baseline)[:10]
    if rows:
        st.dataframe(pd.DataFrame(rows, columns=["host", "summed path risk",
                                                 "paths through it"]), hide_index=True)
    else:
        st.info("Every path is a single hop from the internet, so there are no "
                "intermediate hosts to act as chokepoints.")

with tab_patch:
    base = baseline_risk(A, baseline)
    st.write("Which patches remove the most attack risk? Residual risk is measured over "
             f"the {len(baseline)} baseline paths, as a percentage of the unpatched total.")
    singles = rank_single_patches(A, baseline)[:8]
    st.subheader("Best single patches")
    st.dataframe(pd.DataFrame([{"CVE": s.patch[1], "host": s.patch[0], "CVSS": s.cvss,
                                "KEV": "yes" if VULNS[s.patch[1]].kev else "no",
                                "paths broken": f"{s.paths_broken}/{len(baseline)}",
                                "risk removed %": round(100 * (1 - s.residual_risk / base), 1)}
                               for s in singles]), hide_index=True)
    n = st.slider("Patch budget (number of patches)", 1, 10, 5)
    g, c = greedy_plan(A, baseline, n), cvss_plan(net, A, baseline, n)
    chart = pd.DataFrame(
        {"patches applied": range(1, n + 1),
         "graph-aware plan": [100 * (g[min(i, len(g) - 1)].residual_risk / base)
                              for i in range(n)],
         "highest CVSS first": [100 * (c[min(i, len(c) - 1)].residual_risk / base)
                                for i in range(n)]}).set_index("patches applied")
    st.subheader("Residual risk (% of baseline) vs patch budget")
    st.line_chart(chart)
    st.caption("Caveat to state in any demo: the graph-aware plan directly optimises this "
               "metric on this model, so it is expected to win. The honest claim is that "
               "reachability-aware ordering beats severity-only ordering, not that this "
               "particular margin generalises. M4 validation needs real scan data and "
               "stronger baselines (CVSS+KEV, EPSS, internet-facing first).")
    st.subheader("Graph-aware patch order")
    st.dataframe(pd.DataFrame([{"step": i + 1, "patch CVE": s.patch[1], "on host": s.patch[0],
                                "CVSS": s.cvss,
                                "residual risk %": round(100 * s.residual_risk / base, 1)}
                               for i, s in enumerate(g)]), hide_index=True)

with tab_kg:
    st.write("The infrastructure knowledge graph (Host, User, CVE, Subnet nodes) that "
             "loads into Neo4j. Export it with `python -m scripts.export_graph`.")
    labels = pd.Series([d["label"] for _, d in G.nodes(data=True)]).value_counts().rename("nodes")
    types = pd.Series([d["type"] for _, _, d in G.edges(data=True)]).value_counts().rename("edges")
    a, b = st.columns(2)
    a.dataframe(labels)
    b.dataframe(types)

with tab_data:
    st.write("Every CVE below comes from the NVD feed. The **our score** column is computed "
             "by `apg/cvss.py` from the vector string; **NVD score** is what NVD published. "
             "They must agree - that is what `tests/test_cvss.py` checks.")
    present = sorted({c for h in net.hosts.values() for s in h.services for c in s.cve_ids})
    show_all = st.checkbox("Show the whole catalog, not just what is on this network")
    ids = sorted(VULNS) if show_all else present
    rows = []
    for cid in ids:
        v = VULNS[cid]
        ours = cvss.score(v.vector).base
        rows.append({"CVE": cid, "title": v.title[:70],
                     "our score": ours, "NVD score": v.nvd_base,
                     "agrees": "yes" if v.nvd_base is None or ours == v.nvd_base else "NO",
                     "KEV": "yes" if v.kev else "-",
                     "ransomware": "yes" if v.ransomware else "-",
                     "published": v.published, "vector": v.vector})
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, height=480)
        mismatches = sum(r["agrees"] == "NO" for r in rows)
        st.metric("CVEs where our calculator disagrees with NVD", mismatches)
    else:
        st.info("No CVEs are present on this network.")
