"""Command-line demo: python -m scripts.run_demo  (from the attack-path-intel folder)."""
from __future__ import annotations

import argparse

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.chokepoints import path_participation
from apg.generator import generate_network
from apg.infragraph import build_infrastructure_graph
from apg.paths import paths_to_all
from apg.remediation import baseline_risk, cvss_plan, greedy_plan, rank_single_patches


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workstations", type=int, default=30)
    ap.add_argument("--vuln-rate", type=float, default=0.35)
    ap.add_argument("--k", type=int, default=50, help="paths kept per crown jewel")
    ap.add_argument("--patches", type=int, default=5)
    a = ap.parse_args()

    net = generate_network(a.seed, a.workstations, vuln_rate=a.vuln_rate)
    G = build_infrastructure_graph(net)
    A = derive_attack_graph(net)
    jewels = net.crown_jewels()
    print(f"Network: {len(net.hosts)} hosts, {len(net.users)} users | "
          f"knowledge graph {G.number_of_nodes()} nodes / {G.number_of_edges()} edges | "
          f"attack graph {A.number_of_edges()} edges | crown jewels: {', '.join(jewels)}")

    by_jewel = paths_to_all(A, INTERNET, jewels, a.k)
    baseline = [p for ps in by_jewel.values() for p in ps]
    for j, ps in by_jewel.items():
        print(f"\n== {j}: {len(ps)} paths found (showing top 2)")
        for p in ps[:2]:
            print(f"  p={p.probability:.3f} risk={p.risk:.2f}  " + " -> ".join(p.nodes))
            for s in p.steps:
                print(f"      - {s}")

    print("\n== Chokepoints (risk-weighted path participation)")
    for host, risk, n in path_participation(baseline)[:5]:
        print(f"  {host:14s} risk={risk:6.2f} paths={n}")

    print(f"\n== Best single patches (baseline residual risk {baseline_risk(A, baseline):.2f})")
    for s in rank_single_patches(A, baseline)[:5]:
        print(f"  patch {s.patch[1]} on {s.patch[0]:12s} -> residual {s.residual_risk:6.2f}, "
              f"paths broken {s.paths_broken}/{len(baseline)}")

    print(f"\n== Graph-aware greedy plan vs highest-CVSS-first (n patches: residual risk as % of baseline / paths broken)")
    base = baseline_risk(A, baseline)
    g, c = greedy_plan(A, baseline, a.patches), cvss_plan(net, A, baseline, a.patches)
    for i in range(min(len(g), len(c))):
        print(f"  n={i+1}  greedy: {100*g[i].residual_risk/base:5.1f}% / {g[i].paths_broken:3d}"
              f"   cvss-first: {100*c[i].residual_risk/base:5.1f}% / {c[i].paths_broken:3d}")


if __name__ == "__main__":
    main()
