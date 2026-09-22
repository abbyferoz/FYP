"""Does graph-aware patching beat highest-CVSS-first across many random networks?

python -m scripts.compare_seeds --seeds 30
Prints mean residual risk (% of baseline) after n patches for both strategies.
"""
from __future__ import annotations

import argparse
from statistics import mean

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.generator import generate_network
from apg.paths import paths_to_all
from apg.remediation import baseline_risk, cvss_plan, greedy_plan


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--k", type=int, default=50)
    a = ap.parse_args()
    greedy, cvss, wins, skipped = [[] for _ in range(a.n)], [[] for _ in range(a.n)], 0, 0
    for seed in range(a.seeds):
        net = generate_network(seed)
        A = derive_attack_graph(net)
        paths = [p for ps in paths_to_all(A, INTERNET, net.crown_jewels(), a.k).values() for p in ps]
        base = baseline_risk(A, paths) if paths else 0
        if not base:
            skipped += 1
            continue
        g, c = greedy_plan(A, paths, a.n), cvss_plan(net, A, paths, a.n)
        for i in range(a.n):
            gi = g[min(i, len(g) - 1)].residual_risk if g else 0
            ci = c[min(i, len(c) - 1)].residual_risk
            greedy[i].append(100 * gi / base)
            cvss[i].append(100 * ci / base)
        wins += g[a.n - 1].residual_risk <= c[a.n - 1].residual_risk if g else 0
    used = a.seeds - skipped
    print(f"{used} networks with attack paths ({skipped} skipped: no path to any crown jewel)")
    print("n patches | graph-aware greedy | highest-CVSS first   (mean residual risk, % of baseline)")
    for i in range(a.n):
        print(f"    {i+1}     |       {mean(greedy[i]):5.1f}%       |       {mean(cvss[i]):5.1f}%")
    print(f"graph-aware <= CVSS-first after {a.n} patches on {wins}/{used} networks")


if __name__ == "__main__":
    main()
