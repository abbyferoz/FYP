"""Check remediation plans on a metric the graph-aware planner does NOT optimise.

python -m scripts.reachability_check --seeds 100

Why this exists
---------------
`compare_seeds` scores every plan on residual risk over a FIXED set of baseline paths
(the top-k paths per crown jewel on the unpatched network). The graph-aware planner
minimises exactly that quantity, so it is expected to do well on it.

This script asks a different question. After applying each plan's patches it REBUILDS the
attack graph and searches for paths again from scratch, so routes that were never in the
retained top-k set are found too. It reports:

- re-discovered risk: sum over crown jewels of (probability of the most probable surviving
  path x criticality), as a percentage of the same quantity on the unpatched network
- crown jewels still reachable from the internet after patching

Both are still outputs of our model, not measurements of real-world breaches.
"""
from __future__ import annotations

import argparse
from statistics import mean

import networkx as nx

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.generator import generate_network
from apg.model import Network
from apg.paths import path_probability, paths_to_all
from apg.remediation import baseline_risk, cvss_plan, epss_plan, greedy_plan

STRATEGIES = ("graph-aware", "CVSS-first", "EPSS-first")


def rediscovered(net: Network, patched: set) -> tuple[float, int]:
    """(risk of the best surviving path to each crown jewel, number of jewels reachable)."""
    patched = frozenset(patched)
    A = derive_attack_graph(net, patched)
    risk, reachable = 0.0, 0
    for cj in net.crown_jewels():
        try:
            nodes = nx.shortest_path(A, INTERNET, cj, weight="cost")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        p = path_probability(A, nodes, patched)
        if p > 0:
            reachable += 1
            risk += p * A.nodes[cj]["criticality"]
    return risk, reachable


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=100, help="number of random network seeds")
    ap.add_argument("--n", type=int, default=5, help="number of patches in each plan")
    ap.add_argument("--k", type=int, default=50, help="baseline paths retained per crown jewel")
    a = ap.parse_args()

    steps = sorted({1, a.n})
    fixed = {s: {n: [] for n in steps} for s in STRATEGIES}
    redisc = {s: {n: [] for n in steps} for s in STRATEGIES}
    reach = {s: {n: [] for n in steps} for s in STRATEGIES}
    all_cut = {s: 0 for s in STRATEGIES}
    used = 0
    jewels = []

    for seed in range(a.seeds):
        net = generate_network(seed)
        A = derive_attack_graph(net)
        paths = [p for ps in paths_to_all(A, INTERNET, net.crown_jewels(), a.k).values()
                 for p in ps]
        base = baseline_risk(A, paths) if paths else 0
        if not base:
            continue
        used += 1
        full_risk, n_reach = rediscovered(net, set())
        jewels.append(n_reach)

        plans = {
            "graph-aware": greedy_plan(A, paths, a.n),
            "CVSS-first": cvss_plan(net, A, paths, a.n),
            "EPSS-first": epss_plan(net, A, paths, a.n),
        }
        for name, plan in plans.items():
            for n in steps:
                applied = plan[:n]
                patched = {s.patch for s in applied}
                r, reachable = rediscovered(net, patched)
                fixed[name][n].append(100 * applied[-1].residual_risk / base if applied else 100.0)
                redisc[name][n].append(100 * r / full_risk)
                reach[name][n].append(reachable)
            if reach[name][a.n][-1] == 0:
                all_cut[name] += 1

    print(f"{used} networks with attack paths ({a.seeds - used} skipped: no path to any crown jewel)")
    print(f"Mean crown jewels reachable before patching: {mean(jewels):.2f}")
    print(f"Baseline paths retained per crown jewel: k={a.k}\n")
    print("strategy    | patches | fixed-path residual | re-discovered risk | jewels still reachable")
    print("------------+---------+---------------------+--------------------+-----------------------")
    for name in STRATEGIES:
        for n in steps:
            print(f"{name:11} | {n:7} | {mean(fixed[name][n]):18.1f}% | "
                  f"{mean(redisc[name][n]):17.1f}% | {mean(reach[name][n]):.2f}")
    print(f"\nNetworks with every crown jewel unreachable after {a.n} patches:")
    for name in STRATEGIES:
        print(f"  {name:11}: {all_cut[name]}/{used}")


if __name__ == "__main__":
    main()
