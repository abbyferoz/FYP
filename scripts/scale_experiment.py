"""Scalability and density experiment for the synthetic enterprise network.

Example:
    python -m scripts.scale_experiment

The experiment varies:

1. Number of workstations -> network size
2. Vulnerability rate     -> vulnerability density

For every configuration it runs several random seeds and records:

- mean number of hosts
- mean attack-graph edges
- mean retained attack paths
- mean attack-graph construction time
- mean path-discovery time
- mean remediation-analysis time
- mean total analysis time
- mean residual risk after one graph-aware patch
- number of networks skipped because no attack path reached a crown jewel

This experiment evaluates scalability of the prototype. It does NOT benchmark the
system against commercial products.
"""
from __future__ import annotations

import argparse
import time
from statistics import mean

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.generator import generate_network
from apg.paths import paths_to_all
from apg.remediation import baseline_risk, greedy_plan


def safe_mean(values: list[float]) -> float:
    """Mean with a safe zero value for an empty list."""
    return mean(values) if values else 0.0


def run_configuration(
    workstations: int,
    vuln_rate: float,
    seeds: int,
    k: int,
    patches: int,
) -> dict:
    """Run one network-size / vulnerability-rate configuration."""

    host_counts: list[float] = []
    edge_counts: list[float] = []
    path_counts: list[float] = []

    graph_times: list[float] = []
    path_times: list[float] = []
    remediation_times: list[float] = []
    total_times: list[float] = []

    residual_after_one: list[float] = []

    skipped = 0
    usable = 0

    for seed in range(seeds):
        total_start = time.perf_counter()

        net = generate_network(
            seed,
            workstations,
            vuln_rate=vuln_rate,
        )

        host_counts.append(
            float(len(net.hosts))
        )

        graph_start = time.perf_counter()

        A = derive_attack_graph(
            net
        )

        graph_elapsed = (
            time.perf_counter()
            - graph_start
        )

        graph_times.append(
            graph_elapsed
        )

        edge_counts.append(
            float(A.number_of_edges())
        )

        jewels = net.crown_jewels()

        path_start = time.perf_counter()

        by_jewel = paths_to_all(
            A,
            INTERNET,
            jewels,
            k,
        )

        paths = [
            p
            for ps in by_jewel.values()
            for p in ps
        ]

        path_elapsed = (
            time.perf_counter()
            - path_start
        )

        path_times.append(
            path_elapsed
        )

        path_counts.append(
            float(len(paths))
        )

        base = (
            baseline_risk(
                A,
                paths,
            )
            if paths
            else 0.0
        )

        remediation_start = time.perf_counter()

        if base > 0:
            plan = greedy_plan(
                A,
                paths,
                patches,
            )

            usable += 1

            if plan:
                residual_after_one.append(
                    100
                    * plan[0].residual_risk
                    / base
                )
            else:
                residual_after_one.append(
                    100.0
                )

        else:
            skipped += 1

        remediation_elapsed = (
            time.perf_counter()
            - remediation_start
        )

        remediation_times.append(
            remediation_elapsed
        )

        total_elapsed = (
            time.perf_counter()
            - total_start
        )

        total_times.append(
            total_elapsed
        )

    return {
        "workstations": workstations,
        "vuln_rate": vuln_rate,
        "seeds": seeds,
        "usable": usable,
        "skipped": skipped,
        "hosts": safe_mean(host_counts),
        "edges": safe_mean(edge_counts),
        "paths": safe_mean(path_counts),
        "graph_ms": 1000 * safe_mean(graph_times),
        "path_ms": 1000 * safe_mean(path_times),
        "remediation_ms": 1000 * safe_mean(remediation_times),
        "total_ms": 1000 * safe_mean(total_times),
        "residual_1": safe_mean(residual_after_one),
    }


def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--seeds",
        type=int,
        default=10,
        help="random networks tested per configuration",
    )

    ap.add_argument(
        "--k",
        type=int,
        default=50,
        help="maximum retained attack paths per crown jewel",
    )

    ap.add_argument(
        "--patches",
        type=int,
        default=5,
        help="graph-aware patch budget",
    )

    a = ap.parse_args()

    workstation_sizes = [
        10,
        30,
        60,
        100,
	200,
    ]

    vulnerability_rates = [
        0.20,
        0.35,
        0.50,
    ]

    print(
        "Scalability / density experiment"
    )

    print(
        f"Seeds per configuration: {a.seeds}"
    )

    print(
        f"Paths retained per crown jewel: {a.k}"
    )

    print(
        f"Patch budget: {a.patches}"
    )

    print(
        "\nRunning configurations..."
    )

    results = []

    for workstations in workstation_sizes:
        for vuln_rate in vulnerability_rates:
            print(
                f"  workstations={workstations:<3} "
                f"vuln_rate={vuln_rate:.2f}"
            )

            result = run_configuration(
                workstations=workstations,
                vuln_rate=vuln_rate,
                seeds=a.seeds,
                k=a.k,
                patches=a.patches,
            )

            results.append(
                result
            )

    print(
        "\n== Scalability results"
    )

    print(
        "\n"
        " WS | Vuln | Hosts | Edges  | Paths | "
        "Graph ms | Path ms | Remed ms | Total ms | "
        "Risk after 1 | Used"
    )

    print(
        "----+------+-------+--------+-------+"
        "----------+---------+----------+----------+"
        "--------------+------"
    )

    for r in results:
        print(
            f"{r['workstations']:>3} | "
            f"{r['vuln_rate']:.2f} | "
            f"{r['hosts']:5.1f} | "
            f"{r['edges']:6.1f} | "
            f"{r['paths']:5.1f} | "
            f"{r['graph_ms']:8.2f} | "
            f"{r['path_ms']:7.2f} | "
            f"{r['remediation_ms']:8.2f} | "
            f"{r['total_ms']:8.2f} | "
            f"{r['residual_1']:10.1f}% | "
            f"{r['usable']:>2}/{r['seeds']}"
        )

    print(
        "\nNotes:"
    )

    print(
        "  Hosts = mean number of generated enterprise hosts."
    )

    print(
        "  Edges = mean number of attack-graph edges."
    )

    print(
        "  Paths = mean number of retained paths across crown jewels."
    )

    print(
        "  Graph ms = mean attack-graph construction time."
    )

    print(
        "  Path ms = mean attack-path discovery time."
    )

    print(
        "  Remed ms = mean graph-aware remediation analysis time."
    )

    print(
        "  Total ms = mean end-to-end analysis time for the configuration."
    )

    print(
        "  Risk after 1 = mean residual path risk after the first "
        "graph-aware patch, for usable networks only."
    )

    print(
        "  Used = networks that contained at least one attack path "
        "to a crown jewel."
    )


if __name__ == "__main__":
    main()