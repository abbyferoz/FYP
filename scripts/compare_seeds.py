"""Compare remediation strategies across many random synthetic networks.

python -m scripts.compare_seeds --seeds 30

Prints mean residual risk (% of baseline) after n patches for:

- graph-aware greedy remediation
- highest-CVSS-first
- highest-EPSS-first

The purpose is to test whether graph-aware prioritisation remains effective across
different randomly generated enterprise-network conditions rather than relying on
one illustrative seed.
"""
from __future__ import annotations

import argparse
from statistics import mean

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.generator import generate_network
from apg.paths import paths_to_all
from apg.remediation import (
    baseline_risk,
    cvss_plan,
    epss_plan,
    greedy_plan,
)


def residual_at(plan, i: int) -> float:
    """Return residual risk at patch step i, carrying the final value forward."""
    if not plan:
        return 0.0

    return plan[
        min(
            i,
            len(plan) - 1,
        )
    ].residual_risk


def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--seeds",
        type=int,
        default=30,
        help="number of random network seeds to evaluate",
    )

    ap.add_argument(
        "--n",
        type=int,
        default=5,
        help="number of patches in each remediation plan",
    )

    ap.add_argument(
        "--k",
        type=int,
        default=50,
        help="attack paths retained per crown jewel",
    )

    a = ap.parse_args()

    graph_results = [
        []
        for _ in range(a.n)
    ]

    cvss_results = [
        []
        for _ in range(a.n)
    ]

    epss_results = [
        []
        for _ in range(a.n)
    ]

    skipped = 0

    graph_vs_cvss_wins = 0
    graph_vs_epss_wins = 0
    graph_best_or_equal = 0

    for seed in range(a.seeds):
        net = generate_network(
            seed
        )

        A = derive_attack_graph(
            net
        )

        paths = [
            p
            for ps in paths_to_all(
                A,
                INTERNET,
                net.crown_jewels(),
                a.k,
            ).values()
            for p in ps
        ]

        base = (
            baseline_risk(
                A,
                paths,
            )
            if paths
            else 0
        )

        if not base:
            skipped += 1
            continue

        g = greedy_plan(
            A,
            paths,
            a.n,
        )

        c = cvss_plan(
            net,
            A,
            paths,
            a.n,
        )

        e = epss_plan(
            net,
            A,
            paths,
            a.n,
        )

        for i in range(a.n):
            gi = residual_at(
                g,
                i,
            )

            ci = residual_at(
                c,
                i,
            )

            ei = residual_at(
                e,
                i,
            )

            graph_results[i].append(
                100 * gi / base
            )

            cvss_results[i].append(
                100 * ci / base
            )

            epss_results[i].append(
                100 * ei / base
            )

        final_g = residual_at(
            g,
            a.n - 1,
        )

        final_c = residual_at(
            c,
            a.n - 1,
        )

        final_e = residual_at(
            e,
            a.n - 1,
        )

        if final_g <= final_c:
            graph_vs_cvss_wins += 1

        if final_g <= final_e:
            graph_vs_epss_wins += 1

        if (
            final_g <= final_c
            and final_g <= final_e
        ):
            graph_best_or_equal += 1

    used = (
        a.seeds
        - skipped
    )

    print(
        f"{used} networks with attack paths "
        f"({skipped} skipped: "
        f"no path to any crown jewel)"
    )

    if used == 0:
        print(
            "No usable networks were generated."
        )
        return

    print(
        "\nMean residual risk "
        "(% of baseline)"
    )

    print(
        "\n"
        "n patches | graph-aware | CVSS-first | EPSS-first"
    )

    print(
        "----------+-------------+------------+-----------"
    )

    for i in range(a.n):
        print(
            f"{i + 1:^9} | "
            f"{mean(graph_results[i]):9.1f}% | "
            f"{mean(cvss_results[i]):8.1f}% | "
            f"{mean(epss_results[i]):7.1f}%"
        )

    print(
        f"\nAfter {a.n} patches:"
    )

    print(
        f"  graph-aware <= CVSS-first: "
        f"{graph_vs_cvss_wins}/{used} networks"
    )

    print(
        f"  graph-aware <= EPSS-first: "
        f"{graph_vs_epss_wins}/{used} networks"
    )

    print(
        f"  graph-aware <= both baselines: "
        f"{graph_best_or_equal}/{used} networks"
    )


if __name__ == "__main__":
    main()