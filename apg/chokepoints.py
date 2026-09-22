"""Chokepoint analysis: which hosts do many dangerous paths run through?"""
from __future__ import annotations

from collections import defaultdict

import networkx as nx

from apg.attackgraph import INTERNET
from apg.paths import AttackPath


def path_participation(paths: list[AttackPath]) -> list[tuple[str, float, int]]:
    """(host, summed risk of paths through it, number of paths) for intermediate hosts."""
    risk: dict[str, float] = defaultdict(float)
    count: dict[str, int] = defaultdict(int)
    for p in paths:
        for n in p.nodes[1:-1]:
            if n != INTERNET:
                risk[n] += p.risk
                count[n] += 1
    return sorted(((n, risk[n], count[n]) for n in risk), key=lambda x: -x[1])


def betweenness(A: nx.DiGraph) -> dict[str, float]:
    """Classic betweenness centrality on -ln(p) costs (structure only, ignores targets)."""
    return nx.betweenness_centrality(A, weight="cost")
