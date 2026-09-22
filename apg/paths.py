"""Attack-path discovery and risk scoring."""
from __future__ import annotations

from dataclasses import dataclass
from itertools import islice

import networkx as nx

from apg.attackgraph import Option, blocked


@dataclass
class AttackPath:
    nodes: list[str]
    probability: float     # product of edge probabilities: chance an attacker completes the chain
    risk: float            # probability x criticality of the final host (0-10)
    steps: list[str]       # human-readable description of each hop


def best_option(A: nx.DiGraph, u: str, v: str, patched=frozenset()) -> Option | None:
    live = [o for o in A[u][v]["options"] if not blocked(o, patched)]
    return max(live, key=lambda o: o.p) if live else None


def path_probability(A: nx.DiGraph, nodes: list[str], patched=frozenset()) -> float:
    prob = 1.0
    for u, v in zip(nodes, nodes[1:]):
        o = best_option(A, u, v, patched) if A.has_edge(u, v) else None
        if o is None:
            return 0.0
        prob *= o.p
    return prob


def top_paths(A: nx.DiGraph, source: str, target: str, k: int = 10) -> list[AttackPath]:
    """The k most probable simple attack paths (Yen's algorithm on -ln(p) edge costs)."""
    try:
        node_lists = list(islice(nx.shortest_simple_paths(A, source, target, weight="cost"), k))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
    crit = A.nodes[target].get("criticality", 1)
    out = []
    for nodes in node_lists:
        prob = path_probability(A, nodes)
        steps = [best_option(A, u, v).label for u, v in zip(nodes, nodes[1:])]
        out.append(AttackPath(nodes, prob, prob * crit, steps))
    return out


def paths_to_all(A: nx.DiGraph, source: str, targets: list[str], k: int = 10) -> dict[str, list[AttackPath]]:
    return {t: top_paths(A, source, t, k) for t in targets}
