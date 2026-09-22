"""Which patches break the most dangerous attack paths?

Evaluation is done on a FIXED set of baseline paths (the top-k most probable paths to each
crown jewel on the unpatched network) so different patch plans are compared fairly.
Metric: residual risk = sum over baseline paths of (probability under the plan x criticality).
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from apg.model import Network
from apg.paths import AttackPath, path_probability
from apg.scoring import cve_base_score

Patch = tuple[str, str]   # (host id, CVE id)


@dataclass
class PlanStep:
    patch: Patch
    cvss: float
    residual_risk: float
    paths_broken: int


def all_patchable(net: Network) -> list[Patch]:
    return [(h.id, c) for h in net.hosts.values() for s in h.services for c in s.cve_ids]


def relevant_patches(A: nx.DiGraph, paths: list[AttackPath]) -> set[Patch]:
    """Patches that could affect at least one baseline path."""
    out: set[Patch] = set()
    for p in paths:
        for u, v in zip(p.nodes, p.nodes[1:]):
            out |= {(o.target, o.ref) for o in A[u][v]["options"] if o.kind == "exploit"}
    return out


def evaluate(A: nx.DiGraph, paths: list[AttackPath], patched: frozenset) -> tuple[float, int]:
    residual, broken = 0.0, 0
    for p in paths:
        prob = path_probability(A, p.nodes, patched)
        residual += prob * A.nodes[p.nodes[-1]]["criticality"]
        broken += prob == 0.0
    return residual, broken


def baseline_risk(A: nx.DiGraph, paths: list[AttackPath]) -> float:
    return evaluate(A, paths, frozenset())[0]


def rank_single_patches(A: nx.DiGraph, paths: list[AttackPath]) -> list[PlanStep]:
    """Every relevant patch evaluated alone, best (lowest residual risk) first."""
    steps = []
    for patch in relevant_patches(A, paths):
        r, b = evaluate(A, paths, frozenset({patch}))
        steps.append(PlanStep(patch, cve_base_score(patch[1]), r, b))
    return sorted(steps, key=lambda s: (s.residual_risk, -s.paths_broken, s.patch))


def greedy_plan(A: nx.DiGraph, paths: list[AttackPath], n: int) -> list[PlanStep]:
    """Repeatedly apply the patch that lowers residual risk the most."""
    chosen: set[Patch] = set()
    cands = relevant_patches(A, paths)
    plan: list[PlanStep] = []
    for _ in range(n):
        best = None
        for patch in sorted(cands - chosen):
            r, b = evaluate(A, paths, frozenset(chosen | {patch}))
            if best is None or (r, -b) < (best[1], -best[2]):
                best = (patch, r, b)
        if best is None:
            break
        chosen.add(best[0])
        plan.append(PlanStep(best[0], cve_base_score(best[0][1]), best[1], best[2]))
    return plan


def cvss_plan(net: Network, A: nx.DiGraph, paths: list[AttackPath], n: int) -> list[PlanStep]:
    """Baseline: patch the highest-CVSS findings first, ignoring the attack graph."""
    ranked = sorted(all_patchable(net), key=lambda p: (-cve_base_score(p[1]), p))
    plan, chosen = [], set()
    for patch in ranked[:n]:
        chosen.add(patch)
        r, b = evaluate(A, paths, frozenset(chosen))
        plan.append(PlanStep(patch, cve_base_score(patch[1]), r, b))
    return plan
