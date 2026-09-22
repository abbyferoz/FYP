"""Turns CVSS into an attacker-success probability (a modelling choice - see README)."""
from __future__ import annotations

import math

from apg import cvss
from apg.catalog import VULNS
from apg.model import Vuln

KEV_BOOST = 1.25       # known-exploited-in-the-wild vulnerabilities are easier than CVSS says
P_CAP = 0.99
CRED_THEFT_P = 0.5     # assumed probability of reusing credentials harvested from a session


def exploit_probability(v: Vuln) -> float:
    """p = ExploitabilitySubscore / 3.9 (its maximum), boosted for KEV, capped below 1."""
    p = cvss.score(v.vector).exploitability / cvss.MAX_EXPLOITABILITY
    if v.kev:
        p *= KEV_BOOST
    return min(P_CAP, p)


def grants_foothold(v: Vuln) -> bool:
    """Modelling rule: a vulnerability lets an attacker take over the host only if it has an
    integrity impact (code execution / modification). Pure information disclosure such as
    Heartbleed (C:H/I:N/A:N) does not create an attack-graph edge on its own."""
    return cvss.parse_vector(v.vector)["I"] != "N"


def cve_base_score(cve_id: str) -> float:
    return cvss.score(VULNS[cve_id].vector).base


def edge_cost(p: float) -> float:
    """Shortest path on -ln(p) == most probable path (probabilities multiply along a path)."""
    return -math.log(p)
