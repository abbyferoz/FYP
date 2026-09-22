"""CVSS v3.1 base-score calculator, implemented from the FIRST specification.

We compute scores from the vector string instead of trusting a stored number,
so the same code can later score every CVE pulled from the NVD feed.
The Exploitability sub-score (max 3.9) is what drives attack-path probability.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

MAX_EXPLOITABILITY = 3.9


@dataclass(frozen=True)
class CvssScore:
    base: float
    exploitability: float
    impact: float


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: smallest number with one decimal >= x (float-safe)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if not parts[0].startswith("CVSS:3"):
        raise ValueError(f"Not a CVSS v3 vector: {vector!r}")
    return dict(p.split(":", 1) for p in parts[1:])


def score(vector: str) -> CvssScore:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        base = 0.0
    elif changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = _roundup(min(impact + exploitability, 10))
    return CvssScore(base=base, exploitability=round(exploitability, 1), impact=round(impact, 1))
