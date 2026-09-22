"""Derives the attack graph from a Network.

Nodes are 'internet' plus every host. A directed edge A -> B means: an attacker who has a
foothold on A can get a foothold on B. Each edge carries the list of ways to do it
(Options): a network exploit of a vulnerable service on B that A's zone can reach, or reuse
of an admin credential harvested from a logon session on A. Edge probability is the best
available option, so patching one option may only weaken an edge instead of removing it.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import networkx as nx

from apg.catalog import VULNS
from apg.model import Network
from apg.scoring import CRED_THEFT_P, edge_cost, exploit_probability, grants_foothold

INTERNET = "internet"
ADMIN_PORTS = (445, 3389)     # ports an admin uses to log on to another host


@dataclass(frozen=True)
class Option:
    kind: str        # "exploit" | "cred"
    ref: str         # CVE id, or user id for credential reuse
    p: float
    label: str
    target: str      # host the option gives access to


def blocked(o: Option, patched: frozenset | set) -> bool:
    return o.kind == "exploit" and (o.target, o.ref) in patched


def derive_attack_graph(net: Network, patched: frozenset | set = frozenset()) -> nx.DiGraph:
    A = nx.DiGraph()
    A.add_node(INTERNET, kind="internet", zone="internet", criticality=0)
    zone_hosts: dict[str, list[str]] = defaultdict(list)
    for h in net.hosts.values():
        A.add_node(h.id, kind="host", zone=h.zone, role=h.role, criticality=h.criticality)
        zone_hosts[h.zone].append(h.id)
    zones = set(zone_hosts) | {"internet"}
    opts: dict[tuple[str, str], list[Option]] = defaultdict(list)

    # Network exploits: a source can attack any vulnerable service its zone may reach.
    for t in net.hosts.values():
        for svc in t.services:
            for cve in svc.cve_ids:
                vuln = VULNS.get(cve)
                if vuln is None:
                    raise KeyError(
                        f"{t.id}:{svc.port} claims {cve}, which is not in the catalog. "
                        f"Add it to data/cve_seeds.txt and run `python -m scripts.fetch_feeds`, "
                        f"or filter it out when importing (see network_from_scan's known_cves).")
                if (t.id, cve) in patched or not grants_foothold(vuln):
                    continue
                p = exploit_probability(vuln)
                for zone in zones:
                    if not net.allows(zone, t.zone, svc.port):
                        continue
                    for s in ([INTERNET] if zone == "internet" else zone_hosts[zone]):
                        if s != t.id:
                            opts[(s, t.id)].append(
                                Option("exploit", cve, p, f"exploit {cve} on {t.id}:{svc.port}", t.id))

    # Credential reuse: attacker on H harvests users logged in there and logs on where they are admin.
    admin_targets: dict[str, list[str]] = defaultdict(list)
    for u, h in net.admin_of:
        admin_targets[u].append(h)
    for u, h in net.sessions:
        src = net.hosts[h]
        for t_id in admin_targets[u]:
            t = net.hosts[t_id]
            if t_id == h:
                continue
            if any(net.allows(src.zone, t.zone, port) and any(s.port == port for s in t.services)
                   for port in ADMIN_PORTS):
                opts[(h, t_id)].append(
                    Option("cred", u, CRED_THEFT_P, f"reuse {u} credentials harvested on {h}", t_id))

    for (s, t), options in opts.items():
        best = max(o.p for o in options)
        A.add_edge(s, t, p=best, cost=edge_cost(best), options=options)
    return A
