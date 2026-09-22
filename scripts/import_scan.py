"""Run the full attack-path analysis against a real nmap scan.

    # 1. scan a lab network YOU OWN (a VM on a host-only adapter is ideal)
    nmap -sV --script vulners -oX scans/lab.xml 192.168.56.0/24

    # 2. analyse it
    python -m scripts.import_scan scans/lab.xml

    # with zones, so segmentation is modelled instead of assumed
    python -m scripts.import_scan scans/lab.xml \
        --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers \
        --zone 192.168.58.0/24=data --vantage internet

    # several vantage points: reachability becomes measured, not assumed
    python -m scripts.import_scan scans/outside.xml=internet scans/dmz.xml=dmz \
        --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers

NEVER scan a network you do not own or have written authorisation to test. Port
scanning third-party infrastructure is unlawful in most jurisdictions, including under
Pakistan's Prevention of Electronic Crimes Act 2016.
"""
from __future__ import annotations

import argparse
import sys

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.catalog import FEED_META, VULNS
from apg.chokepoints import path_participation
from apg.nmap_import import merge_scans, network_from_scan, parse_nmap_xml
from apg.paths import paths_to_all
from apg.remediation import baseline_risk, cvss_plan, greedy_plan, rank_single_patches


def kv(pairs: list[str], what: str, cast=str) -> dict:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            sys.exit(f"--{what} expects KEY=VALUE, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = cast(v)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scans", nargs="+",
                    help="nmap XML file(s). Use FILE=ZONE to say where the scan ran from.")
    ap.add_argument("--vantage", default="internet",
                    help="zone a scan ran from when not given as FILE=ZONE (default: internet)")
    ap.add_argument("--zone", action="append", metavar="CIDR=NAME",
                    help="map a subnet to a zone, e.g. 192.168.56.0/24=dmz (repeatable)")
    ap.add_argument("--role", action="append", metavar="HOST=ROLE",
                    help="override the inferred role for a host id or IP (repeatable)")
    ap.add_argument("--criticality", action="append", metavar="HOST=1-10",
                    help="override business criticality for a host id or IP (repeatable)")
    ap.add_argument("--min-criticality", type=int, default=8,
                    help="crown-jewel threshold (default 8)")
    ap.add_argument("-k", type=int, default=25, help="paths kept per crown jewel")
    ap.add_argument("--patches", type=int, default=5)
    a = ap.parse_args()

    zone_map = kv(a.zone, "zone")
    roles = kv(a.role, "role")
    crit = kv(a.criticality, "criticality", int)

    scans = []
    for spec in a.scans:
        path, _, vantage = spec.partition("=")
        scans.append(parse_nmap_xml(path, vantage or a.vantage))
    for s in scans:
        print(f"Parsed {s.source}: {len(s.hosts)} hosts up, vantage '{s.vantage}'\n"
              f"        nmap args: {s.args}")
    print(f"Catalog: {FEED_META.summary()}")

    build = merge_scans if len(scans) > 1 else (lambda ss, **kw: network_from_scan(ss[0], **kw))
    net, warnings = build(scans, zone_map=zone_map, roles=roles, criticality=crit,
                          known_cves=set(VULNS))

    print("\n== Imported network")
    for h in sorted(net.hosts.values(), key=lambda h: (h.zone, h.id)):
        cves = sorted({c for s in h.services for c in s.cve_ids})
        print(f"  {h.id:<18} zone={h.zone:<16} role={h.role:<12} crit={h.criticality:<2} "
              f"ports={sorted(s.port for s in h.services)}")
        if cves:
            print(f"  {'':<18} CVEs: {', '.join(cves)}")

    print("\n== Assumptions and gaps (say these out loud in a demo)")
    for w in warnings:
        print(f"  ! {w}")

    A = derive_attack_graph(net)
    jewels = net.crown_jewels(a.min_criticality)
    print(f"\n== Attack graph: {A.number_of_nodes()} nodes, {A.number_of_edges()} edges | "
          f"crown jewels (criticality >= {a.min_criticality}): {', '.join(jewels) or 'none'}")
    if not jewels:
        sys.exit("No crown jewels to target. Set one with --criticality HOST=10.")

    by_jewel = paths_to_all(A, INTERNET, jewels, a.k)
    baseline = [p for ps in by_jewel.values() for p in ps]
    if not baseline:
        print("\nNo attack path from the internet to any crown jewel. That is a GOOD "
              "result for the network, and a boring one for a demo: either the scan "
              "found no exploitable service on the way in, or segmentation blocks it.")
        return

    for j, ps in by_jewel.items():
        print(f"\n== {j}: {len(ps)} path(s)")
        for p in ps[:3]:
            print(f"  p={p.probability:.3f} risk={p.risk:.2f}  " + " -> ".join(p.nodes))
            for s in p.steps:
                print(f"      - {s}")

    chokes = path_participation(baseline)
    if chokes:
        print("\n== Chokepoints (risk-weighted path participation)")
        for host, risk, n in chokes[:5]:
            print(f"  {host:<18} risk={risk:7.2f} paths={n}")

    base = baseline_risk(A, baseline)
    print(f"\n== Best single patches (baseline residual risk {base:.2f})")
    for s in rank_single_patches(A, baseline)[:5]:
        print(f"  patch {s.patch[1]:<16} on {s.patch[0]:<18} -> residual {s.residual_risk:7.2f}, "
              f"paths broken {s.paths_broken}/{len(baseline)}")

    g, c = greedy_plan(A, baseline, a.patches), cvss_plan(net, A, baseline, a.patches)
    print("\n== Graph-aware plan vs highest-CVSS-first (residual risk as % of baseline)")
    for i in range(min(len(g), len(c))):
        print(f"  n={i+1}  graph-aware: {100*g[i].residual_risk/base:5.1f}% / broke "
              f"{g[i].paths_broken:3d}   cvss-first: {100*c[i].residual_risk/base:5.1f}% / broke "
              f"{c[i].paths_broken:3d}")


if __name__ == "__main__":
    main()
