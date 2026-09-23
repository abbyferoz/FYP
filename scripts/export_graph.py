"""Export the knowledge graph as Cypher for Neo4j.

    python -m scripts.export_graph --out graph.cypher
    python -m scripts.export_graph --scan scans/lab.xml --out lab.cypher
    python -m scripts.export_graph --queries          # print the example queries

Load it (Neo4j running via `brew install --cask docker` then the neo4j image):
    cat graph.cypher | cypher-shell -u neo4j -p password
"""
from __future__ import annotations

import argparse
from pathlib import Path

from apg.catalog import VULNS
from apg.generator import generate_network
from apg.neo4j_export import EXAMPLE_QUERIES, to_cypher
from apg.nmap_import import network_from_scan, parse_nmap_xml


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="graph.cypher", help="output file (default graph.cypher)")
    ap.add_argument("--scan", help="export a real nmap scan instead of a synthetic network")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workstations", type=int, default=30)
    ap.add_argument("--queries", action="store_true", help="also print example Cypher queries")
    a = ap.parse_args()

    if a.scan:
        net, warnings = network_from_scan(parse_nmap_xml(a.scan), known_cves=set(VULNS))
        for w in warnings:
            print(f"  ! {w}")
    else:
        net = generate_network(a.seed, a.workstations)

    cypher = to_cypher(net)
    Path(a.out).write_text(cypher)
    print(f"Wrote {a.out}: {len(cypher.splitlines())} statements, "
          f"{len(net.hosts)} hosts, {len(net.users)} users")
    print(f"Load with:  cat {a.out} | cypher-shell -u neo4j -p password")
    if a.queries:
        print(EXAMPLE_QUERIES)


if __name__ == "__main__":
    main()
