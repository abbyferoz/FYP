# Enterprise Cyber Attack-Path Intelligence - Milestone 1 demonstrator

Models an enterprise network as a graph, finds and scores the attack paths from the internet
to crown-jewel assets, finds chokepoints, and recommends which patches remove the most risk.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                       # 16 tests
python -m scripts.run_demo                # command-line walkthrough
python -m scripts.compare_seeds --seeds 100   # graph-aware vs highest-CVSS-first, many networks
streamlit run app.py                      # dashboard
```

## How it works

| Module | Job |
|---|---|
| `apg/cvss.py` | CVSS v3.1 calculator (scores computed from vector strings; tested against NVD values) |
| `apg/catalog.py` | Small hand-entered CVE sample and per-role service templates (replace with NVD/KEV loader) |
| `apg/generator.py` | Seeded synthetic network: internet, DMZ, corporate, servers, data zone, users and sessions |
| `apg/infragraph.py` | Knowledge graph with the outline's schema (Host, User, CVE, Subnet; HAS_VULN, CAN_ACCESS, EXPOSED_TO...) |
| `apg/attackgraph.py` | Derives "foothold on A -> foothold on B" edges from exploits and credential reuse |
| `apg/paths.py` | Top-k most probable attack paths (Yen's algorithm on -ln p costs) and risk scoring |
| `apg/chokepoints.py` | Risk-weighted path participation and betweenness centrality |
| `apg/remediation.py` | Single-patch ranking, greedy patch plan, highest-CVSS-first baseline |

## Modelling assumptions (decide these with your advisor, they drive every result)

1. Exploit probability = CVSS Exploitability sub-score / 3.9, times 1.25 if the CVE is in CISA KEV, capped at 0.99.
2. A vulnerability gives a foothold only if its CVSS integrity impact is not None (so Heartbleed alone does not).
3. Credential reuse succeeds with a fixed probability of 0.5 when an admin has a logon session on the attacker's host and can reach the target on 445 or 3389.
4. Path probability is the product of edge probabilities, so the most probable path is the shortest path under cost -ln p.
5. Risk of a path = probability x criticality (1-10) of the final host.
6. Patch plans are scored on a fixed set of baseline paths (top-k per crown jewel on the unpatched network).

## Known limitations

- The catalog is 10 entries, not the NVD. CVE IDs and vectors were entered by hand: verify against nvd.nist.gov and the KEV catalog before quoting them.
- The generated network is small (about 40 hosts) and my own design; results such as the graph-aware vs CVSS comparison hold by construction of the model. Real validation needs scan data (Nmap/OpenVAS from a lab) and stronger baselines (CVSS + KEV, EPSS, internet-facing first).
- Top-k paths are dominated by near-identical variants (web-01 or web-02, app-02 or app-04). Deduplicate by pattern, or reason over the graph directly, at scale.
- The attack graph has O(hosts^2) edges within permitted zones, so 10,000-node scale needs a zone-aware representation.
- Neo4j is not used yet: `infragraph.py` produces the schema, and a loader is the next step.

## Milestone 1 checklist

- [x] Schema and synthetic data generator
- [x] Attack-path discovery and scoring (works end to end)
- [x] Chokepoint analysis and patch prioritisation
- [x] Dashboard
- [ ] Ingest a real NVD/KEV feed
- [ ] Parse real Nmap XML from a lab network
- [ ] Neo4j loader
- [ ] Written proposal (use the department template)
- [ ] "AI Tools Used" paragraph in the proposal (required by the FYP policy)
