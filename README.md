# Enterprise Cyber Attack-Path Intelligence

**FYP Milestone 1 demonstrator** — Muhammad Rayyan Khan (28410), Abdullah Feroz (29219)
Advisor: Tasbiha Fatima · Department of Computer Science, IBA Karachi

Models an enterprise network as a graph, finds and scores the attack paths from the
internet to crown-jewel assets, identifies chokepoints, and recommends which patches
remove the most risk — measured against a highest-CVSS-first baseline.

Runs on a seeded synthetic network **or on real `nmap -oX` scan output**, unchanged.

**Branches:** `main` is the live trunk. `milestone-1` is a frozen snapshot of the M1
submission — do not commit to it.

| Document | What it is |
|---|---|
| [`TEAMMATE.md`](TEAMMATE.md) | **Start here if you are new to the repo** — setup, what works, what still needs doing |
| [`PROPOSAL.md`](PROPOSAL.md) | The M1 written proposal: problem, related work, architecture, method, results, plan |
| [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) | Module-by-module explanation, written for the individual viva |
| [`CHANGELOG.md`](CHANGELOG.md) | Development log and AI-tool disclosure (required by FYP policy §0.3) |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                            # 128 tests
python -m scripts.run_demo                     # command-line walkthrough
python -m scripts.compare_seeds --seeds 100    # graph-aware vs CVSS-first, many networks
streamlit run app.py                           # dashboard
```

The vulnerability data is committed under `data/`, so everything above works offline.
To refresh it from the live feeds (about 8 minutes at NVD's anonymous rate limit):

```bash
python -m scripts.fetch_feeds
```

## Running it on a real scan

```bash
nmap -sV --script vulners -oX scans/lab.xml 192.168.56.0/24

python -m scripts.import_scan scans/lab.xml \
    --zone 192.168.56.0/24=dmz \
    --zone 192.168.57.0/24=servers \
    --zone 192.168.58.0/24=data
```

> **Only scan machines you own or have written authorisation to test.** A Metasploitable
> or Windows VM on a host-only adapter is the right target. Port scanning third-party
> infrastructure is unlawful in most jurisdictions, including under Pakistan's Prevention
> of Electronic Crimes Act 2016.

Try it without a lab using the committed fixture:

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data
```

Scanning from more than one vantage point turns assumed reachability into measured
reachability — each scan contributes one row of the firewall matrix:

```bash
python -m scripts.import_scan scans/outside.xml=internet scans/dmz.xml=dmz --zone ...
```

## How it works

| Module | Job |
|---|---|
| `apg/cvss.py` | CVSS v3.1 calculator — scores computed from vector strings, validated against NVD |
| `apg/feeds.py` | Loads the cached NVD CVE records and the CISA KEV catalog |
| `apg/catalog.py` | Joins them into the working catalog; per-role service templates for the generator |
| `apg/model.py` | Data model: Host, Service, User, Vuln, Network |
| `apg/generator.py` | Seeded synthetic network: internet, DMZ, corporate, servers, data zone |
| `apg/nmap_import.py` | Parses real `nmap -oX` output into a Network |
| `apg/infragraph.py` | Knowledge graph (Host, User, CVE, Subnet; HAS_VULN, CAN_ACCESS, EXPOSED_TO) |
| `apg/attackgraph.py` | Derives "foothold on A ⇒ foothold on B" edges from exploits and credential reuse |
| `apg/paths.py` | Top-k most probable attack paths (Yen's algorithm on −ln p costs) and risk scoring |
| `apg/chokepoints.py` | Risk-weighted path participation and betweenness centrality |
| `apg/remediation.py` | Single-patch ranking, greedy plan, highest-CVSS-first baseline |
| `apg/neo4j_export.py` | Idempotent Cypher export of the knowledge graph |

## Data

69 CVEs from the NVD API, cross-referenced against the CISA KEV catalog: 62 are
known-exploited and 44 are flagged for use in ransomware campaigns. Our CVSS calculator
recomputes the base score from each vector string and **agrees with NVD's published score
on 69 of 69**, which is what `tests/test_cvss.py` checks.

Both caches carry a `fetched_at` timestamp, so the report can state exactly which
snapshot produced its numbers. Edit `data/cve_seeds.txt` and re-run `scripts.fetch_feeds`
to add more.

## Results

**Graph-aware patching vs highest-CVSS-first, across 100 seeded networks** (71 had a path
from the internet to a crown jewel; mean residual risk as a percentage of the unpatched
baseline):

| Patches | Graph-aware | Highest-CVSS first |
|---:|---:|---:|
| 1 | **5.6 %** | 58.1 % |
| 2 | **0.4 %** | 36.2 % |
| 3 | **0.0 %** | 18.6 % |
| 5 | **0.0 %** | 5.1 % |

Graph-aware was at least as good as the baseline on 71 of 71 networks.

**On real scan data**, the mechanism is visible in one screen: the severity-first plan
spends four patches on 9.8- and 10.0-rated CVEs and breaks *no* path to the database,
because the database's own 8.8-rated flaw is directly reachable. The graph-aware plan
breaks all five paths with that one patch.

**Read this honestly.** The greedy planner directly optimises the same residual-risk
metric the comparison reports, on the same model, so it is *expected* to win. The
defensible claim is narrower: reachability-aware ordering dominates severity-only
ordering on this model, and the mechanism by which it does so occurs in real networks.
Establishing a real effect size needs scan data at scale and stronger baselines
(CVSS+KEV, EPSS, internet-facing-first) — that is M4's job. See PROPOSAL §6.6.

## Modelling assumptions

These drive every result. Full justification in PROPOSAL §5; summary:

1. Exploit probability = CVSS Exploitability sub-score ÷ 3.9, ×1.25 if in CISA KEV,
   capped at 0.99.
2. A vulnerability gives a foothold only if its CVSS integrity impact is not `None`
   — so Heartbleed alone does not create an edge, despite scoring 7.5.
3. Credential reuse succeeds with fixed probability 0.5 when an admin has a logon session
   on the attacker's host and can reach the target on 445 or 3389.
4. Path probability is the product of edge probabilities (treated as independent), so the
   most probable path is the shortest path under cost −ln p.
5. Risk of a path = probability × criticality (1–10) of the final host.
6. Patch plans are scored on a **fixed** baseline path set, so competing plans are
   compared on identical ground.
7. From a single scan vantage point, reachability between other zone pairs is **assumed
   open** on every observed port — pessimistic by design, because over-reporting paths is
   the safe direction for a security tool.

## Known limitations

- **Self-evaluating benchmark.** See the honesty note above and PROPOSAL §6.6.
- **The credential-reuse probability (0.5) and KEV multiplier (1.25) are judgement calls**,
  not measured quantities. EPSS and BloodHound-style identity collection are the
  principled replacements.
- **Scale.** The attack graph has O(hosts²) edges within permitted zone pairs. 42 hosts
  gives 932 edges in ~2 ms; the outline's 10,000-node target needs zone-level aggregation.
- **Top-k paths are dominated by near-identical variants** (`web-01` vs `web-02`).
  Deduplication by path *pattern* is pending.
- **Independence assumption.** Two steps exploiting the same CVE are correlated, so path
  probability is understated.
- **NVD vectors sometimes understate impact.** CVE-2017-10271 is scored `C:N/I:N/A:H`, so
  our foothold rule excludes a CVE that is in practice remote code execution.
- **Neo4j is exported, not loaded.** `neo4j_export.py` emits the Cypher; running it
  against a live instance is M2.
- **Identity data is synthetic.** nmap cannot see logon sessions or admin rights, so a
  scan-derived graph has exploit edges only.

## Milestone 1 checklist

- [x] Schema and synthetic data generator
- [x] Attack-path discovery and scoring, end to end
- [x] Chokepoint analysis and patch prioritisation
- [x] Dashboard
- [x] Real NVD feed + CISA KEV cross-reference
- [x] Real `nmap -oX` parsing
- [x] Neo4j Cypher export
- [x] Test suite (128 tests)
- [x] Written proposal — `PROPOSAL.md`
- [x] "AI Tools Used" disclosure — `CHANGELOG.md`, PROPOSAL §10
- [ ] Reformat the proposal onto the department template
- [ ] Run a real scan against a lab VM you own
- [ ] Confirm M1 date, software track, and AI-tool permission with the advisor
- [ ] Both team members rehearse `docs/WALKTHROUGH.md` for the individual viva
