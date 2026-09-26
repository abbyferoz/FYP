# Enterprise Cyber Attack-Path Intelligence

Final Year Project — Muhammad Rayyan Khan (28410), Abdullah Feroz (29219)
Advisor: Tasbiha Fatima · Department of Computer Science, IBA Karachi
CSE 493/494 · Software track

---

## What this is

Security scanners find far more vulnerabilities than any team can fix. The usual response
is to sort by CVSS severity and work down the list — which is wrong in a specific way:

> **CVSS scores a vulnerability in isolation. An attacker exploits a chain.**

A 10.0-rated flaw on a host nothing can reach contributes nothing to real risk. An
8.8-rated flaw on the one machine every route to your customer database passes through is
the whole breach.

This tool models a network as a graph, finds the attack paths from the internet to
business-critical assets, scores them by probability and impact, and works out **which
specific patches break the most paths** — then measures that against severity-first
patching to show the difference.

It runs on a generated synthetic network *or* on real `nmap` scan output, with the same
engine either way.

## Seeing it work

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data
```

```
== Graph-aware plan vs highest-CVSS-first (residual risk as % of baseline)
  n=1  graph-aware:   0.0% / broke   5   cvss-first: 100.0% / broke   0
  n=4  graph-aware:   0.0% / broke   5   cvss-first:  78.3% / broke   0
```

Severity-first spends four patches on CVEs rated 9.8 and 10.0 — Log4Shell, Zerologon,
BlueKeep — and breaks **zero** paths to the database. The graph-aware plan breaks all five
with one patch rated 8.8, because that 8.8 sits on the database itself and every path runs
through it.

That is the entire argument for the project, in one command.

---

## Quick start

Needs Python 3.10+. No internet, no API keys, no database — the vulnerability data is
committed to the repo.

```bash
git clone https://github.com/abbyferoz/FYP.git
cd FYP
python3 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python -m pytest -q                # expect: 128 passed
python -m scripts.run_demo         # the engine end to end
streamlit run app.py               # interactive dashboard
```

**Full instructions for macOS, Linux and Windows — with the output each command should
produce — are in [`docs/RUNNING.md`](docs/RUNNING.md).** Start there if anything is
unclear or does not work.

---

## Documentation

| | |
|---|---|
| [`docs/RUNNING.md`](docs/RUNNING.md) | **How to install, run and test everything, on any machine**, with expected output and troubleshooting |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | What the system does, how data flows through it, and the five ideas it rests on |
| [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) | Module-by-module deep dive, with likely examiner questions |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What works, what the known gaps are, what comes next |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Branch model, project rules, invariants, how to make common changes |
| [`PROPOSAL.md`](PROPOSAL.md) | The academic project proposal |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed, when |

**Branches:** `main` is the live trunk. `milestone-1` is a frozen snapshot of the M1
submission — do not commit to it.

---

## What it does

```
   NVD API ──┐                        ┌── seeded synthetic network
             ├──► vulnerability facts │
  CISA KEV ──┘                        │
                                      ▼
  nmap -oX ──► network facts ──►  data model  ──┬──► knowledge graph ──► Neo4j export
                                                │    (what is out there)
                                                │
                                                └──► attack graph
                                                     (what an attacker can do)
                                                          │
                                       ┌──────────────────┼──────────────────┐
                                       ▼                  ▼                  ▼
                                  attack paths      chokepoints        patch plan
```

| Module | Job |
|---|---|
| `apg/cvss.py` | CVSS v3.1 calculator — computed from vector strings, validated against NVD |
| `apg/feeds.py` | Loads cached NVD CVE records and the CISA KEV catalog |
| `apg/catalog.py` | Joins them into the working catalog |
| `apg/model.py` | Host, Service, User, Vuln, Network |
| `apg/scoring.py` | Turns CVSS into attacker-success probability — the modelling layer |
| `apg/generator.py` | Seeded synthetic enterprise: DMZ, corporate, servers, data tier |
| `apg/nmap_import.py` | Parses real `nmap -oX` output into a Network |
| `apg/infragraph.py` | Knowledge graph: Host, User, CVE, Subnet nodes |
| `apg/attackgraph.py` | Derives "foothold on A ⇒ foothold on B" from exploits and stolen credentials |
| `apg/paths.py` | The k most probable attack paths (Yen's algorithm on −ln p costs) |
| `apg/chokepoints.py` | Which hosts carry the most risk |
| `apg/remediation.py` | Patch ranking, greedy plan, severity-first baseline |
| `apg/neo4j_export.py` | Idempotent Cypher export |

---

## Data

69 CVEs pulled from the NVD API and cross-referenced against the CISA Known Exploited
Vulnerabilities catalog: **62 are known-exploited**, 44 flagged for use in ransomware
campaigns.

Our CVSS calculator recomputes the base score from each vector string and **agrees with
NVD's published score on 69 of 69** — 69 ground truths produced by someone else, which is
what makes the scoring demonstrably correct rather than merely self-consistent. That is
`tests/test_cvss.py::test_matches_nvd_published_score`.

Both caches carry a `fetched_at` timestamp so any result can be traced to a specific
snapshot. `python -m scripts.fetch_feeds` refreshes them.

---

## Results

Graph-aware patching vs highest-CVSS-first across 100 generated networks (71 had a path
from the internet to a crown jewel; mean residual risk as a percentage of the unpatched
baseline):

| Patches | Graph-aware | Highest-CVSS first |
|---:|---:|---:|
| 1 | **5.6 %** | 58.1 % |
| 2 | **0.4 %** | 36.2 % |
| 3 | **0.0 %** | 18.6 % |
| 5 | **0.0 %** | 5.1 % |

Graph-aware was at least as good as severity-first on **71 of 71** networks. Reproduce
with `python -m scripts.compare_seeds --seeds 100` — the numbers are identical every run,
and a test enforces that.

### How to read this honestly

The graph-aware planner **directly optimises the same metric this table reports**, on the
same model, so it is *expected* to win. The margin does not transfer to real networks.

What the table legitimately shows is that the implementation works. What transfers is the
*mechanism* — a high-severity CVE lying on no path to anything valuable is worthless to
patch first — and that is true of real estates regardless of our model. Establishing a
real effect size needs scan data at scale and stronger baselines (CVSS+KEV, EPSS,
internet-facing-first). See [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Modelling assumptions

Every result rests on these. Full reasoning in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

1. Exploit probability = CVSS Exploitability sub-score ÷ 3.9, ×1.25 if in CISA KEV,
   capped at 0.99.
2. A vulnerability gives a foothold only if its CVSS **integrity impact is not None** — so
   Heartbleed creates no attack-graph edge despite scoring 7.5.
3. Credential reuse succeeds with probability 0.5 when an admin has a logon session on the
   attacker's host and can reach the target on 445 or 3389.
4. Path probability is the product of edge probabilities, treated as independent — so the
   most probable path is the shortest path under cost −ln p.
5. Path risk = probability × criticality (1–10) of the final host.
6. Patch plans are scored on a **fixed** baseline path set, so competing plans are compared
   on identical ground.
7. From a single scan vantage point, reachability between other zones is **assumed open**
   on every observed port — pessimistic by design, because over-reporting paths is the safe
   direction for a security tool.

---

## Status

Working: CVSS engine, real vulnerability data, synthetic generator, attack graph, path
finding, chokepoints, patch prioritisation, nmap ingestion, Neo4j export, dashboard, 128
tests.

Main known gap: **no real scan has been run yet.** The parser is complete and tested, but
the fixtures in `tests/fixtures/` were hand-built to mirror real nmap output rather than
captured from a live host. [`docs/RUNNING.md`](docs/RUNNING.md) §6 has the lab setup.

Full status and known limitations: [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Scanning

> **Only scan machines you own or have written authorisation to test.** A virtual machine
> on a host-only adapter is the right target. Port scanning infrastructure you do not own
> is unlawful in most jurisdictions, including under Pakistan's Prevention of Electronic
> Crimes Act 2016. Never scan a university, employer, or public network.
