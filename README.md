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
engine either way. Every step of an attack path carries labelled evidence — what nmap
**observed**, what vulnerability enrichment **correlated**, and what the model
**inferred** — so an analyst can see which parts of a conclusion are measured and which
are assumed.

## Seeing it work

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data
```

```
== Remediation comparison: graph-aware vs CVSS-first vs EPSS-first (residual risk as % of baseline)
  n=1  graph-aware:   0.0% / broke   5   cvss-first: 100.0% / broke   0   epss-first: 100.0% / broke   0
  n=4  graph-aware:   0.0% / broke   5   cvss-first:  78.3% / broke   0   epss-first:  40.3% / broke   3
```

> **This input is a hand-built fixture**, written to mirror nmap 7.94 output. No host was
> scanned to produce it. It illustrates the mechanism; it is not evidence about a real
> network. The real lab scan is described under [Results](#results).

Severity-first spends four patches on CVEs rated 9.8 and 10.0 — Log4Shell, Zerologon,
BlueKeep — and breaks **zero** paths to the database. The graph-aware plan breaks all five
with one patch rated 8.8, because that 8.8 sits on the database itself and every path runs
through it. EPSS-first likewise leaves residual risk at 100 % for its first three patches.

That is the argument for the project, in one command.

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

python -m pytest -q                # expect: 146 passed
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
| [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md) | **Every experimental result**, with the command, parameters, feed snapshot and limitations. The source for any number quoted elsewhere |
| [`docs/DEMO.md`](docs/DEMO.md) | The defence demo: commands in order, what to say, fallback outputs |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What works, what the known gaps are, what comes next |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Branch model, project rules, invariants, how to make common changes |
| [`PROPOSAL.md`](PROPOSAL.md) | The academic project proposal |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed, when |

**Branches:** `main` is the live trunk and contains all work to date. `milestone-1` is a
frozen snapshot of the M1 submission — do not commit to it. The `feature/*` and
`defense-development` branches are earlier points on the same line of history and are
fully contained in `main`.

---

## What it does

```
   NVD API ──┐                        ┌── seeded synthetic network
  CISA KEV ──┼──► vulnerability facts │
 FIRST EPSS ─┘                        │
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
| `apg/feeds.py` | Loads cached NVD CVE records, the CISA KEV catalog and FIRST EPSS scores |
| `apg/catalog.py` | Joins them into the working catalog |
| `apg/model.py` | Host, Service, User, Vuln, Network |
| `apg/scoring.py` | Turns CVSS into attacker-success probability — the modelling layer |
| `apg/generator.py` | Seeded synthetic enterprise: DMZ, corporate, servers, data tier |
| `apg/nmap_import.py` | Parses real `nmap -oX` output into a Network, labelling observed and correlated evidence |
| `apg/infragraph.py` | Knowledge graph: Host, User, CVE, Subnet nodes |
| `apg/attackgraph.py` | Derives "foothold on A ⇒ foothold on B" from exploits and stolen credentials |
| `apg/paths.py` | The k most probable attack paths (Yen's algorithm on −ln p costs), with per-step provenance |
| `apg/chokepoints.py` | Which hosts carry the most risk |
| `apg/remediation.py` | Patch ranking, greedy plan, CVSS-first and EPSS-first baselines |
| `apg/neo4j_export.py` | Idempotent Cypher export |

---

## Data

70 CVEs pulled from the NVD API (snapshot 2026-10-20) and cross-referenced against the
CISA Known Exploited Vulnerabilities catalog (version 2026.10.21): **62 are
known-exploited**, 44 flagged for use in ransomware campaigns. Every one also has a FIRST
EPSS score (snapshot 2026-10-21). The 70th, CVE-2011-2523 (the vsftpd 2.3.4 backdoor),
was added for the real Metasploitable scan.

Our CVSS calculator recomputes the base score from each vector string and **agrees with
NVD's published score on 70 of 70** — ground truths produced by someone else, which is
what makes the scoring demonstrably correct rather than merely self-consistent. That is
`tests/test_cvss.py::test_matches_nvd_published_score`.

All three caches carry a `fetched_at` timestamp so any result can be traced to a specific
snapshot. `python -m scripts.fetch_feeds` refreshes them — **which changes EPSS-based
results**, since EPSS is updated daily. Do not refresh before reproducing the published
numbers.

---

## Results

Full details, commands and limitations for every result: [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md).

### Remediation across 100 generated networks

71 of 100 seeded networks had a path from the internet to a crown jewel. Mean residual
risk on the fixed baseline paths, as a percentage of the unpatched value:

| Patches | Graph-aware | CVSS-first | EPSS-first |
|---:|---:|---:|---:|
| 1 | **5.6 %** | 58.1 % | 97.7 % |
| 2 | **0.4 %** | 36.2 % | 82.4 % |
| 3 | **0.0 %** | 18.6 % | 60.4 % |
| 5 | **0.0 %** | 5.1 % | 31.4 % |

Graph-aware was at least as good as both baselines on **71 of 71** networks. Reproduce
with `python -m scripts.compare_seeds --seeds 100`. The numbers are identical every run,
and a test enforces that.

The planner optimises that metric directly, so it is *expected* to win on it. A second
check uses a metric it does not optimise: after each plan's patches, rebuild the attack
graph and search for paths again from scratch (`python -m scripts.reachability_check
--seeds 100`).

| After 5 patches | Graph-aware | CVSS-first | EPSS-first |
|---|---:|---:|---:|
| Networks with every crown jewel cut off | **71 / 71** | 55 / 71 | 19 / 71 |
| Re-discovered risk (% of unpatched) | **0.0 %** | 20.7 % | 67.8 % |

The same check shows a weakness of the fixed-path metric: after **one** graph-aware patch
it reports 5.6 % residual risk, but re-discovery finds 22.4 %, because routes outside the
top-50 retained paths were never counted.

### Scalability

Across 300 generated networks from 22 to 212 hosts, at three vulnerability densities,
the largest configuration (212 hosts, ~33,000 attack-graph edges) analysed end to end in a
mean of 643 ms on the team laptop (Intel Core i3-1315U). Path discovery is capped at 50
paths per crown jewel, so this shows practicality at the tested scale, not unbounded
enterprise scale.

### The real lab scan

`nmap -sV --script vulners` against a Metasploitable 2 VM on a host-only network
(evidence committed in `evidence/real_scan/`): 23 open ports, 417 CVE identifiers
reported. One — CVE-2011-2523 on vsftpd 2.3.4 — is in the catalog; 416 were dropped and
reported. The engine produced one single-hop path (p = 0.990, risk 8.91) with full
observed → correlated → inferred provenance, and one patch that breaks it.

This validates the pipeline end to end on genuine scanner output. It does **not** validate
multi-hop paths or the strategy comparison: with one host and one finding, every strategy
chooses the same patch. The exploit was not executed.

### How to read all of this honestly

These results come from our model and our generator. They show the implementation works
and that, *under its assumptions*, reachability-aware ordering cuts attack paths that
score-only ordering misses. They are not evidence of real-world breach reduction, and
EPSS-first doing badly says nothing about EPSS as a predictor of exploitation — EPSS
answers a different question. What transfers to real estates is the *mechanism*: a
high-scoring CVE that lies on no path to anything valuable is not the best first patch.

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
6. Patch plans are scored on a **fixed** baseline path set (top 50 per crown jewel), so
   competing plans are compared on identical ground. Routes outside that set are not counted.
7. From a single scan vantage point, reachability between other zones is **assumed open**
   on every observed port — pessimistic by design, because over-reporting paths is the safe
   direction for a security tool.
8. EPSS is used **only** as a remediation baseline. It does not feed the exploit
   probability in (1), which still uses the CVSS sub-score and the KEV multiplier.

---

## Status

Working: CVSS engine, real vulnerability data (NVD, KEV, EPSS), synthetic generator,
attack graph, path finding with evidence provenance, chokepoints, graph-aware patch
planning against CVSS-first and EPSS-first baselines, nmap ingestion (exercised on a real
lab scan), Neo4j export, dashboard, scalability experiment, 146 tests.

Main known gaps: the real-scan validation is a single host; the local catalog covers only
70 CVEs, so most CVEs a real scan reports are dropped; identity data is synthetic; and the
Neo4j export has not been loaded into a live instance.

Full status and known limitations: [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Scanning

> **Only scan machines you own or have written authorisation to test.** A virtual machine
> on a host-only adapter is the right target. Port scanning infrastructure you do not own
> is unlawful in most jurisdictions, including under Pakistan's Prevention of Electronic
> Crimes Act 2016. Never scan a university, employer, or public network.
