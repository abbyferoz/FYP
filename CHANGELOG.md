# Changelog

---

## Pre-defence consolidation — 2026-10-27 (`main`)

Developed on `feature/provenance` → `feature/epss-comparison` →
`feature/scalability-experiments`, one linear line of history, then fast-forwarded into
`main`. Engine results are unchanged from commit `c171606`.

### Real lab scan (2026-10-20/21)
- Scanned a Metasploitable 2 VM on a host-only network with `nmap -sV --script vulners`:
  23 open ports, 417 CVE identifiers reported. None of the 417 were in the 69-CVE catalog,
  so the first import produced no attack edge — a catalog-coverage limitation, not a
  parser failure.
- Added CVE-2011-2523 (vsftpd 2.3.4 backdoor) to `data/cve_seeds.txt`; catalog now 70 CVEs.
  The import then yields one host, one edge, one path (p = 0.990, risk 8.91); 416 CVEs are
  still dropped and reported.
- The scan XML and the importer's output are committed in `evidence/real_scan/`.

### Evidence provenance
- `Service` gains `evidence_status` and `evidence`. Scan-derived services are labelled
  `[OBSERVED]` (open port, identified product) and `[CORRELATED]` (CVE from vulnerability
  enrichment); generated services carry no such labels.
- Exploit options in the attack graph add `[INFERRED]` lines (foothold, computed
  probability), and each `AttackPath` carries per-hop provenance. `import_scan` prints it.

### EPSS
- `scripts/fetch_feeds.py` fetches FIRST EPSS scores into `data/epss.json` (70 scores,
  snapshot 2026-10-21). KEV cache refreshed to catalog 2026.10.21 (1,754 entries).
- `Vuln` gains `epss` and `epss_percentile`.
- `remediation.epss_plan` — highest-EPSS-first baseline. EPSS is **not** used in the
  attack-graph edge probability, which still uses the CVSS sub-score and the KEV
  multiplier.

### Experiments
- `compare_seeds` now compares graph-aware, CVSS-first and EPSS-first. 100 seeds, 71
  usable: graph-aware ≤ both baselines on 71/71.
- `scripts/scale_experiment.py` — 22–212 hosts × three vulnerability densities.
- `scripts/reachability_check.py` — rebuilds the attack graph after each plan and
  searches again, a metric the planner does not optimise. After 5 patches every crown
  jewel is cut off in 71/71 networks (graph-aware), 55/71 (CVSS-first), 19/71 (EPSS-first).
- `docs/EXPERIMENTS.md` — the single record of every result, with commands, parameters,
  feed snapshots and limitations.

### Tests
129 → 146. `tests/test_epss_provenance.py` adds direct tests for EPSS loading and
ordering, evidence labels on services and path steps, the real scan, the reachability
check and the seed-7 demo. (The 129th test was the NVD cross-check for CVE-2011-2523.)

### Documentation corrections
- `PROPOSAL.md` §1 and §6.4, `README.md`, `docs/ARCHITECTURE.md` and `docs/RUNNING.md`
  described the `tests/fixtures/lab_scan.xml` result as "real scan data". That file is a
  hand-built fixture; no host was scanned to produce it. Corrected throughout, and the
  real scan is now reported separately.
- Figures updated across all documents (70 CVEs, 146 tests, three-way comparison). The
  proposal keeps its M1 figures, with a dated status note.

---

## Documentation restructure — 2026-09-26

- `docs/RUNNING.md` — complete install/run/test guide for macOS, Linux and Windows, with
  the expected output of every command and a troubleshooting section.
- `docs/ARCHITECTURE.md` — what the system does, how data flows through it, the ideas it
  rests on, and what it deliberately does not know.
- `docs/ROADMAP.md` — current status, known gaps in priority order, and planned work.
- `CONTRIBUTING.md` — branch model, project rules, invariants, common changes.
- `README.md` rewritten as a front door.

---

## Milestone 1 — 2026-09-23 (tagged as branch `milestone-1`)

### Real vulnerability data
Replaced the hand-entered CVE catalog with real data from the NVD API, cross-referenced
against the CISA Known Exploited Vulnerabilities catalog.

- `apg/feeds.py` — reads the cached NVD and KEV data. Pure and deterministic; no network
  I/O, so tests run offline and demos work without internet.
- `scripts/fetch_feeds.py` — downloads both feeds. Standard library only. Rate-limit aware
  (NVD allows 5 requests per 30 s anonymously), and merges into the existing cache so a
  re-run only fetches what is missing.
- 69 CVEs covering every host role; 62 are in CISA KEV, 44 flagged for ransomware use.
- Service templates now carry several candidate CVEs each, so two hosts of the same role
  get different weaknesses — which is what makes chokepoint analysis non-trivial.
- `Vuln` extended with provenance: NVD's published base score, publication date, KEV date,
  ransomware flag, CWEs.

**Found a real error in the process.** The hand-typed EternalBlue vector was
`AV:N/AC:H/PR:N` (8.1); NVD scores it `AV:N/AC:L/PR:L` (8.8). The old test did not catch
it because it compared a hand-typed vector against a hand-typed expected score — both
wrong in the same direction, so they agreed. `tests/test_cvss.py` now cross-checks every
cached CVE against NVD's published score: **69 of 69 agree**.

### Real scan ingestion
- `apg/nmap_import.py` — parses `nmap -oX` output and builds a `Network`. Deliberately
  split into a pure parsing stage (only what nmap literally reported) and an explicit
  modelling stage (every inference documented, and returned to the caller as warnings
  rather than hidden).
- `merge_scans()` — combines scans from several vantage points, replacing assumed
  zone-to-zone reachability with measured reachability.
- `scripts/import_scan.py` — runs the full analysis against a scan file.
- `tests/fixtures/` — three nmap XML fixtures covering the normal case, the no-CVE case,
  and a second vantage point. Hand-built to mirror nmap 7.94 output; no host was scanned
  to produce them.

### Neo4j export
- `apg/neo4j_export.py` — emits idempotent `MERGE`-based Cypher plus example queries.
  Uniqueness constraints are written first so loading does not degrade to full label
  scans.
- `scripts/export_graph.py`.

### Fixes
- **Reproducibility.** `derive_attack_graph` iterated a Python `set` of zone names, so
  edge insertion order depended on `PYTHONHASHSEED`. networkx breaks ties between
  equal-cost paths in graph order, so the same seed produced different top-k paths between
  runs and the 100-network figures moved by 2–3 percentage points each time. All
  order-sensitive iteration is now sorted, and
  `test_results_do_not_depend_on_pythonhashseed` runs the engine in subprocesses under
  different hash seeds to prevent regression.
- **`merge_scans` aliasing.** It reused the caller's `ScannedHost` objects, so merging one
  scan's services mutated the other's and every vantage point appeared to have observed
  every port. Reachability is now measured before merging, into copies.
- **Role inference order.** `app` was ranked above `web`, misclassifying any web server
  that also ran an application container on 8080.
- `derive_attack_graph` now raises a descriptive error for a CVE missing from the catalog
  instead of a bare `KeyError` three frames deep.

### Dashboard
- Shows data provenance as a banner — green for real feed data, orange when the catalog
  has fallen back to the hand-entered set, so illustrative numbers can never be mistaken
  for real ones.
- Accepts an uploaded nmap XML file as an alternative to the synthetic generator.
- Surfaces import warnings.
- New "Vulnerability data" tab cross-checking our computed CVSS scores against NVD's.

### Tests
16 → 128.

### Documentation
- `PROPOSAL.md` — the academic proposal.
- `docs/WALKTHROUGH.md` — module-by-module explanation with likely examiner questions.

---

## Initial demonstrator — 2026-09-22

First working version:

- `apg/cvss.py` — CVSS v3.1 base-score calculator from vector strings.
- `apg/model.py` — Host, Service, User, Vuln, Network.
- `apg/scoring.py` — CVSS to attacker-success probability.
- `apg/generator.py` — seeded synthetic enterprise network.
- `apg/infragraph.py` — knowledge graph.
- `apg/attackgraph.py` — derived attack graph with exploit and credential-reuse edges.
- `apg/paths.py` — k most probable attack paths via Yen's algorithm.
- `apg/chokepoints.py` — risk-weighted path participation and betweenness centrality.
- `apg/remediation.py` — patch ranking and the severity-first baseline comparison.
- `app.py` — Streamlit + PyVis dashboard.
- `scripts/run_demo.py`, `scripts/compare_seeds.py`.
- 16 tests.

The modelling assumptions documented in `docs/ARCHITECTURE.md` were established here:
exploit probability from the CVSS Exploitability sub-score, the integrity-impact foothold
rule, credential reuse, and the fixed-baseline evaluation design.
