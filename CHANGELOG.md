# Changelog

---

## Unreleased (`main`)

### Documentation
- `docs/RUNNING.md` — complete install/run/test guide for macOS, Linux and Windows, with
  the expected output of every command and a troubleshooting section.
- `docs/ARCHITECTURE.md` — what the system does, how data flows through it, the five ideas
  it rests on, and what it deliberately does not know.
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
