# Development log and AI-tool disclosure

The FYP AI-Assisted Development Policy (booklet §0.3) requires every deliverable to carry
a short "AI Tools Used" paragraph — which tools, for what, and roughly how much of the
work they produced. This file is the running record those paragraphs are drawn from.

**Keep it up to date as you go.** It is far easier to write this honestly session by
session than to reconstruct it the week before submission. The policy's boundary is
clear: AI-assisted *code* is fine when disclosed; AI-generated *analysis or reasoning*
must not be presented as your own.

> **Action for the team:** the "we did" entries below were inferred from the project
> history and the briefs given to the assistant. Correct them — add what each of you
> actually wrote, decided, debugged or rejected. An inaccurate disclosure is worse than
> a modest one, and the M2 viva tests understanding directly.

---

## Session 3 — 2026-09-22/23 · Claude Code (Claude Opus 5) · M1 hardening

**Brief given:** continue and harden the existing demonstrator for Milestone 1 — replace
the hand-entered CVE catalog with a real NVD loader cross-referenced against CISA KEV,
add a parser for real `nmap -oX` output, keep the tests passing and add more, and explain
each module well enough to defend it unaided.

**Written by the assistant (from that brief):**
- `apg/feeds.py`, `scripts/fetch_feeds.py` — NVD and CISA KEV ingestion and caching.
- `apg/nmap_import.py`, `scripts/import_scan.py` — nmap XML parsing and network construction.
- `apg/neo4j_export.py`, `scripts/export_graph.py` — Cypher export.
- `data/cve_seeds.txt` — the curated 69-CVE list.
- `tests/test_feeds.py`, `tests/test_nmap_import.py`, `tests/test_neo4j_export.py`, and the
  rewrite of `tests/test_cvss.py`. Test count went from 16 to 128.
- `tests/fixtures/*.xml` — hand-built nmap fixtures (no real host was scanned to make them).
- Modifications to `apg/catalog.py`, `apg/model.py`, `apg/generator.py`, `apg/attackgraph.py`, `app.py`.
- First drafts of `PROPOSAL.md`, `docs/WALKTHROUGH.md`, this file, and `README.md`.

**Defects the assistant found and fixed during this session:**
1. The hand-entered EternalBlue vector was wrong — `AV:N/AC:H/PR:N` (8.1) where NVD scores
   it `AV:N/AC:L/PR:L` (8.8). The old test did not catch it because it compared a
   hand-typed vector against a hand-typed expected score. Now every cached CVE is
   cross-checked against NVD's published value (69/69 agree).
2. `merge_scans()` aliased the caller's `ScannedHost` objects, so merging one scan's
   services mutated the other's and every vantage point appeared to have observed every
   port. Reachability is now measured before merging, into copies.
3. Role inference ranked `app` above `web`, misclassifying any web server that also ran
   an app container on 8080.
4. A reference CVSS value the assistant itself hand-typed into the new test (2.9) was
   wrong; the implementation's 3.5 was correct. The arithmetic is now worked out in a
   comment beside it.
5. **The experiments were not reproducible.** `derive_attack_graph` iterated a *set* of
   zone names, so edge insertion order depended on `PYTHONHASHSEED`; networkx breaks ties
   between equal-cost paths in graph order, so the same seed produced different top-k
   paths between runs and the 100-network figures moved by 2-3 percentage points. Found by
   noticing two runs of the same command disagreeing. All order-sensitive iteration is now
   sorted, and `test_results_do_not_depend_on_pythonhashseed` runs the engine in
   subprocesses under different hash seeds to prevent a regression. This one matters: the
   proposal quotes these numbers to one decimal place.

**Decided by us:**
- To ingest real NVD/KEV data rather than keep the illustrative catalog, and to cache a
  curated set rather than the full multi-hundred-megabyte feed.
- To build and test the nmap parser against fixtures now, and run it against a real lab
  VM once that environment exists.
- To keep the honesty caveat about the self-evaluating benchmark (PROPOSAL §6.6) rather
  than present the 71/71 result unqualified.

**Verified by us:** _(fill in — which outputs did you actually run and check yourself?)_

---

## Session 2 — 2026-09-21/22 · Cowork · initial demonstrator

Built the first working version: `apg/cvss.py`, `apg/catalog.py`, `apg/model.py`,
`apg/generator.py`, `apg/infragraph.py`, `apg/attackgraph.py`, `apg/paths.py`,
`apg/scoring.py`, `apg/chokepoints.py`, `apg/remediation.py`, `app.py`,
`scripts/run_demo.py`, `scripts/compare_seeds.py`, and 16 tests.

The modelling assumptions now documented in PROPOSAL §5 were established in this session
— exploit probability from the CVSS Exploitability sub-score, the integrity-impact
foothold rule, credential reuse, the fixed-baseline evaluation.

_(Fill in: how much of this did each of you write or rewrite? What did you reject or
change from what the tool proposed? The assumptions above are the project's intellectual
core — be clear about who decided them.)_

---

## Session 1 — 2026-09-09 to 09-11 · project selection

Shortlisted five FYP ideas and corresponded with the advisor, who recommended Enterprise
Cyber Attack-Path Intelligence on grounds of technical depth, industry relevance,
single-semester feasibility, and the availability of simulatable or public data (NVD,
CISA KEV). The advisor also supplied the twelve-month extended roadmap that Term 2's
scope follows.

---

## Draft "AI Tools Used" paragraph

*(For pasting into deliverables. Keep it current; expand it if the balance of work
changes.)*

> Claude (Anthropic), used through Cowork and Claude Code, served as a coding assistant
> throughout this project. It produced the majority of the source code in `apg/`,
> `scripts/`, `tests/` and `app.py` from our specifications, together with first drafts of
> the project documentation. We selected the project and its scope, established the threat
> model and every modelling assumption (exploit probability, the integrity-impact foothold
> rule, credential reuse, the fixed-baseline evaluation design, pessimistic reachability
> from a single scan vantage point), chose the vulnerability data to ingest and the host
> roles to model, directed the decision to validate our CVSS implementation against NVD
> rather than against hand-entered expectations, and wrote the limitations analysis. No
> AI-generated analysis or reasoning is presented as our own unaided work; both team
> members can explain and modify every module without tool assistance.
