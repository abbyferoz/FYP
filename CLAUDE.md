# CLAUDE.md

Context for future Claude Code sessions in this repository.

## What this is

An IBA final-year project (CSE 493/494, software track): **Enterprise Cyber Attack-Path
Intelligence**. It models an enterprise network as a graph, finds attack paths from the
internet to crown-jewel assets, scores them, finds chokepoints, and ranks patches against
a highest-CVSS-first baseline.

Two students, graded individually at a viva where a jury picks a component and asks them
to explain or modify it **without tool assistance**. That constraint shapes everything
below.

## Working rules

- **Explain, don't just implement.** Every non-obvious design decision belongs in a
  comment or docstring in the code itself, phrased so a student can defend it to a jury.
  Density of explanation matters more here than terseness.
- **Never invent security data.** CVSS vectors, base scores and KEV status come from the
  feeds in `data/`. If a CVE is not there, add it to `data/cve_seeds.txt` and re-run
  `python -m scripts.fetch_feeds` — do not hand-type a vector. A hand-typed vector was
  wrong once already (EternalBlue, 8.1 vs NVD's 8.8) and the hand-written test agreed
  with it.
- **Separate facts from modelling.** Facts come from feeds and scans. Modelling choices
  (probabilities, thresholds, inference rules) must be named, documented, and stated as
  assumptions — `apg/catalog.py` and `apg/nmap_import.py` both draw this line explicitly.
- **Keep assumptions visible to the user.** `network_from_scan()` returns warnings rather
  than hiding them; the dashboard shows a banner when the catalog falls back. Do not
  make anything fail silently in a direction that flatters the results.
- **Be pessimistic about reachability.** Over-reporting attack paths is the safe
  direction for a security tool; under-reporting hides real risk.
- **Protect the honesty caveat.** The greedy planner optimises the same metric the
  headline comparison reports (PROPOSAL §6.6). Do not remove or soften that note, and do
  not let a change quietly make the baseline weaker.
- **Update `CHANGELOG.md`** after substantive work. The FYP policy requires a disclosure
  paragraph in every deliverable and it is much easier to keep current than reconstruct.
- **Run the tests after every change**: `python -m pytest -q`. 128 currently pass.

## Commands

```bash
source .venv/bin/activate
python -m pytest -q                            # 128 tests
python -m scripts.run_demo                     # CLI walkthrough
python -m scripts.compare_seeds --seeds 100    # graph-aware vs CVSS-first
python -m scripts.import_scan FILE.xml --zone CIDR=NAME    # analyse a real nmap scan
python -m scripts.export_graph --out graph.cypher          # Neo4j export
python -m scripts.fetch_feeds                  # refresh NVD + KEV caches (~8 min)
streamlit run app.py                           # dashboard
```

## Layout

```
apg/          engine (see docs/WALKTHROUGH.md for a module-by-module explanation)
  cvss.py     CVSS v3.1 calculator          feeds.py     NVD + CISA KEV loading
  model.py    dataclasses                   catalog.py   joined catalog + service templates
  generator.py  synthetic networks          nmap_import.py  real scan -> Network
  infragraph.py knowledge graph             attackgraph.py  derived attack graph
  paths.py    Yen's k-best paths            chokepoints.py  centrality
  remediation.py  patch ranking             neo4j_export.py Cypher output
  scoring.py  CVSS -> probability (the modelling layer)
scripts/      CLI entry points          tests/     128 tests + nmap fixtures
data/         cached NVD + KEV feeds, committed on purpose so demos work offline
app.py        Streamlit + PyVis dashboard
```

Dependency order — and the order to read it in — is: `cvss` → `feeds` → `model` →
`catalog` → {`generator`, `nmap_import`} → {`infragraph`, `attackgraph`} → `paths` →
{`chokepoints`, `remediation`} → `app`.

## Key invariants

- `apg/cvss.py` must reproduce NVD's published base score for every cached CVE.
  `test_matches_nvd_published_score` enforces this; it is the project's strongest test.
- `derive_attack_graph` raises a descriptive `KeyError` for a CVE not in the catalog
  rather than silently skipping it.
- Patch plans are always evaluated against a **fixed** baseline path set computed on the
  unpatched network. Changing this invalidates every comparison in the proposal.
- `Network.allows()` is the single reachability predicate. Route all segmentation
  questions through it.
- Parsing (`parse_nmap_xml`) stays pure; all inference lives in `network_from_scan`.

## Scanning rules

Only ever scan machines the team owns, on a host-only adapter. Never suggest scanning
university, employer or third-party infrastructure — Pakistan's PECA 2016 applies.

## Milestone context

- **M1** (~week 6): working demonstrator + written proposal, jury defence. *Code complete;
  see the checklist at the end of `README.md` for what the team still owes.*
- **M2** (~week 15): full system end-to-end plus an individual viva where each student
  modifies a component unaided.
- **M3**: external Open House. **M4**: real-conditions validation. **M5**: final defence.

Term 2 scope (from the advisor's roadmap): predictive GNN for unmapped lateral movement,
min-cut / ILP minimum patch set, LLM remediation-script agent, live scanner ingestion.
