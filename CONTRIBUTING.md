# Working on this project

Setup and how to run things: `docs/RUNNING.md`.
What the system does and why: `docs/ARCHITECTURE.md`.

---

## Branches

| Branch | Purpose |
|---|---|
| `main` | The live trunk. Work here. |
| `milestone-1` | Frozen snapshot of the M1 submission. **Do not commit to it.** |
| `feature/provenance`, `feature/epss-comparison`, `feature/scalability-experiments`, `defense-development` | Earlier points on the same line of history, all contained in `main`. Kept for reference; do not develop on them. |

`milestone-1` is pinned so the state the proposal describes can always be shown as
submitted. For anything larger than a small fix, branch off `main` and merge back, so
`main` always runs.

```bash
git checkout main && git pull
git checkout -b lab-scans          # for larger work
# ... changes ...
python -m pytest -q                # must stay green
git add -A && git commit -m "describe what changed"
git push
```

---

## Rules

**1. Never hand-type a CVSS vector or score.**
All vulnerability facts come from the feeds in `data/`. If a CVE is missing, add its ID to
`data/cve_seeds.txt` and run `python -m scripts.fetch_feeds`.

This is not pedantry. A hand-typed vector was wrong once already: EternalBlue was entered
as `AV:N/AC:H/PR:N` (8.1) where NVD scores it `AV:N/AC:L/PR:L` (8.8). The test did not
catch it because it compared a hand-typed vector against a hand-typed expected score —
both wrong in the same direction, so they agreed. Cross-checking against the real feed is
what found it.

**2. Keep facts and modelling separate.**
*Facts* come from feeds and scans. *Modelling choices* — probabilities, thresholds,
inference rules — are ours, and must be named, documented, and stated as assumptions.
`apg/catalog.py` and `apg/nmap_import.py` both draw this line explicitly in their module
docstrings; follow the pattern.

**3. Keep assumptions visible.**
`network_from_scan()` *returns* its assumptions as warnings rather than hiding them; the
dashboard shows an orange banner when the data cache is missing. Nothing may fail silently
in a direction that flatters the results.

**4. Be pessimistic about reachability.**
Where something is unknown, assume the attacker-favourable case. Over-reporting attack
paths is the safe direction for a security tool; under-reporting hides real risk.

**5. Do not weaken the honest caveat.**
The greedy planner optimises the same metric the headline comparison reports
(`ARCHITECTURE.md`, "The honest limitation"). Do not remove or soften that note, and do
not let a change quietly make the CVSS-first or EPSS-first baselines weaker — if a
baseline gets worse, the result is less meaningful, not more impressive.

**5a. Keep the five kinds of evidence apart.**
Synthetic demo, hand-built fixtures, the real Metasploitable scan, the multi-seed
comparison and the scalability experiment show different things
(`docs/EXPERIMENTS.md` §0). Never describe a fixture result as real scan data, and never
quote a number that is not in `docs/EXPERIMENTS.md`.

**6. Explain design decisions in the code.**
Every non-obvious choice belongs in a comment or docstring, written so someone can defend
it without having been in the room. Density of explanation matters more here than
terseness.

**7. Run the tests after every change.**
`python -m pytest -q` — 146 currently pass. Add tests as you add code.

---

## Invariants

Breaking any of these invalidates results elsewhere:

- **`apg/cvss.py` must reproduce NVD's published base score for every cached CVE.**
  `test_matches_nvd_published_score` enforces it across all 70. This is the strongest
  evidence the project has that its scoring is correct rather than merely self-consistent.

- **Patch plans are always evaluated against a *fixed* baseline path set**, computed on
  the unpatched network. Changing this invalidates every comparison in the proposal.

- **Results must not depend on `PYTHONHASHSEED`.** Iterating a Python `set` of strings
  makes order depend on the hash seed; networkx breaks ties between equal-cost paths in
  graph order, so set iteration once made the same seed produce different results between
  runs. Sort anything whose order reaches the graph.
  `test_results_do_not_depend_on_pythonhashseed` runs the engine in subprocesses under
  different hash seeds to keep it that way.

- **`Network.allows()` is the single reachability predicate.** Route every segmentation
  question through it — that is why adding a zone or per-host firewall rules touches one
  function instead of ten.

- **Parsing stays pure.** `parse_nmap_xml()` returns only what nmap literally reported.
  All inference lives in `network_from_scan()`, which reports what it assumed.

- **An unknown CVE is an error, not a skip.** `derive_attack_graph` raises a descriptive
  `KeyError`. A silently dropped CVE becomes a zero-probability edge and hides a real path.

- **Only scan data may be labelled `[OBSERVED]`.** Services from `network_from_scan()` are
  `observed`; generated services never carry `[OBSERVED]` or `[CORRELATED]` labels, and a
  CVE dropped on import never appears in the evidence trail. `test_epss_provenance.py`
  enforces all three.

- **Feed snapshots are part of the experimental record.** The committed `data/*.json`
  caches are what the published results were computed from. Refreshing them (including
  via `--kev-only` or `--nvd-only`, which also refresh EPSS) changes EPSS-first results.

---

## Common changes

| Want to... | Do this |
|---|---|
| Add a CVE | Add the ID to `data/cve_seeds.txt`, run `scripts.fetch_feeds`, reference it in `SERVICE_TEMPLATES` if the generator should use it |
| Add a network zone | Add to `_ZONE`, `_CRITICALITY`, `FIREWALL` in `generator.py`, and a role in `SERVICE_TEMPLATES` |
| Change how exploit probability is computed | `apg/scoring.py` — one function, `exploit_probability` |
| Change what counts as a foothold | `apg/scoring.py`, `grants_foothold` |
| Add per-host firewall rules | An optional dict consulted inside `Network.allows()` |
| Add a new analysis | New module in `apg/`, taking the attack graph as input |

---

## Testing

| File | Covers |
|---|---|
| `test_cvss.py` | reference vectors, Roundup edge cases, **every cached CVE against NVD** |
| `test_feeds.py` | NVD/KEV join, dropped CVEs, missing-cache degradation, provenance |
| `test_engine.py` | tiny hand-built networks, credential reuse, determinism, plan monotonicity |
| `test_nmap_import.py` | parsing fixtures, inference, warnings, scan → path end to end, vantage merging |
| `test_neo4j_export.py` | Cypher escaping, idempotency, completeness |
| `test_epss_provenance.py` | EPSS join and ordering, evidence labels on services and path steps, the real Metasploitable scan, the reachability check, the seed-7 demo |

Prefer tests that check a *property* over tests that pin a number: "the greedy plan is
monotone", "unknown CVEs are dropped and reported", "results do not depend on hash seed".
Numbers pinned by hand are how the EternalBlue error survived.

The fixtures in `tests/fixtures/` are hand-built to mirror real nmap 7.94 output. **No host
was scanned to produce them.** The one real capture — Metasploitable 2, 20 October 2026 —
lives in `evidence/real_scan/`, and the tests that use it skip if it is absent.
