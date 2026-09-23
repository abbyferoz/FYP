# Module walkthrough — written for the viva

The M2 viva picks a component and asks you to explain or modify it **unaided**. This
document is the preparation for that: for each module, what it does, why it is built
that way, the questions a jury is likely to ask, and a concrete modification you should
be able to make at the keyboard.

Read it with the source open. If any section here tells you something the code does not,
the code wins — fix the document.

The dependency order is also the order to learn it in. Nothing below depends on anything
above it being understood first.

---

## 1. `apg/cvss.py` — the CVSS v3.1 calculator

**Does:** turns a vector string like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` into
three numbers: base score, Exploitability sub-score, Impact sub-score.

**Why we compute rather than store.** A stored score is a number someone typed. A
computed score can be checked against NVD's published value, and the same code then
scores any CVE we ingest later. This is not theoretical: the check caught a wrong
hand-typed EternalBlue vector (see §11).

**The arithmetic**, straight from the FIRST specification:

```
Exploitability = 8.22 × AV × AC × PR × UI
ISS            = 1 − (1−C)(1−I)(1−A)
Impact         = 6.42 × ISS                                    (scope unchanged)
               = 7.52 × (ISS−0.029) − 3.25 × (ISS−0.02)^15     (scope changed)
Base           = 0                                              if Impact ≤ 0
               = Roundup(min(Impact + Exploitability, 10))      (scope unchanged)
               = Roundup(min(1.08 × (Impact + Exploitability), 10))  (scope changed)
```

**The one subtle part: `_roundup`.** CVSS 3.1 defines Roundup on *integer* arithmetic:
multiply by 100000, and if the result is not an exact multiple of 10000, floor-divide and
add one tenth. It exists because `math.ceil(x * 10) / 10` gives the wrong answer for
values like 8.9 that binary floating point cannot represent exactly — 3.0 implementations
disagreed with each other for exactly this reason, and 3.1 fixed it by specifying the
integer form.

**Note `PR` has two tables.** Privileges Required is scored more harshly when scope is
changed (`_PR_CHANGED`), because gaining privileges that cross a security boundary is
worth more to an attacker.

**Likely questions**
- *Why divide Exploitability by 3.9?* 3.9 is its theoretical maximum
  (8.22 × 0.85 × 0.77 × 0.85 × 0.85), so dividing normalises to [0, 1] for use as a
  probability. See `scoring.py`.
- *Why use Exploitability and not the base score for probability?* Base score mixes in
  Impact, which describes consequences, not the chance of the step succeeding. We model
  consequences separately as asset criticality.
- *Show that scope change matters.* `test_scope_change_raises_the_score`.

**Be able to modify:** add CVSS v4.0 support. You would add a `CVSS:4.0` branch in
`parse_vector`, a new metric table, and v4's different base formula, while keeping
`score()` returning the same `CvssScore` shape so nothing downstream changes.

---

## 2. `apg/feeds.py` + `scripts/fetch_feeds.py` — real vulnerability data

**Does:** `fetch_feeds.py` downloads; `feeds.py` reads. The split is deliberate — reading
is pure and deterministic, so tests run against fixtures with no network and the demo
works in a room with no internet.

**Two sources, two different jobs.**
- **NVD** supplies the CVSS vector. One HTTP request per CVE (there is no bulk-by-ID
  endpoint), rate-limited to 5 requests per 30 seconds anonymously, hence the 6.5 s delay
  and the resume-on-failure merge.
- **CISA KEV** supplies the exploited-in-the-wild flag. One request for the whole
  catalog. This is the single most useful signal we have that is *not* in CVSS: it is
  evidence a vulnerability *has been* exploited, not that it *could be*.

**`pick_cvss` preference order.** NVD often carries several scorings per CVE: its own
analyst score plus vendor (CNA) submissions. We prefer NVD Primary v3.1, then any v3.1,
then v3.0, so every CVE is scored on a consistent basis.

**A CVE with no v3 vector is dropped, not defaulted.** A missing score is recoverable; an
invented one silently corrupts every downstream number.

**`FeedMeta` carries provenance** — snapshot date, KEV catalog version, counts. Quote
this in the report rather than "about 70 CVEs".

**Likely questions**
- *What if NVD is down during the demo?* Nothing breaks: the engine reads the cached
  JSON in `data/`, which is committed. That is why the cache exists.
- *What if the cache is missing entirely?* `catalog.py` falls back to ten hand-entered
  CVEs **and says so loudly** in `FEED_META.summary()`, which the dashboard renders as a
  warning banner. `test_catalog_came_from_the_feed_not_the_fallback` fails in CI so you
  cannot demo fallback numbers believing they are real.

**Be able to modify:** add EPSS. Fetch `https://api.first.org/data/v1/epss`, add an
`epss` field to `Vuln`, and use it in `scoring.exploit_probability` in place of the
hand-picked 1.25 KEV multiplier. This is the highest-value single change in the project.

---

## 3. `apg/model.py` — the data model

Five plain dataclasses: `Vuln`, `Service`, `Host`, `User`, `Network`.

**`Network` is the interesting one.** It holds `hosts`, `users`, `sessions`
(`user is logged in here`), `admin_of` (`user is administrator of this host`), and
`firewall`: a dict keyed by `(source zone, destination zone)` mapping to a frozenset of
allowed ports.

**Why zone-to-zone and not host-to-host?** Real firewalls are written between network
segments, not between individual machines, and a host-pair matrix is O(n²) to store. Two
methods matter:

- `allows(src_zone, dst_zone, port)` — the single reachability predicate the whole
  engine asks. Everything about segmentation flows through this one function.
- `crown_jewels(min_criticality=8)` — which hosts are targets. Criticality is a
  *business* input; the tool cannot infer it.

**Likely question:** *Where would per-host firewall rules go?* Add an optional
`host_firewall` dict and consult it inside `allows()` before falling back to the zone
rule. One function to change, because every caller goes through `allows()`.

---

## 4. `apg/catalog.py` — facts vs. model

Holds two different kinds of thing, and the distinction is the point:

- `VULNS` — **facts**, loaded from the feeds. Not editable here.
- `SERVICE_TEMPLATES` — **our model** of what each host role runs. Synthetic. Only the
  generator uses it; a network imported from a real scan never touches it.

`have(...)` filters template CVEs down to what the loaded catalog can actually score, so
a minimal fallback catalog degrades to fewer vulnerabilities instead of raising a
`KeyError` deep in the attack-graph build.

**Likely question:** *Isn't picking which CVEs go on which role stacking the deck?* For
the synthetic generator, yes, it is our design — that is why it is quarantined in this
file and labelled. The scan-driven path (§8) has no such input, and §6.4 of the proposal
reports that result separately.

---

## 5. `apg/generator.py` — the synthetic enterprise

Builds a segmented network: internet → DMZ web tier → application/file/domain servers →
data tier, plus a corporate workstation zone, with helpdesk, DBA and domain-admin
accounts whose sessions can be harvested.

**Seeded.** `random.Random(seed)` means the same seed always gives the same network —
required for the 100-network experiment to be reproducible.

**Two details worth defending:**
1. *One CVE guaranteed on `web-01`'s HTTPS app.* Without it, a low vulnerability rate can
   produce a network with no way in at all, and runs across seeds stop being comparable.
   It is a deliberate experimental control, and it is documented in the code.
2. *Candidate CVE lists.* Each service template names several plausible CVEs and the
   generator picks one, so two hosts of the same role get different weaknesses. Without
   this, every web server is identical and chokepoint analysis becomes trivial.

**`FIREWALL`** encodes the segmentation policy: internet reaches only the DMZ on 80/443;
the DMZ reaches servers only on 8080; the data zone is reachable only from servers. This
is a textbook three-tier design and is where the interesting paths come from.

**Be able to modify:** add a fifth zone (say `ot` for operational technology) — add it to
`_ZONE`, `_CRITICALITY`, `FIREWALL`, and add a role to `SERVICE_TEMPLATES`. Nothing else
changes, which is the point of routing all reachability through `allows()`.

---

## 6. `apg/infragraph.py` — the knowledge graph

A `networkx.MultiDiGraph` with the schema from the project outline: `Host`, `User`,
`CVE`, `Subnet`, `Internet` nodes; `IN_SUBNET`, `HAS_VULN`, `EXPOSED_TO`, `HAS_SESSION`,
`CAN_ACCESS` edges.

**This is descriptive, not analytical.** It answers *what is there*. It is what loads into
Neo4j. The attack graph (§7) answers *what an attacker can do* and is a separate object
derived from the same `Network`.

Keeping these apart is the single most common point of confusion in this problem area,
and is worth saying clearly in a defence: one node per real thing, versus one node per
attacker state.

**Why MultiDiGraph?** Two nodes can be joined by several different relationships at once
(a user both has a session on a host and is admin of it), and a simple graph would lose
one of them.

---

## 7. `apg/attackgraph.py` — the derived attack graph

**The core of the project.** Nodes are `internet` plus every host. A directed edge
A → B means *an attacker with a foothold on A can get a foothold on B*.

Each edge carries a list of `Option`s — the distinct ways to make that hop:

- **`exploit`** — a vulnerable service on B, on a port A's zone is allowed to reach.
  Probability from `scoring.exploit_probability`.
- **`cred`** — an admin has a logon session on A and is administrator of B, and A's zone
  can reach B on 445 or 3389. Fixed probability 0.5.

**Edge probability is the best option available**, `max(o.p for o in options)`. This is
why patching one CVE may only *weaken* an edge rather than remove it — there may be
another way across. That behaviour is what makes the remediation problem non-trivial, and
it is worth demonstrating live.

**Complexity.** The exploit loop is over (targets × services × CVEs × zones × hosts in
zone), so within a permitted zone pair it is O(n²) edges. 42 hosts gives 932 edges in
about 2 ms; 10,000 hosts would not fit. The fix is zone-level aggregation — represent
"any host in zone X can reach any host in zone Y" implicitly rather than enumerating it.
Expect to be asked this.

**The `patched` parameter** takes a set of `(host, cve)` pairs and omits those exploit
options, which is how remediation evaluates a plan.

**Why `zones` is `sorted(...)` and not a set — expect this question.** Iteration order
here decides the order edges are added to the graph, and networkx breaks ties between
equal-cost paths in graph order. Iterating a *set of strings* makes that order depend on
`PYTHONHASHSEED`, which Python randomises per process. The same seed therefore produced
different top-k paths between runs, and the 100-network experiment moved by 2-3
percentage points each time it was run. Every order-sensitive iteration in the engine is
now sorted, and `test_results_do_not_depend_on_pythonhashseed` runs the engine in
subprocesses under different hash seeds to keep it that way. This is a good bug to be
able to talk about: it was invisible to every existing test, and it silently undermined
the one property the experiments depend on.

**Likely questions**
- *Why can't an attacker on A exploit A?* `if s != t.id` — you already have it.
- *Why is `internet` a node?* It is the attacker's starting state. Making it a node means
  "reachable from outside" is the same graph query as everything else.
- *Where does the foothold rule live?* `scoring.grants_foothold`, not here — this module
  asks, it does not decide.

---

## 8. `apg/nmap_import.py` — real scan data

**Two stages, deliberately separate:**

- `parse_nmap_xml()` — pure XML → facts. Everything it returns is something nmap
  literally reported. Testable with no network and no nmap installed.
- `network_from_scan()` — facts → `Network`. Every step is a *modelling choice*, and each
  returns a warning the caller must show.

**What nmap can and cannot tell you** — know this cold:

| Can | Cannot |
|---|---|
| hosts up, open TCP ports | the firewall policy |
| software and version (`-sV`) | who is logged in where |
| OS guess | which accounts are admin of what |
| CVE IDs (`--script vulners`) | what the business considers critical |

**The reachability assumption.** nmap measures what the scanner reached *from where it
stood*. One scan gives one measured row of the firewall matrix; for everything else we
assume any zone can reach any observed open port. That over-reports paths, which is the
safe direction for a security tool. `merge_scans()` replaces assumption with measurement:
scan from several vantage points, and each contributes a measured row.

**Inference details.** `ROLE_SIGNATURES` is checked most-specific-first: AD ports beat
SMB (a domain controller also has 445 open), and 80/443 beats 8080 (a web server commonly
also runs an app container). `infer_zone` uses the supplied CIDR map, else one zone per
/24 — which at least preserves real segmentation boundaries instead of flattening
everything.

**Unknown CVEs are dropped and reported.** A CVE we cannot score would otherwise become a
silent zero-probability edge and hide a real path.

**Two bugs found here during development** (good material for a defence — they show the
tests do real work):
1. `merge_scans` mutated the caller's `ScannedHost` objects, so appending one scan's
   services changed the other's, and every vantage point appeared to have seen every
   port. Fixed by measuring reachability *before* merging, into copies.
2. Role inference ranked `app` above `web`, misclassifying any web server that also ran
   something on 8080.

**Legal line, and say it unprompted in any demo:** only ever scan machines you own. A VM
on a host-only adapter is the right target. Pakistan's PECA 2016 applies.

---

## 9. `apg/paths.py` — finding the k most probable paths

**The trick.** Path probability is `∏ pᵢ`. Taking logs turns the product into a sum:
maximising `∏ pᵢ` is minimising `∑ −ln pᵢ`. Since every `p` is in (0, 1], every `−ln p` is
non-negative, so standard shortest-path algorithms apply. `edge_cost` in `scoring.py` is
exactly `-math.log(p)`.

`top_paths` calls `nx.shortest_simple_paths` (Yen's algorithm) on the `cost` attribute and
takes the first k. *Simple* paths — no repeated nodes — which is right: revisiting a host
you already control gains nothing.

**Independence is an approximation.** Two steps exploiting the same CVE are correlated, so
true path probability is understated. Know this; it is the honest answer to "is your
probability real?"

**Be able to modify:** deduplicate near-identical paths. Currently the top 10 to a jewel
are often the same route via `web-01` vs `web-02`. Group by the *pattern* — the sequence
of (role, zone) pairs rather than host IDs — and keep the best of each group.

---

## 10. `apg/chokepoints.py` — which hosts carry the risk

Two different measures, and you should know why both exist:

- `path_participation` — for each intermediate host, the summed risk of the baseline
  paths through it. **Target-aware**: it knows what we are protecting.
- `betweenness` — classic betweenness centrality on the `-ln p` costs. **Structure only**:
  it ignores which hosts are crown jewels.

Participation is the operationally useful one. Betweenness is the standard graph-theory
measure and is there as a comparison; a jury may well ask why they differ.

---

## 11. `apg/remediation.py` — ranking patches

**The evaluation design is the part to defend.** All plans are scored on a **fixed**
baseline path set — the top-k paths to each crown jewel on the *unpatched* network.
Re-deriving paths after each patch would let a plan look good by changing the question
rather than by reducing risk.

- `evaluate(A, paths, patched)` → `(residual risk, paths fully broken)`.
- `rank_single_patches` — every relevant patch evaluated alone.
- `greedy_plan(n)` — repeatedly apply whichever patch lowers residual risk most. Cost is
  O(n × candidates × paths).
- `cvss_plan(n)` — the baseline: highest CVSS first, ignoring the graph.

**Why greedy?** Choosing the optimal set of k patches is a set-cover-like problem and is
NP-hard. Residual risk is monotone decreasing and close to submodular in the patch set,
which is the standard setting where greedy is a good approximation. The exact
formulation (min-cut / ILP) is explicitly Term 2 work.

**The honesty point — expect this question and have the answer ready.** *"Your greedy
planner optimises exactly the metric you then report. Isn't the comparison rigged?"*
Correct, and it is stated in the proposal (§6.6) and captioned in the dashboard. The
defensible claim is narrower: reachability-aware ordering beats severity-only ordering on
this model, and §6.4 shows the mechanism — a 10.0 CVE off every path contributes nothing,
while the one 8.8 on the target does. A fair effect size needs real data and baselines the
planner does not optimise. Volunteering this before you are asked is much stronger than
conceding it afterwards.

---

## 12. `apg/neo4j_export.py` — Cypher output

**Why export rather than require a live database at M1?** NetworkX does the analysis in
memory, faster, with no service to start. Emitting the Cypher proves the schema without
making Docker a prerequisite for the demo.

Two design points a jury may probe:
- **`MERGE`, never `CREATE`** — loading the same network twice gives one copy, not two.
  Essential when the graph is refreshed from a nightly scan.
- **Constraints first** — a uniqueness constraint also creates the backing index. Without
  it, `MERGE` does a full label scan and loading a large estate degrades to O(n²).

`EXAMPLE_QUERIES` reproduces the outline's questions in Cypher, which doubles as a
cross-check: the Cypher and the NetworkX code should agree on the reachable set.

---

## 13. The test suite (128 tests)

| File | Covers |
|---|---|
| `test_cvss.py` | reference vectors, Roundup edge cases, **every cached CVE against NVD's published score** |
| `test_feeds.py` | NVD/KEV join, dropped CVEs, missing-cache degradation, provenance |
| `test_engine.py` | tiny hand-built networks, credential reuse, determinism, plan monotonicity |
| `test_nmap_import.py` | parsing fixtures, inference, warnings, end-to-end scan → path, vantage merging |
| `test_neo4j_export.py` | escaping, idempotency, completeness |

**The single most valuable test** is `test_matches_nvd_published_score`: ~69 ground truths
produced by someone else. It caught a real error the previous hand-written test could not,
because that test compared a hand-typed vector against a hand-typed score — both wrong in
the same direction, so they agreed.

---

## Rehearsal checklist

Before the viva, do each of these without notes:

1. Trace one attack path from the dashboard back to the CVEs and firewall rules that
   created it.
2. On `apg/cvss.py`, compute a base score by hand and match the code's answer.
3. Explain why Heartbleed creates no attack-graph edge despite scoring 7.5.
4. Add a zone to the generator and show the paths change.
5. Explain the `-ln p` transform and why Yen's algorithm applies.
6. State the §6.6 honesty caveat *before* being asked.
7. Point at the two bugs in `nmap_import.py` and explain what the tests now prevent.
8. Say what nmap cannot tell you, and what you assumed instead.
9. Explain why iterating a set of strings broke reproducibility, and how the subprocess
   test catches it.
