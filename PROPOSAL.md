# Enterprise Cyber Attack-Path Intelligence

**Milestone 1 — MVP / Feasibility Pilot, written proposal**

Muhammad Rayyan Khan (28410) · Abdullah Feroz (29219)
Advisor: Tasbiha Fatima, Lecturer, Department of Computer Science
Track: Software · CSE 493, Term 1 (Sept–Dec 2026)

> **Note before submission.** Reformat this document onto the department's proposal
> template (title page pattern in the FYP booklet, §0.5.2; full template in the linked
> repository) before handing it in. The content below is organised to map onto that
> template section by section. Confirm the exact M1 date and the software-track
> designation with the advisor.

---

## 1. Problem statement

Enterprise security teams do not have a vulnerability *detection* problem. They have a
vulnerability *prioritisation* problem. A mid-sized estate scanned with a commercial
tool typically returns tens of thousands of findings, of which a large fraction are
rated High or Critical by CVSS. No team can patch them all, so the universal practice
is to sort by CVSS base score and work down the list.

That practice is wrong in a specific and measurable way: **CVSS scores a vulnerability
in isolation, but an attacker exploits a chain.** A 10.0-rated flaw on a host that is
unreachable from anywhere an attacker can stand contributes nothing to real risk. An
8.8-rated flaw on the one host that every route to the customer database passes through
is the whole breach. Severity-first patching therefore spends a limited remediation
budget on findings that do not lie on any path to anything valuable.

This project builds the tool that answers the question severity-first ordering cannot:
*given this network, which specific patches break the most attack paths from the
internet to our crown-jewel assets?*

Our M1 result already shows the gap concretely. On a real lab scan, the highest-CVSS
plan spends four patches on 10.0-rated CVEs (Zerologon, Log4Shell) and breaks **zero**
paths to the database, because the database's own 8.8-rated flaw is directly reachable.
The graph-aware plan breaks all five paths with that one patch.

## 2. Aims and objectives

**Aim.** Model an enterprise network as a graph, compute the attack paths from an
external entry point to business-critical assets, score them, and produce a remediation
plan that is demonstrably better than severity-only ordering.

**Term 1 objectives (this milestone and M2):**

1. Implement a CVSS v3.1 base-score calculator and validate it against NVD. *(done)*
2. Ingest real vulnerability data: NVD CVE records cross-referenced with the CISA
   Known Exploited Vulnerabilities catalog. *(done)*
3. Model hosts, services, users, sessions, privileges and segmentation. *(done)*
4. Derive an attack graph whose edges are exploit steps and credential-reuse steps,
   each carrying a success probability. *(done)*
5. Find the k most probable attack paths to each crown jewel and score their risk. *(done)*
6. Identify chokepoints — hosts that carry disproportionate path risk. *(done)*
7. Produce a graph-aware patch plan and benchmark it against a highest-CVSS-first
   baseline across many networks. *(done)*
8. Ingest real scanner output (`nmap -oX`) so the engine runs on measured data, not
   only on simulation. *(done)*
9. Export the knowledge graph to Neo4j and reproduce core queries in Cypher. *(schema
   and exporter done; loading into a live instance is M2)*
10. Interactive dashboard for analysts. *(done)*

**Term 2 (M4–M5), as scoped in the advisor's twelve-month roadmap:** a predictive GNN
layer for unmapped lateral movement, a minimum-cut / ILP "minimum patch set" optimiser,
an LLM remediation-script agent, and validation against a larger real environment.

## 3. Related work

**Attack-graph generation.** The academic line runs from Phillips and Swiler's original
attack-graph model through Sheyner's model-checking approach to **MulVAL** (Ou et al.,
2005), which encodes host configuration and network reachability as Datalog and derives
logical attack graphs. MulVAL is the closest academic ancestor of this project. Our
engine differs in two ways: it attaches an explicit success *probability* to each edge
rather than treating reachability as boolean, and it targets remediation ranking rather
than exhaustive path enumeration. The scalability problem MulVAL surfaced — attack
graphs grow super-linearly in host count — is the same one we address in §8.

**Identity-centric graphs.** **BloodHound** (Robbins, Vazarkar, Schroeder) mapped Active
Directory relationships as a graph and showed that credential reuse and privilege
inheritance, not software flaws, are the dominant lateral-movement mechanism in Windows
estates. Our credential-reuse edges are a deliberate, much-simplified version of that
idea; adopting SharpHound's collection format is the obvious route to real identity
data in Term 2.

**Commercial reachability-based prioritisation.** Tools in this space (XM Cyber, Tenable
Attack Path Analysis, Wiz's security graph) sell exactly the thesis of this project, and
their existence is evidence of the industry demand our advisor noted. They are closed,
so their scoring models cannot be examined or reproduced — which is what leaves room for
an open, inspectable implementation.

**Exploit-likelihood scoring.** FIRST's **EPSS** predicts the probability that a
vulnerability will be exploited in the wild within 30 days, and the **CISA KEV** catalog
records what actually has been. We use KEV now; EPSS is the most valuable single
addition to our probability model and is planned for Term 2. Both exist precisely
because the security community accepts that CVSS base score alone is a poor prioritiser
— that consensus is the foundation this project builds on.

**Gap we address.** The academic work models paths but largely stops at enumeration; the
commercial work prioritises but is not inspectable; EPSS and KEV improve per-vulnerability
scoring but say nothing about topology. An open implementation that combines
reachability, identity and exploit-likelihood into a *ranked remediation plan*, and that
publishes its comparison against the severity-first baseline honestly, is a defensible
contribution at undergraduate scope.

## 4. System architecture

```
  NVD API ──┐                    ┌── synthetic generator (seeded, reproducible)
            ├─► apg/feeds.py ────┤
 CISA KEV ──┘   (facts: vectors, ├── apg/nmap_import.py ◄── nmap -oX (real scan)
                 KEV status)     │   (facts: hosts, ports, products, CVEs)
                                 ▼
                          apg/model.py
                  Host · Service · User · Vuln · Network
                                 │
              ┌──────────────────┴───────────────────┐
              ▼                                      ▼
      apg/infragraph.py                      apg/attackgraph.py
   knowledge graph (Host, User,         "foothold on A ⇒ foothold on B"
    CVE, Subnet; HAS_VULN,               edges from exploits and stolen
    CAN_ACCESS, EXPOSED_TO)              credentials, each with p
              │                                      │
              ▼                          ┌───────────┼────────────┐
   apg/neo4j_export.py                   ▼           ▼            ▼
     idempotent Cypher              apg/paths.py  chokepoints  remediation
                                    Yen's k-best   centrality   greedy plan
                                                        │
                                                        ▼
                                          app.py — Streamlit + PyVis dashboard
```

**Layer 1 — data.** `feeds.py` is the only place vulnerability *facts* enter the system.
`nmap_import.py` is the only place network facts enter. Both are pure readers over
cached or supplied files, so every result is reproducible offline.

**Layer 2 — model.** Plain dataclasses. A `Network` is hosts, users, logon sessions,
admin rights and a firewall matrix keyed by `(source zone, destination zone) → ports`.

**Layer 3 — graphs.** The *knowledge graph* is the descriptive schema from the project
outline, and is what loads into Neo4j. The *attack graph* is derived from the same
`Network` and is what the algorithms run on. Keeping them separate matters: the
knowledge graph answers "what is there", the attack graph answers "what can an attacker
do", and conflating them is the usual source of confusion in this area.

**Layer 4 — analysis.** Path finding, chokepoints, remediation ranking.

**Layer 5 — presentation.** Streamlit dashboard and command-line scripts.

## 5. Method and modelling choices

Every number this system produces rests on the assumptions below. They are stated
explicitly because they are the project's main threat to validity, and because the M2
viva will ask about them.

**5.1 Exploit probability.** `p = ExploitabilitySubScore / 3.9`, multiplied by 1.25 if
the CVE is in CISA KEV, capped at 0.99. The Exploitability sub-score already combines
attack vector, complexity, privileges required and user interaction — exactly the
factors that determine whether a step succeeds — while the Impact sub-score describes
consequences, which we model separately through asset criticality. Dividing by the
theoretical maximum 3.9 normalises to [0, 1]. *The KEV multiplier of 1.25 is a judgement
call, not a measured quantity.* Replacing it with EPSS is the principled fix.

**5.2 What counts as a foothold.** A vulnerability creates an attack-graph edge only if
its CVSS integrity impact is not `None`. Heartbleed (`C:H/I:N/A:N`) leaks memory but does
not by itself give an attacker control of the host, so it creates no edge — it is still
reported, but it does not manufacture a path. This is why a 7.5-rated CVE can be
correctly ignored by the planner while an 8.8 is urgent.

**5.3 Credential reuse.** If an attacker holds a host where an admin has a logon session,
they may reuse that credential against any host the admin administers and can reach on
445 or 3389, with a fixed probability of 0.5. The fixed constant is the weakest
assumption in the model; BloodHound-style collection would replace it with observed
privilege relationships.

**5.4 Path probability and ranking.** Edge probabilities are treated as independent and
multiplied along a path. Maximising `∏ pᵢ` is equivalent to minimising `∑ −ln pᵢ`, so the
most probable path is the shortest path under cost `−ln p`, and Yen's algorithm gives the
k most probable paths directly. *Independence is an approximation:* two steps exploiting
the same CVE are clearly correlated, so true path probability is understated.

**5.5 Risk.** `risk = path probability × criticality of the final host (1–10)`. A simple
likelihood × impact product. Criticality is a business input, not a technical one; the
tool cannot infer it and should not pretend to.

**5.6 Evaluating a patch plan.** All plans are scored on a **fixed** baseline set — the
top-k paths to each crown jewel on the *unpatched* network — so that competing plans are
compared on identical ground. Residual risk is the sum over those baseline paths of
(probability under the plan × criticality). Re-deriving paths after each patch would let
a plan look good by simply changing the question.

**5.7 Reachability from a scan.** nmap measures what the scanner could reach from where
it stood. It cannot see the firewall policy. A single scan therefore yields one measured
row of the reachability matrix and, for everything else, the *pessimistic* assumption
that any zone can reach any observed open port. Over-reporting paths is the safe
direction for a security tool. `merge_scans()` converts assumption into measurement:
scan from several vantage points and each contributes a measured row.

## 6. Results so far (the M1 demonstrator)

All figures reproducible: `python -m pytest -q`, `python -m scripts.run_demo`,
`python -m scripts.compare_seeds --seeds 100`.

**6.1 CVSS implementation validated against NVD.** 69 CVEs cached from the NVD API
(snapshot 2026-09-22); 62 are in CISA KEV, 44 flagged for known ransomware use. Our
calculator recomputes the base score from each vector string and agrees with NVD's
published score on **69 of 69**. Cross-checking against the feed also caught a real error
in the earlier hand-entered catalog: EternalBlue had been typed as `AV:N/AC:H/PR:N` (8.1)
where NVD scores it `AV:N/AC:L/PR:L` (8.8), and the hand-written test agreed with the
hand-written vector, so the mistake was invisible until real data arrived.

**6.2 Scale of the synthetic estate.** Seed 7 produces 42 hosts, 34 users, a knowledge
graph of 95 nodes and 235 edges, and an attack graph of 932 edges, derived in about 2 ms.

**6.3 Graph-aware vs highest-CVSS-first, 100 seeded networks.** 71 networks had at least
one internet-to-crown-jewel path (29 had none and were excluded). Mean residual risk as a
percentage of the unpatched baseline:

| Patches applied | Graph-aware plan | Highest-CVSS first |
|---:|---:|---:|
| 1 | **5.6 %** | 58.1 % |
| 2 | **0.4 %** | 36.2 % |
| 3 | **0.0 %** | 18.6 % |
| 4 | **0.0 %** | 10.6 % |
| 5 | **0.0 %** | 5.1 % |

The graph-aware plan was at least as good as the severity-first baseline on **71 of 71**
networks, and reached zero residual risk with three patches where the baseline still
carried 18.6 %.

**6.4 End-to-end on real scan data.** The engine runs unchanged on `nmap -sV --script
vulners -oX` output. On the lab scan fixture, the graph-aware plan removes 100 % of
residual risk with a single 8.8-rated patch, while the severity-first plan spends four
patches on 9.8- and 10.0-rated CVEs and breaks no path at all.

**6.5 Test suite.** 128 tests, all passing, covering CVSS conformance and NVD agreement,
feed parsing, attack-graph construction, path finding, remediation monotonicity, the
nmap parser against realistic fixtures, and the Cypher exporter.

**6.6 How to read result 6.3 honestly.** The greedy planner directly optimises the same
residual-risk metric the comparison reports, on the same model, so it is *expected* to
win — the table demonstrates that the implementation works, not that the margin
generalises to real estates. The defensible claim from M1 is narrower: **reachability-aware
ordering dominates severity-only ordering on this model, and the mechanism by which it
does so (§6.4) is one that occurs in real networks.** Establishing an effect size on real
data, against stronger baselines (CVSS+KEV, EPSS, internet-facing-first), is exactly what
M4's real-conditions validation is for.

## 7. Term 1 plan (≈15 weeks)

| Weeks | Work | Milestone |
|---|---|---|
| 1–2 | Idea selection, advisor approval, environment setup | |
| 3–5 | Core engine: CVSS, model, generator, attack graph, paths, chokepoints, remediation, dashboard | |
| 6 | **Real NVD/KEV ingestion, nmap import, Neo4j export, test suite to 128, this proposal** | **M1 — jury defence** |
| 7–8 | Live Neo4j instance; port core queries to Cypher; cross-check against the NetworkX results | |
| 9–10 | Lab environment: Metasploitable + a Windows VM on a host-only network; real scans end-to-end | |
| 11–12 | EPSS integration; stronger baselines; path deduplication; scale testing toward 10,000 nodes | |
| 13–14 | Identity data (BloodHound/SharpHound format) replacing the fixed credential-reuse constant | |
| 15 | Freeze, documentation, internal evaluation | **M2 — internal evaluation + individual viva** |
| 16 | Public presentation of the same build | **M3 — External Open House** |

**Division of work.** Rayyan (Information Security focus) leads the threat model, the
lab environment, scan collection, and the security correctness of the modelling
assumptions. Abdullah (ML/AI focus) leads the graph algorithms, the scoring and
remediation optimisation, the data pipeline, and the Term 2 GNN work. Both review each
other's modules, because the M2 viva examines each of us individually on any component.

## 8. Risks and limitations

| Risk | Impact | Mitigation |
|---|---|---|
| Attack graph is O(hosts²) within permitted zones | Blocks the 10,000-node scale target | Zone-level aggregation; represent intra-zone reachability implicitly rather than as explicit edges |
| Top-k paths are dominated by near-identical variants (web-01 vs web-02) | Analyst sees ten copies of one finding | Deduplicate by path *pattern* (role/zone sequence) rather than host identity |
| Fixed credential-reuse probability of 0.5 is unjustified | Weakens every result involving lateral movement | Replace with observed AD relationships from SharpHound collection |
| KEV multiplier of 1.25 is a guess | Distorts exploit probability | Replace with EPSS, which is an actual predicted probability |
| Self-evaluating benchmark (§6.6) | Headline result could be dismissed as circular | Real scan data, stronger baselines, and an evaluation metric the planner does not directly optimise |
| NVD's own vectors sometimes understate impact (e.g. CVE-2017-10271 is scored `C:N/I:N/A:H`, so our foothold rule excludes a CVE that is in practice RCE) | Real paths can be missed | Document; consider CNA vectors or KEV description as a secondary signal |
| Lab scanning must stay lawful | Project-ending | Scan only VMs we own on host-only adapters. Never scan third-party or university infrastructure — Pakistan's PECA 2016 applies |

## 9. Deliverables

- Working demonstrator (this repository): engine, dashboard, 128 tests, cached real data.
- This proposal, reformatted onto the department template.
- `docs/RUNNING.md` — install, run and test instructions with expected output.
- `docs/ARCHITECTURE.md` — system design and modelling rationale.
- `docs/WALKTHROUGH.md` — module-by-module explanation, written for the individual viva.
- `docs/ROADMAP.md` — status, known limitations and planned work.

## References

1. X. Ou, S. Govindavajhala, A. W. Appel. *MulVAL: A Logic-based Network Security
   Analyzer.* USENIX Security Symposium, 2005.
2. O. Sheyner, J. Haines, S. Jha, R. Lippmann, J. M. Wing. *Automated Generation and
   Analysis of Attack Graphs.* IEEE Symposium on Security and Privacy, 2002.
3. C. Phillips, L. P. Swiler. *A Graph-Based System for Network-Vulnerability Analysis.*
   New Security Paradigms Workshop, 1998.
4. A. Robbins, R. Vazarkar, W. Schroeder. *BloodHound: Six Degrees of Domain Admin.*
   DEF CON 24, 2016.
5. FIRST. *Common Vulnerability Scoring System v3.1: Specification Document.*
   https://www.first.org/cvss/v3.1/specification-document
6. FIRST. *Exploit Prediction Scoring System (EPSS).* https://www.first.org/epss/
7. CISA. *Known Exploited Vulnerabilities Catalog.*
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog
8. NIST. *National Vulnerability Database API 2.0.* https://nvd.nist.gov/developers/vulnerabilities
9. J. Y. Yen. *Finding the K Shortest Loopless Paths in a Network.* Management Science,
   17(11), 1971.
