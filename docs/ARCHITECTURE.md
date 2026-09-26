# What this system does and how

If you only read one document about the design, read this one. `WALKTHROUGH.md` goes
module by module; this explains the shape of the whole thing and why it is shaped that
way.

---

## The problem

Enterprise security teams do not have a vulnerability *detection* problem. Scanners find
plenty. They have a **prioritisation** problem: a mid-sized company scan returns tens of
thousands of findings, a large fraction rated High or Critical, and nobody can patch them
all. So the universal practice is to sort by CVSS severity and work down the list.

That is wrong in a specific, measurable way:

> **CVSS scores a vulnerability in isolation. An attacker exploits a chain.**

A 10.0-rated flaw on a host nothing can reach contributes nothing to real risk. An
8.8-rated flaw on the one machine every route to the customer database passes through is
the entire breach. Severity-first ordering spends a limited budget on findings that lie on
no path to anything valuable.

This tool answers the question severity-first ordering cannot: **given this network, which
specific patches break the most attack paths from the internet to our crown jewels?**

You can watch this happen in `docs/RUNNING.md` §4.2 — on real scan data, severity-first
spends four patches on 9.8s and 10.0s and breaks *zero* paths, while one 8.8 breaks all
five.

---

## Data flow

```
   NVD API ──┐                        ┌── generator.py ── seeded synthetic network
             ├──► feeds.py ───────┐   │
  CISA KEV ──┘   facts about      │   │
                 vulnerabilities  ▼   │
                              catalog.py
                            VULNS (the facts)
                                  │
                                  ▼
  nmap -oX ──► nmap_import.py ──► model.py ◄── generator.py
               facts about        Host · Service · User
               the network        Vuln · Network
                                  │
                ┌─────────────────┴──────────────────┐
                ▼                                    ▼
        infragraph.py                         attackgraph.py
     "what is out there"                   "what an attacker can do"
     Host/User/CVE/Subnet nodes            edges: foothold on A ⇒ foothold on B
     HAS_VULN, CAN_ACCESS, EXPOSED_TO      each carrying a probability
                │                                    │
                ▼                    ┌───────────────┼───────────────┐
        neo4j_export.py              ▼               ▼               ▼
         idempotent Cypher      paths.py       chokepoints.py   remediation.py
                                Yen's k-best   who carries       which patches
                                paths          the risk          break the most
                                               │
                                               ▼
                                     app.py — dashboard
                                     scripts/ — command line
```

Read it in five layers:

**1. Data.** `feeds.py` is the *only* place vulnerability facts enter. `nmap_import.py` is
the *only* place real network facts enter. Both read from cached or supplied files and do
no network I/O, so every result is reproducible offline.

**2. Model.** Plain dataclasses in `model.py`. A `Network` is hosts, users, logon sessions,
admin rights, and a firewall matrix keyed by `(source zone, destination zone) → ports`.
Nothing in the model knows about graphs.

**3. Graphs.** Two of them, and keeping them separate is the most important structural
decision in the project:

| | Knowledge graph (`infragraph.py`) | Attack graph (`attackgraph.py`) |
|---|---|---|
| Answers | *what is out there* | *what an attacker can do* |
| One node per | real thing (host, user, CVE, subnet) | attacker state (which host they hold) |
| Edges | descriptive relationships | "foothold on A gets you a foothold on B" |
| Used for | Neo4j, reporting, exploration | path finding, chokepoints, remediation |

Conflating these is the usual source of confusion in this problem area. Both are derived
from the same `Network`; neither is derived from the other.

**4. Analysis.** Path finding, chokepoint ranking, patch planning.

**5. Presentation.** Streamlit dashboard, command-line scripts.

---

## The five ideas that make it work

### 1. Probability, not reachability

Most academic attack-graph work treats an edge as boolean: reachable or not. We attach a
**success probability** to every edge, derived from the CVSS Exploitability sub-score:

```
p = ExploitabilitySubScore / 3.9      (3.9 is its theoretical maximum)
p = p × 1.25 if the CVE is in CISA KEV
p = min(p, 0.99)
```

Exploitability combines attack vector, complexity, privileges required and user
interaction — exactly the things that decide whether a step *succeeds*. The Impact
sub-score describes *consequences*, which we model separately as asset criticality. Mixing
them, as the CVSS base score does, is precisely what makes base score a poor prioritiser.

The KEV multiplier means "this has actually been exploited in the wild, not merely could
be" — the single most useful signal that is not in CVSS.

### 2. Not every vulnerability gives you a foothold

A CVE creates an attack-graph edge only if its **integrity impact is not None**.

Heartbleed (`C:H/I:N/A:N`, rated 7.5) leaks memory but does not by itself give an attacker
control of the host. It is still reported — but it does not manufacture an attack path.
This is why the planner can correctly ignore a 7.5 while treating an 8.8 as urgent, and it
is a good thing to be able to explain.

### 3. Attackers steal credentials, not just exploits

Real intrusions move laterally through stolen credentials at least as often as through
software flaws. So the attack graph has two kinds of edge:

- **exploit** — a vulnerable service on B, on a port A's zone can reach.
- **credential reuse** — an admin has a logon session on A and administers B, and A can
  reach B on 445 or 3389.

An edge carries *all* the ways to make that hop and takes the probability of the best one.
That is why patching one CVE may only *weaken* an edge rather than remove it — there may
be another way across. That is what makes remediation a real optimisation problem rather
than a lookup.

### 4. Multiplying probabilities is adding logarithms

Path probability is the product of its edge probabilities. Taking logs:

```
maximise  ∏ pᵢ      ⟺      minimise  ∑ −ln pᵢ
```

Every `p` is in (0, 1], so every `−ln p` is non-negative and standard shortest-path
algorithms apply unchanged. The most probable attack path *is* the shortest path under
cost `−ln p`, and Yen's algorithm gives the k most probable paths directly.

*(Approximation: edges are treated as independent. Two steps exploiting the same CVE are
obviously correlated, so true path probability is understated.)*

### 5. Compare plans on fixed ground

Every patch plan is scored against the **same fixed set of baseline paths** — the top-k
paths to each crown jewel on the *unpatched* network.

```
residual risk = Σ over baseline paths of (probability under this plan × criticality)
```

Re-deriving paths after each patch would let a plan look good by changing the question
instead of reducing risk. This is the detail that makes the comparison in §4.3 of
`RUNNING.md` mean anything.

---

## What the tool does not know

Being explicit about this is a feature, not an apology — `network_from_scan()` returns
these as warnings you are expected to show, rather than hiding them.

| nmap can tell you | nmap cannot tell you |
|---|---|
| which hosts are up | the firewall policy |
| which TCP ports are open | who is logged in where |
| what software answers (`-sV`) | which accounts administer what |
| CVE IDs (`--script vulners`) | what the business considers critical |

Where something is unknown, the tool assumes the **pessimistic** case — reachability is
assumed open unless measured. Over-reporting attack paths is the safe direction for a
security tool; under-reporting hides real risk. Scanning from several vantage points
(`merge_scans()`) converts assumption into measurement.

Asset criticality has no technical answer at all. It is a business input, and the tool
does not pretend to infer it.

---

## The honest limitation

The headline result — graph-aware patching reaching 0% residual risk in three patches
against 18.6% for severity-first, winning or tying on 71 of 71 networks — has a real
weakness, and it is documented rather than buried:

**The greedy planner directly optimises the same residual-risk metric the comparison then
reports, on the same model. So it is expected to win.**

What the experiment legitimately demonstrates is that the implementation works. What
transfers to real networks is the *mechanism*, not the margin: a high-severity CVE that
sits on no path to anything valuable is worthless to patch first, and that is true of real
estates regardless of our model.

Establishing a genuine effect size needs real scan data at scale and stronger baselines
(CVSS+KEV, EPSS, internet-facing-first). See `docs/ROADMAP.md`.

**State this before anyone asks.** Volunteering a limitation reads as rigour; conceding it
under questioning reads as overselling.

---

## Where things live

```
apg/                 the engine
  cvss.py            CVSS v3.1 calculator (validated against NVD)
  feeds.py           loads cached NVD + CISA KEV data
  catalog.py         joins them; service templates for the generator
  model.py           Host, Service, User, Vuln, Network
  scoring.py         CVSS → probability. The modelling layer.
  generator.py       seeded synthetic networks
  nmap_import.py     real nmap XML → Network
  infragraph.py      knowledge graph
  attackgraph.py     derived attack graph
  paths.py           Yen's k most probable paths
  chokepoints.py     risk-weighted participation, betweenness
  remediation.py     patch ranking and plan comparison
  neo4j_export.py    idempotent Cypher

scripts/             command-line entry points
tests/               128 tests; fixtures/ holds sample nmap XML
data/                cached NVD + KEV feeds, committed so demos work offline
app.py               Streamlit + PyVis dashboard
```

**Dependency order**, which is also the order to learn it in:

`cvss` → `feeds` → `model` → `catalog` → {`generator`, `nmap_import`} →
{`infragraph`, `attackgraph`} → `paths` → {`chokepoints`, `remediation`} → `app`

Nothing depends on anything later in that chain.
