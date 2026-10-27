# Running and testing everything

Complete instructions for any machine, with the output each command should produce so
you can tell success from failure without guessing.

**Contents**
1. [Requirements](#1-requirements)
2. [Install](#2-install) — macOS, Linux, Windows
3. [Verify the install](#3-verify-the-install)
4. [The things you can run](#4-the-things-you-can-run)
5. [Refreshing the vulnerability data](#5-refreshing-the-vulnerability-data)
6. [Analysing a real network you own](#6-analysing-a-real-network-you-own)
7. [Loading the graph into Neo4j](#7-loading-the-graph-into-neo4j)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Requirements

| | |
|---|---|
| **Python** | 3.10 or newer. 3.11–3.13 tested. |
| **Disk** | ~150 MB (mostly the virtual environment) |
| **Internet** | **Not required.** All vulnerability data is committed to the repo. Only needed to *refresh* it (§5). |
| **Optional** | `nmap` — only if you want to scan a real network (§6). `Docker` — only for Neo4j (§7). |

Everything else installs with `pip`. There are five dependencies: `networkx`, `streamlit`,
`pyvis`, `pandas`, `pytest`.

---

## 2. Install

### macOS

```bash
# One-time, if you do not have them:
xcode-select --install
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12 git

# The project:
git clone https://github.com/abbyferoz/FYP.git
cd FYP
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git

git clone https://github.com/abbyferoz/FYP.git
cd FYP
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

Install Python from [python.org](https://www.python.org/downloads/) — **tick "Add Python
to PATH"** during setup — and Git from [git-scm.com](https://git-scm.com/download/win).

```powershell
git clone https://github.com/abbyferoz/FYP.git
cd FYP
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell refuses to run the activate script:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

> On Windows, use `python` wherever this document says `python3`, and
> `.\.venv\Scripts\Activate.ps1` wherever it says `source .venv/bin/activate`.

### Every time you come back to the project

```bash
cd FYP
source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
```

Your prompt should now start with `(.venv)`. If it does not, the commands below will fail
with `ModuleNotFoundError`.

---

## 3. Verify the install

```bash
python -m pytest -q
```

**Success looks like:**

```
........................................................................ [ 49%]
........................................................................ [ 98%]
..                                                                       [100%]
146 passed in 1.70s
```

146 passing is the only acceptable result. If anything fails, go to §8.

The most important test in that run is `test_matches_nvd_published_score`: it takes every
one of the 70 CVEs in the local cache, recomputes the CVSS base score from the vector
string using our own calculator, and asserts it equals the score NVD published. Those are
70 ground truths produced by someone else, so passing means the scoring engine is
genuinely correct rather than merely self-consistent.

`tests/test_epss_provenance.py` covers the features added in October: EPSS loading and
ordering, observed / correlated / inferred evidence labels, the real Metasploitable scan,
and the reachability check.

---

## 4. The things you can run

### 4.1 `run_demo` — the whole engine on a synthetic network

```bash
python -m scripts.run_demo
```

Generates a 42-host enterprise network, derives the attack graph, finds paths to the
crown jewels, identifies chokepoints, and compares three patching strategies:
graph-aware, highest-CVSS-first and highest-EPSS-first.

**Success looks like** (abridged — the real output is longer):

```
Network: 42 hosts, 34 users | knowledge graph 95 nodes / 235 edges | attack graph 932 edges | crown jewels: db-01, db-02, dc-01

== db-01: 50 paths found (showing top 2)
  p=0.485 risk=4.85  internet -> web-01 -> app-03 -> fileserver-01 -> db-01
      - exploit CVE-2021-44228 on web-01:443
      - exploit CVE-2022-22965 on app-03:8080
      - exploit CVE-2020-0796 on fileserver-01:445
      - reuse domadmin credentials harvested on fileserver-01

== Chokepoints (risk-weighted path participation)
  app-03         risk=799.67 paths=150
  fileserver-01  risk=640.62 paths=127

== Best single patches (baseline residual risk 799.67)
  patch CVE-2022-22965 on app-03       -> residual   0.00, paths broken 150/150
  patch CVE-2020-0796 on fileserver-01 -> residual 191.41, paths broken 115/150

== Remediation comparison: graph-aware vs CVSS-first vs EPSS-first

  n=1
    graph-aware:   0.0% residual / 150 paths broken
      selected: CVE-2022-22965 on app-03 (CVSS=9.8, EPSS=0.9964)
    cvss-first:   23.9% residual / 115 paths broken
      selected: CVE-2020-0796 on fileserver-01 (CVSS=10.0, EPSS=0.9981)
    epss-first:  100.0% residual /   0 paths broken
      selected: CVE-2022-26134 on app-01 (CVSS=9.8, EPSS=1.0000)
```

**How to read it.**
- `p=0.485` — the probability an attacker completes that whole chain.
- `risk=4.85` — probability × how critical the final host is (1–10).
- Each `-` line is one hop: which CVE was exploited on which host and port, or whose
  credentials were reused.
- **Chokepoints** are the hosts the most risk flows through. `app-03` carries 799.67 of
  risk across 150 paths — it is the single most valuable thing to fix.
- **Best single patches** — patching `CVE-2022-22965` on `app-03` alone takes residual
  risk to `0.00` and breaks all 150 paths. That is the tool working: one patch, chosen by
  position in the graph rather than by severity, removes everything.
- The last block compares the three strategies on this one network. EPSS-first ranks
  every finding in the network by EPSS; its first pick, CVE-2022-26134 (EPSS 1.0000), sits
  on `app-01`, a host no retained path uses, so it breaks nothing. Rebuilding the graph confirms that patching `app-03`
  really does cut off all three crown jewels in this network; it is not an artefact of the
  50-path limit.
- Once residual risk reaches 0, later graph-aware steps all score 0 and are chosen by
  tie-break, so steps 2–5 of the graph-aware plan carry no meaning here.
- One network proves nothing general. Read §4.3.

Useful flags: `--seed 12` (different network), `--workstations 60`, `--vuln-rate 0.5`,
`--patches 8`. The same seed always produces the same network.

### 4.2 `import_scan` — the same engine on scan data

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz \
    --zone 192.168.57.0/24=servers \
    --zone 192.168.58.0/24=data
```

This runs on `nmap -oX` output instead of a simulation — the engine is identical, only the
input differs.

> **`lab_scan.xml` is a hand-built fixture.** It was written to mirror nmap 7.94 output;
> **no host was scanned to produce it**. It shows the mechanism clearly, but it is not
> evidence about a real network. The real scan is in §4.2.1 below.

**Success looks like** (abridged; each path step also prints its evidence labels):

```
Parsed tests/fixtures/lab_scan.xml: 3 hosts up, vantage 'internet'
Catalog: 70 CVEs from NVD (snapshot 2026-10-20), 62 of them in CISA KEV (catalog 2026.10.21, 1754 entries)

== Imported network
  db-01              zone=data     role=db          crit=9  ports=[445, 1433]
                     CVEs: CVE-2020-0618
  web-01             zone=dmz      role=web         crit=3  ports=[22, 80, 443, 8080]
                     CVEs: CVE-2021-44228, CVE-2021-45046, CVE-2022-22965
  fs-01              zone=servers  role=fileserver  crit=6  ports=[135, 139, 445, 3389]
                     CVEs: CVE-2017-0143, CVE-2017-0144, CVE-2019-0708, CVE-2020-1472

== Assumptions and gaps (say these out loud in a demo)
  ! Firewall policy was not supplied. ...
  ! No identity data: nmap cannot see logon sessions or admin rights ...

== Best single patches (baseline residual risk 39.90)
  patch CVE-2020-0618    on db-01    -> residual    0.00, paths broken 5/5
  patch CVE-2017-0143    on fs-01    -> residual   39.90, paths broken 0/5

== Remediation comparison: graph-aware vs CVSS-first vs EPSS-first (residual risk as % of baseline)
  n=1  graph-aware:   0.0% / broke   5   cvss-first: 100.0% / broke   0   epss-first: 100.0% / broke   0
  n=4  graph-aware:   0.0% / broke   5   cvss-first:  78.3% / broke   0   epss-first:  40.3% / broke   3
```

**Why this matters.** Severity-first patching spends its first four patches on CVEs rated
9.8 and 10.0 — Zerologon, Log4Shell, BlueKeep — and breaks **zero** paths to the database.
The graph-aware plan breaks all five with one patch rated 8.8, because that 8.8 sits on
the database itself and every path must pass through it. A 10.0 that lies on no path to
anything valuable contributes nothing to modelled risk. That is the thesis of the project,
visible in one screen — on a constructed example.

**The "Assumptions and gaps" block is not boilerplate — read it.** nmap cannot see your
firewall rules or who is logged in where, so the tool states what it measured and what it
assumed instead of hiding the difference.

Now try the awkward case:

```bash
python -m scripts.import_scan tests/fixtures/metasploitable.xml
```

This fixture has no CVE data (it was scanned without the `vulners` script), so you get:

```
  ! No CVEs found in the scan, so the attack graph will have no exploit edges.
    Re-run nmap with `--script vulners` (or supply CVEs another way).

== Attack graph: 2 nodes, 0 edges | crown jewels (criticality >= 8): 192.168.56.101

No attack path from the internet to any crown jewel. That is a GOOD result for the
network, and a boring one for a demo.
```

**That is correct behaviour, not a failure.** An empty attack graph could mean "this
network is secure" or "you gave me no vulnerability data" — the tool tells you which.
(`tests/fixtures/metasploitable.xml` is also hand-built. It is not the real scan below.)

#### 4.2.1 The real Metasploitable 2 scan

```bash
python -m scripts.import_scan evidence/real_scan/metasploitable-vulners.xml --criticality 192.168.56.102=9
```

This XML was captured on 20 October 2026 with `nmap -sV --script vulners` against a
Metasploitable 2 VM on a host-only network. The full expected output is committed as
`evidence/real_scan/import-output.txt`. Key lines:

```
Parsed evidence/real_scan/metasploitable-vulners.xml: 1 hosts up, vantage 'internet'
  192.168.56.102     zone=net-192.168.56   role=db           crit=9  ports=[21, 22, 23, ...]
                     CVEs: CVE-2011-2523
  ! 416 CVE(s) reported by nmap are not in the local catalog and were dropped: ...

== 192.168.56.102: 1 path(s)
  p=0.990 risk=8.91  internet -> 192.168.56.102
      - exploit CVE-2011-2523 on 192.168.56.102:21
        status: INFERRED
        evidence:
          * [OBSERVED] TCP/21 observed open by nmap
          * [OBSERVED] service identified as vsftpd 2.3.4
          * [CORRELATED] CVE-2011-2523 reported by nmap NSE/vulnerability enrichment
          * [INFERRED] model infers CVE-2011-2523 can provide a foothold on 192.168.56.102
          * [INFERRED] exploit probability computed as 0.990
```

**What it shows:** the whole pipeline works on genuine scanner output, and the evidence
labels separate what nmap saw from what the model concluded.

**What it does not show:** multi-hop paths (one host, one edge), any difference between
strategies (only one finding, so all three choose it), or that the exploit works (it was
not executed). It also exposed a real limitation: 416 of 417 reported CVEs are outside the
local catalog. The `db` role is a port-based guess (MySQL and PostgreSQL are open), and 9 is
that role's default criticality.

### 4.3 `compare_seeds` — does the approach hold up across many networks?

```bash
python -m scripts.compare_seeds --seeds 100
```

Builds 100 different networks and runs all three patching strategies on each. Takes about
10 seconds.

**Success looks like:**

```
71 networks with attack paths (29 skipped: no path to any crown jewel)

Mean residual risk (% of baseline)

n patches | graph-aware | CVSS-first | EPSS-first
----------+-------------+------------+-----------
    1     |       5.6% |     58.1% |    97.7%
    2     |       0.4% |     36.2% |    82.4%
    3     |       0.0% |     18.6% |    60.4%
    4     |       0.0% |     10.6% |    43.7%
    5     |       0.0% |      5.1% |    31.4%

After 5 patches:
  graph-aware <= CVSS-first: 71/71 networks
  graph-aware <= EPSS-first: 71/71 networks
  graph-aware <= both baselines: 71/71 networks
```

**How to read it.** After three patches the graph-aware plan has removed all residual risk
*on the retained baseline paths*; CVSS-first still carries 18.6 % and EPSS-first 60.4 %.
It is at least as good as both on every network.

**These numbers are reproducible.** Run it twice, get the same answer — that is deliberate
and there is a test (`test_results_do_not_depend_on_pythonhashseed`) that enforces it. If
you ever see them move between runs, something is wrong.

**The honest caveat, which you should state before anyone asks.** The graph-aware planner
*directly optimises the same metric this table reports*, on the same model. So it is
**expected** to win, and the size of the margin does not transfer to real networks. §4.4
checks it against a metric the planner does not optimise. EPSS-first doing worst is not a
verdict on EPSS: EPSS predicts exploitation in the wild, not position in this network.

### 4.4 `reachability_check` — a metric the planner does not optimise

```bash
python -m scripts.reachability_check --seeds 100
```

After applying each plan's patches, it rebuilds the attack graph and searches for paths
again from scratch, so routes outside the 50 retained paths per crown jewel are counted
too. Takes about 11 seconds.

**Success looks like:**

```
71 networks with attack paths (29 skipped: no path to any crown jewel)
Mean crown jewels reachable before patching: 3.00
Baseline paths retained per crown jewel: k=50

strategy    | patches | fixed-path residual | re-discovered risk | jewels still reachable
------------+---------+---------------------+--------------------+-----------------------
graph-aware |       1 |                5.6% |              22.4% | 0.76
graph-aware |       5 |                0.0% |               0.0% | 0.00
CVSS-first  |       1 |               58.1% |              93.6% | 2.92
CVSS-first  |       5 |                5.1% |              20.7% | 0.68
EPSS-first  |       1 |               97.7% |              99.9% | 3.00
EPSS-first  |       5 |               31.4% |              67.8% | 2.20

Networks with every crown jewel unreachable after 5 patches:
  graph-aware: 71/71
  CVSS-first : 55/71
  EPSS-first : 19/71
```

**How to read it.** Two things. First, the graph-aware advantage survives on a metric it
was not optimised for: five patches cut off every crown jewel in all 71 networks. Second,
the fixed-path metric flatters a single patch: 5.6 % on the retained paths, but 22.4 % once
the graph is searched again. "0 % residual" in §4.3 means "every *retained* path is broken",
not "the crown jewels are unreachable".

### 4.5 `scale_experiment` — how cost grows with size and vulnerability density

```bash
python -m scripts.scale_experiment --seeds 20
```

Runs 300 networks: 10, 30, 60, 100 and 200 workstations (22–212 hosts) at vulnerability
rates 0.20, 0.35 and 0.50. For each configuration it prints mean hosts, attack-graph edges,
retained paths, the time for each stage, and residual risk after the first graph-aware
patch. Takes a few minutes.

The structural columns are deterministic. Timings depend on the machine — on the team
laptop (Core i3-1315U), the largest configuration (212 hosts, ~33,000 edges) took a mean of
643 ms end to end. Path discovery is capped at 50 paths per crown jewel, which is what keeps
it fast. Full table and caveats: `docs/EXPERIMENTS.md` §E5.

### 4.6 `app.py` — the interactive dashboard

```bash
streamlit run app.py
```

Opens `http://localhost:8501` in your browser. Press `Ctrl+C` in the terminal to stop.

**Success looks like:** a dark page titled *Enterprise Cyber Attack-Path Intelligence*,
with a **green banner** reading:

```
✓ Vulnerability data: 70 CVEs from NVD (snapshot 2026-10-20), 62 of them in
  CISA KEV (catalog 2026.10.21, 1754 entries)
```

> **If that banner is orange instead of green**, the data cache is missing and you are
> looking at ten illustrative hand-entered CVEs, not real data. Fix it with §5 before
> quoting any number from the screen. The banner exists precisely so this can never
> happen silently.

Below it, five metrics (Hosts 42, Knowledge-graph edges 235, Attack-graph edges 932, Crown
jewels 3, Attack paths kept 150) and five tabs:

| Tab | What to check |
|---|---|
| **Attack paths** | A left-to-right graph with the selected path highlighted **red**. Drag the "Highlight path rank" slider and watch the red route change. Colours: orange DMZ, blue corporate, purple servers, red data tier. |
| **Chokepoints** | A table of hosts ranked by risk flowing through them. |
| **Patch plan** | A line chart where the *graph-aware* line drops to zero faster than the *highest CVSS first* line. The dashboard compares these two only; the EPSS-first baseline is in the command-line scripts (§4.1, §4.3). |
| **Knowledge graph** | Node and edge counts by type — the schema that loads into Neo4j. |
| **Vulnerability data** | Every CVE with **our score**, **NVD score**, and an **agrees** column. The metric at the bottom must read **0**. |

The sidebar switches between the synthetic generator and **uploading your own nmap XML**.
Try uploading `tests/fixtures/lab_scan.xml`.

### 4.7 `export_graph` — Cypher for Neo4j

```bash
python -m scripts.export_graph --out graph.cypher
```

**Success looks like:**

```
Wrote graph.cypher: 370 statements, 42 hosts, 34 users
Load with:  cat graph.cypher | cypher-shell -u neo4j -p password
```

Add `--queries` to print example Cypher queries, or `--scan FILE.xml` to export a real
scan instead of a synthetic network. See §7 to actually load it.

---

## 5. Refreshing the vulnerability data

The repo ships with the data already cached (`data/nvd_cves.json`, `data/kev.json`,
`data/epss.json`), so **you do not need this to run anything**. Use it when you want
fresher data or have added CVEs to `data/cve_seeds.txt`.

> **Refreshing changes published results.** EPSS scores are updated daily and KEV grows,
> so after a refresh the EPSS-first numbers in `docs/EXPERIMENTS.md` will no longer
> reproduce exactly. Every mode of the script refreshes EPSS, including `--kev-only` and
> `--nvd-only`. Commit the old caches or note the new snapshot dates before quoting
> anything.

```bash
python -m scripts.fetch_feeds
```

Takes about 8 minutes. NVD rate-limits anonymous callers to 5 requests per 30 seconds and
there is no bulk-by-ID endpoint, so it paces itself at 6.5 s per CVE.

**Success looks like:**

```
EPSS: fetching scores for 70 CVEs
EPSS: received 70 score(s)
KEV: 1754 known-exploited vulnerabilities (catalog version 2026.10.21)
NVD: 70 CVEs, 6.5s apart, about 7.6 min (anonymous: 5 requests / 30s)
  ...
NVD: 70/70 cached in data/nvd_cves.json
```

Failures are reported and the cache is **merged**, not replaced — so re-running only
fetches what is missing. A few timeouts on a first run are normal; just run it again.

**Faster:** get a free API key from
[nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) (raises the limit to 50
requests per 30 s) and pass `--api-key YOUR_KEY`. Other flags: `--kev-only`, `--nvd-only`,
`--delay N`.

**To add CVEs:** put the IDs in `data/cve_seeds.txt`, re-run, then reference them from
`SERVICE_TEMPLATES` in `apg/catalog.py` if you want the synthetic generator to use them.

---

## 6. Analysing a real network you own

> ### Scan only machines you own
> Port scanning infrastructure you do not own or have written authorisation to test is
> unlawful in most jurisdictions, including under Pakistan's Prevention of Electronic
> Crimes Act 2016. Never scan a university, employer, or public network. A virtual machine
> on a **host-only** adapter is the correct target and carries no risk to anyone.

### Build a lab

1. Install VirtualBox (or UTM on Apple Silicon).
2. Download **Metasploitable 2** — a VM built deliberately full of old, real
   vulnerabilities. Optionally add a Windows Server evaluation VM with SMBv1 enabled,
   which gives you EternalBlue and PrintNightmare and exercises the credential-reuse side
   of the model.
3. Set the network adapter to **Host-only**. Not NAT, not Bridged. Host-only means the VM
   can talk to your machine and nothing else — no packet reaches your real network.
4. Boot it and note its IP (`ifconfig` inside the VM, usually `192.168.56.x`).

### Scan and analyse

```bash
brew install nmap          # Linux: sudo apt install nmap  |  Windows: nmap.org/download

mkdir -p scans
nmap -sV --script vulners -oX scans/lab.xml 192.168.56.0/24

python -m scripts.import_scan scans/lab.xml --zone 192.168.56.0/24=dmz
```

- `-sV` — probe each open port to identify the software and version. **Required**: without
  it there is nothing to match CVEs against.
- `--script vulners` — the NSE script that reports CVE IDs. **Required**, or the attack
  graph will be empty (and the tool will tell you so).
- `-oX` — XML output, which is what the parser reads.

`scans/*.xml` is gitignored, so your scan output stays out of the repo. To keep a scan as
evidence — as was done for the Metasploitable scan — copy it into `evidence/` and commit
it together with the importer's output and the exact command used.

### Making the model match reality

The importer's defaults are deliberately pessimistic. Tighten them with:

| Flag | Why |
|---|---|
| `--zone 192.168.56.0/24=dmz` | Without a zone map, every /24 becomes its own zone and reachability between them is *assumed* open. Repeat per subnet. |
| `--criticality db-01=10` | nmap cannot know what the business cares about. Nothing is a crown jewel until criticality ≥ 8. |
| `--role 192.168.56.11=web` | Overrides port-based role guessing. |
| `--vantage dmz` | Which zone you scanned *from*. Changes what counts as measured versus assumed. |

**Best practice — scan from more than one place.** A single scan can only measure what the
scanner could reach from where it stood; everything else is assumed. Scan again from
inside another zone and pass both, and each contributes a *measured* row:

```bash
python -m scripts.import_scan scans/outside.xml=internet scans/dmz.xml=dmz \
    --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers
```

The warning about assumed reachability disappears, replaced by
`Reachability measured from 2 vantage point(s)`.

### If nmap finds CVEs we cannot score

You will see:

```
! 416 CVE(s) reported by nmap are not in the local catalog and were dropped: CVE-2006-20001, ...
```

That is the real Metasploitable result. Add the IDs you need to `data/cve_seeds.txt`, run
`python -m scripts.fetch_feeds`, and re-run the import — this is how CVE-2011-2523 was
added. They are dropped rather than guessed at because an unscoreable CVE would otherwise
become a silent zero-probability edge and hide a real attack path. A dropped CVE is
unknown to the model, not judged safe.

---

## 7. Loading the graph into Neo4j

Optional — the analysis runs entirely in memory via NetworkX and needs no database. This
is for demonstrating the knowledge-graph schema and cross-checking results in Cypher.

```bash
# 1. Start Neo4j
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
    -e NEO4J_AUTH=neo4j/testpassword neo4j:5

# 2. Export and load
python -m scripts.export_graph --out graph.cypher
cat graph.cypher | docker exec -i neo4j cypher-shell -u neo4j -p testpassword

# 3. Browse at http://localhost:7474
```

Every write is a `MERGE`, so loading twice gives one copy, not two — safe to re-run from a
nightly scan. Uniqueness constraints are created first; without them `MERGE` does a full
label scan and large estates degrade badly.

`python -m scripts.export_graph --queries` prints ready-made queries: internet-exposed
hosts, crown jewels and their CVEs, the KEV working list, shortest zone-to-zone routes,
and which user's credentials bridge the most hosts.

---

## 8. Troubleshooting

**`ModuleNotFoundError: No module named 'apg'` / `'networkx'`**
The virtual environment is not active, or you are not in the repo root. Run
`source .venv/bin/activate` from inside the `FYP` directory. Your prompt should show
`(.venv)`.

**`python: command not found`**
Use `python3`. On Windows use `python`.

**Tests fail on `test_catalog_came_from_the_feed_not_the_fallback`**
The data cache is missing or corrupted, so the code fell back to ten hand-entered CVEs.
Run `python -m scripts.fetch_feeds`. This test exists to stop you demoing illustrative
numbers believing they are real.

**Tests fail on `test_matches_nvd_published_score`**
Our CVSS calculator disagrees with NVD for some CVE. Either `apg/cvss.py` has a genuine
bug, or NVD rescored that CVE since the cache was taken (it happens — NVD rescored
EternalBlue from 8.1 to 8.8). Check the failing vector at
`https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX`. If NVD changed, re-run
`scripts.fetch_feeds`.

**Results change between runs of `compare_seeds`**
They should not — this is a bug. Run `python -m pytest -k pythonhashseed` and report it.

**`KeyError: ... is not in the catalog`**
A network names a CVE the catalog does not have. The message tells you the fix: add it to
`data/cve_seeds.txt` and re-run `scripts.fetch_feeds`, or filter it on import.

**The dashboard shows an orange banner instead of green**
The data cache is missing. See §5. Do not quote numbers from an orange-bannered dashboard.

**`streamlit: command not found`**
Dependencies are not installed, or the venv is not active. Re-run
`pip install -r requirements.txt`.

**Dashboard port already in use**
`streamlit run app.py --server.port 8502`

**`scripts.fetch_feeds` fails with HTTP 403**
NVD rate limiting. The script backs off and continues; failures are listed at the end and
the cache merges, so just run it again. Or use `--api-key`.

**nmap reports no CVEs**
You omitted `--script vulners`, or the script is not installed. Confirm with
`nmap --script-help vulners`.

**Everything still broken**
Delete and rebuild the environment — it is disposable:
```bash
rm -rf .venv && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```
