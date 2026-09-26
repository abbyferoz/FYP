# Running and testing everything

Complete instructions for any machine, with the output each command should produce so
you can tell success from failure without guessing.

**Contents**
1. [Requirements](#1-requirements)
2. [Install](#2-install) — macOS, Linux, Windows
3. [Verify the install](#3-verify-the-install)
4. [The five things you can run](#4-the-five-things-you-can-run)
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
........................................................................ [ 56%]
........................................................                 [100%]
128 passed in 0.76s
```

128 passing is the only acceptable result. If anything fails, go to §8.

The most important test in that run is `test_matches_nvd_published_score`: it takes every
one of the 69 CVEs in the local cache, recomputes the CVSS base score from the vector
string using our own calculator, and asserts it equals the score NVD published. Those are
69 ground truths produced by someone else, so passing means the scoring engine is
genuinely correct rather than merely self-consistent.

---

## 4. The five things you can run

### 4.1 `run_demo` — the whole engine on a synthetic network

```bash
python -m scripts.run_demo
```

Generates a 42-host enterprise network, derives the attack graph, finds paths to the
crown jewels, identifies chokepoints, and compares two patching strategies.

**Success looks like** (abridged — the real output is ~56 lines):

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

== Graph-aware greedy plan vs highest-CVSS-first
  n=1  greedy:   0.0% / 150   cvss-first:  23.9% / 115
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
- The last block is the headline comparison. Read §4.3.

Useful flags: `--seed 12` (different network), `--workstations 60`, `--vuln-rate 0.5`,
`--patches 8`. The same seed always produces the same network.

### 4.2 `import_scan` — the same engine on real scan data

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz \
    --zone 192.168.57.0/24=servers \
    --zone 192.168.58.0/24=data
```

**This is the most persuasive output in the project.** It runs on `nmap -oX` output
instead of a simulation — the engine is identical, only the input differs.

**Success looks like:**

```
Parsed tests/fixtures/lab_scan.xml: 3 hosts up, vantage 'internet'
Catalog: 69 CVEs from NVD (snapshot 2026-09-22), 62 of them in CISA KEV

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

== Graph-aware plan vs highest-CVSS-first (residual risk as % of baseline)
  n=1  graph-aware:   0.0% / broke   5   cvss-first: 100.0% / broke   0
  n=4  graph-aware:   0.0% / broke   5   cvss-first:  78.3% / broke   0
```

**Why this matters.** Severity-first patching spends its first four patches on CVEs rated
9.8 and 10.0 — Zerologon, Log4Shell, BlueKeep — and breaks **zero** paths to the database.
The graph-aware plan breaks all five with one patch rated 8.8, because that 8.8 sits on
the database itself and every path must pass through it. A 10.0 that lies on no path to
anything valuable contributes nothing to real risk. That is the entire thesis of the
project, visible in one screen.

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

### 4.3 `compare_seeds` — does the approach hold up across many networks?

```bash
python -m scripts.compare_seeds --seeds 100
```

Builds 100 different networks and runs both patching strategies on each. Takes ~6 seconds.

**Success looks like:**

```
71 networks with attack paths (29 skipped: no path to any crown jewel)
n patches | graph-aware greedy | highest-CVSS first   (mean residual risk, % of baseline)
    1     |          5.6%      |        58.1%
    2     |          0.4%      |        36.2%
    3     |          0.0%      |        18.6%
    4     |          0.0%      |        10.6%
    5     |          0.0%      |         5.1%
graph-aware <= CVSS-first after 5 patches on 71/71 networks
```

**How to read it.** After three patches the graph-aware plan has removed *all* measurable
risk; severity-first still carries 18.6%. It wins or ties on every single network.

**These numbers are reproducible.** Run it twice, get the same answer — that is deliberate
and there is a test (`test_results_do_not_depend_on_pythonhashseed`) that enforces it. If
you ever see them move between runs, something is wrong.

**The honest caveat, which you should state before anyone asks.** The graph-aware planner
*directly optimises the same metric this table reports*, on the same model. So it is
**expected** to win, and the size of the margin does not transfer to real networks. What
the table legitimately shows is that the implementation works. What §4.2 shows — the
mechanism, a high-severity CVE that lies on no path being worthless to patch — is the part
that genuinely occurs in real estates. Establishing a real effect size needs scan data at
scale and stronger baselines (CVSS+KEV, EPSS, internet-facing-first).

### 4.4 `app.py` — the interactive dashboard

```bash
streamlit run app.py
```

Opens `http://localhost:8501` in your browser. Press `Ctrl+C` in the terminal to stop.

**Success looks like:** a dark page titled *Enterprise Cyber Attack-Path Intelligence*,
with a **green banner** reading:

```
✓ Vulnerability data: 69 CVEs from NVD (snapshot 2026-09-22), 62 of them in
  CISA KEV (catalog 2026.09.21, 1717 entries)
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
| **Patch plan** | A line chart where the *graph-aware* line drops to zero faster than the *highest CVSS first* line. This is the money shot. |
| **Knowledge graph** | Node and edge counts by type — the schema that loads into Neo4j. |
| **Vulnerability data** | Every CVE with **our score**, **NVD score**, and an **agrees** column. The metric at the bottom must read **0**. |

The sidebar switches between the synthetic generator and **uploading your own nmap XML**.
Try uploading `tests/fixtures/lab_scan.xml`.

### 4.5 `export_graph` — Cypher for Neo4j

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

The repo ships with the data already cached (`data/nvd_cves.json`, `data/kev.json`), so
**you do not need this to run anything**. Use it when you want fresher data or have added
CVEs to `data/cve_seeds.txt`.

```bash
python -m scripts.fetch_feeds
```

Takes about 8 minutes. NVD rate-limits anonymous callers to 5 requests per 30 seconds and
there is no bulk-by-ID endpoint, so it paces itself at 6.5 s per CVE.

**Success looks like:**

```
KEV: 1717 known-exploited vulnerabilities (catalog version 2026.09.21)
NVD: 69 CVEs, 6.5s apart, about 7.5 min (anonymous: 5 requests / 30s)
  [  1/69] CVE-2021-44228  base=10.0  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  ...
NVD: 69/69 cached in data/nvd_cves.json (42 KB)
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

`scans/*.xml` is gitignored, so your scan output stays out of the repo.

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
! 3 CVE(s) reported by nmap are not in the local catalog and were dropped: CVE-2011-2523, ...
```

Add those IDs to `data/cve_seeds.txt`, run `python -m scripts.fetch_feeds`, re-run the
import. They are dropped rather than guessed at because an unscoreable CVE would otherwise
become a silent zero-probability edge and hide a real attack path.

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
