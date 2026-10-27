# Experiments and Evidence

This file is the single source of truth for every result quoted in the proposal, report,
README and defence slides. If a number appears anywhere else, it should come from here.

Code version: branch `feature/scalability-experiments` at commit `e51e37d`. The engine code is
unchanged since `c171606`; later commits add the real-scan evidence,
`scripts/reachability_check.py`, tests and documentation.

## 0. Five kinds of evidence — never merge them

| # | Evidence | Input | What it can show | What it cannot show |
|---|---|---|---|---|
| E1 | Synthetic demo (seed 7) | `generate_network(7)` | How the method behaves on one network | Anything general |
| E2 | Hand-built nmap fixtures | `tests/fixtures/*.xml` | The parser and importer handle realistic XML | Anything about a real host: **no host was scanned** to produce them |
| E3 | Real Metasploitable 2 scan | `evidence/real_scan/metasploitable-vulners.xml` | The pipeline runs end to end on genuine scanner output | Multi-hop paths, strategy comparison, enterprise accuracy |
| E4 | Multi-seed remediation comparison | 100 generated networks | How the strategies compare across many synthetic networks | Real-world breach reduction |
| E5 | Scalability experiment | 300 generated networks | Runtime and graph size at the tested scale | Unbounded or enterprise-scale performance |

The "one 8.8-rated patch breaks all five paths while severity-first breaks none" result
comes from **E2** (`tests/fixtures/lab_scan.xml`), a hand-built fixture. It must not be
described as real scan data.

## Feed snapshots (shared by all experiments)

| Feed | Snapshot | Count | File |
|---|---|---|---|
| NVD CVE records | fetched 2026-10-20 19:26 UTC | 70 CVEs (0 failed, 0 without CVSS v3) | `data/nvd_cves.json` |
| CISA KEV | catalogue 2026.10.21, fetched 2026-10-21 18:49 UTC | 1,754 entries; 62 of our 70 CVEs listed | `data/kev.json` |
| FIRST EPSS | fetched 2026-10-21 18:49 UTC | 70 scores | `data/epss.json` |

EPSS scores change daily. Re-fetching the feeds will change the EPSS-first rankings, so these
cached files are part of the experimental record and must not be overwritten before the
defence.

## Shared definitions

- **Edge probability (exploit):** `min(0.99, ExploitabilitySubscore / 3.9 × (1.25 if KEV))`.
  This is a modelling heuristic, not a calibrated probability.
- **Edge probability (credential reuse):** fixed at 0.5. Synthetic networks only.
- **Path probability:** product of edge probabilities, which assumes the steps are independent.
- **Path risk:** path probability × criticality of the target (1–10).
- **Baseline paths:** the top-k most probable simple paths (Yen's algorithm on −ln p) from
  `internet` to each crown jewel (criticality ≥ 8) on the unpatched network. Default k = 50.
- **Fixed-path residual risk:** sum over the baseline paths of (path probability with the plan's
  patches applied × criticality), reported as a percentage of the unpatched value.
- **Re-discovered risk:** after patching, rebuild the attack graph and search again from
  scratch. Sum over crown jewels of (probability of the best surviving path × criticality), as
  a percentage of the unpatched value. The planner does **not** optimise this metric.
- **Usable network:** a generated network with at least one path to a crown jewel. Networks
  without one are skipped because residual risk as a percentage of zero is undefined.
- **Strategies:**
  - *Graph-aware:* `greedy_plan`. Repeatedly picks the patch that most lowers fixed-path
    residual risk.
  - *CVSS-first:* `cvss_plan`. Highest CVSS base score first, over every finding in the network.
  - *EPSS-first:* `epss_plan`. Highest EPSS score first, over every finding in the network.

## E1 — Synthetic demo, seed 7

```
python -m scripts.run_demo
```

Default network: 30 workstations, vulnerability rate 0.35, 42 hosts. 150 baseline paths
(50 per crown jewel: db-01, db-02, dc-01).

| First patch | Strategy | CVSS | EPSS | Fixed-path residual | Paths broken |
|---|---|---:|---:|---:|---:|
| CVE-2022-22965 on app-03 | graph-aware | 9.8 | 0.9964 | 0.0% | 150/150 |
| CVE-2020-0796 on fileserver-01 | CVSS-first | 10.0 | 0.9981 | 23.9% | 115/150 |
| CVE-2022-26134 on app-01 | EPSS-first | 9.8 | 1.0000 | 100.0% | 0/150 |

Independent check: after patching CVE-2022-22965 on app-03 and rebuilding the graph, all three
crown jewels are unreachable. In this network app-03 is a genuine cut, not an artefact of
the 50-path limit.

Limitation: this is one network, and it was chosen for illustration. E4 is the general result.

## E2 — Hand-built nmap fixtures

```
python -m pytest tests/test_nmap_import.py -q
python -m scripts.import_scan tests/fixtures/lab_scan.xml --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data
```

`lab_scan.xml`, `dmz_scan.xml` and `metasploitable.xml` were written by hand to mirror nmap
7.94 output. They test parsing, role inference, warnings, zone mapping and multi-vantage
merging. `tests/fixtures/metasploitable.xml` is a mock with no CVEs. It is **not** the real
scan in E3.

## E3 — Real Metasploitable 2 lab scan

Lab: VirtualBox, Kali Linux (192.168.56.101), Metasploitable 2 (192.168.56.102), host-only
network. Run on 20 October 2026.

```
# on Kali
nmap -sV --script vulners -oX metasploitable-vulners.xml 192.168.56.102
# in the project
python -m scripts.import_scan evidence\real_scan\metasploitable-vulners.xml --criticality 192.168.56.102=9
```

Saved output: `evidence/real_scan/import-output.txt`.

| Quantity | Value |
|---|---|
| Hosts up | 1 |
| Open TCP ports | 23 |
| CVE identifiers reported by nmap/vulners | 417 |
| CVEs in local catalogue (retained) | 1: CVE-2011-2523 (vsftpd 2.3.4 backdoor; EPSS 0.9618) |
| CVEs dropped (not in catalogue) | 416 |
| Inferred role | `db` (MySQL 3306 / PostgreSQL 5432 open) |
| Criticality | 9 (equal to the default for role `db`; also passed explicitly) |
| Attack graph | 2 nodes, 1 edge |
| Paths | 1: `internet → 192.168.56.102`, p = 0.990, risk = 8.91 |
| Best single patch | CVE-2011-2523 → residual 0.00, 1/1 paths broken |
| Strategy comparison at n = 1 | all three strategies identical (0.0%) |

Provenance recorded for the path step:
`[OBSERVED]` TCP/21 open → `[OBSERVED]` vsftpd 2.3.4 → `[CORRELATED]` CVE-2011-2523 via
vulners → `[INFERRED]` foothold → `[INFERRED]` p = 0.990.

What it shows: the full pipeline (parse → enrich → catalogue join → attack graph → path →
provenance → remediation) runs on genuine scanner output.

What it does not show:
- Multi-hop paths. There is one host and one edge.
- Any difference between strategies. Only one finding is modelled, so every strategy picks it.
- Exploitability. The exploit was not executed. The CVE is a version-based correlation.
- Role correctness. "db" is a port heuristic, and Metasploitable is a deliberately vulnerable
  general-purpose VM.

It also exposed a real limitation. Before CVE-2011-2523 was added to `data/cve_seeds.txt`,
none of the 417 identifiers were in the 69-CVE catalogue, so no attack edge was produced. The
416 dropped CVEs are reported as a warning. They are unknown to the model, not judged safe.

## E4 — Multi-seed remediation comparison

```
python -m scripts.compare_seeds --seeds 100
python -m scripts.reachability_check --seeds 100
```

Parameters: seeds 0–99; 30 workstations; vulnerability rate 0.35; k = 50 paths per crown
jewel; patch budget n = 5. Results are deterministic: identical output under different
`PYTHONHASHSEED` values. 71 networks usable; 29 skipped (no path to a crown jewel).

### E4a — Fixed-path residual risk (the metric the planner optimises)

| Patches | Graph-aware | CVSS-first | EPSS-first |
|---:|---:|---:|---:|
| 1 | 5.6% | 58.1% | 97.7% |
| 2 | 0.4% | 36.2% | 82.4% |
| 3 | 0.0% | 18.6% | 60.4% |
| 4 | 0.0% | 10.6% | 43.7% |
| 5 | 0.0% | 5.1% | 31.4% |

After 5 patches, graph-aware was less than or equal to CVSS-first in 71/71 networks, to
EPSS-first in 71/71, and to both in 71/71.

### E4b — Re-discovered risk and reachability (a metric the planner does not optimise)

| Strategy | Patches | Fixed-path residual | Re-discovered risk | Crown jewels still reachable (of 3) |
|---|---:|---:|---:|---:|
| Graph-aware | 1 | 5.6% | 22.4% | 0.76 |
| Graph-aware | 5 | 0.0% | 0.0% | 0.00 |
| CVSS-first | 1 | 58.1% | 93.6% | 2.92 |
| CVSS-first | 5 | 5.1% | 20.7% | 0.68 |
| EPSS-first | 1 | 97.7% | 99.9% | 3.00 |
| EPSS-first | 5 | 31.4% | 67.8% | 2.20 |

Networks with **every** crown jewel unreachable after 5 patches: graph-aware 71/71,
CVSS-first 55/71, EPSS-first 19/71.

### Interpretation

1. E4a is partly expected by design: the greedy planner minimises exactly the quantity it is
   scored on.
2. E4b is the stronger result. Measured by rebuilding the graph rather than by the fixed path
   set, five graph-aware patches disconnected every crown jewel in all 71 networks. The
   score-only baselines did so in 55 and 19.
3. The fixed-path metric understates residual risk after a single patch: 5.6% fixed-path
   versus 22.4% re-discovered. The top-50 paths concentrate around one chokepoint, so
   alternative routes are not in the retained set. Fixed-path "0%" after one patch must
   therefore not be read as "the crown jewels are cut off".
4. EPSS-first performs worst because it ranks findings anywhere in the network, many of them
   on hosts that no retained path uses. This says nothing about EPSS as a predictor of
   exploitation. EPSS answers a different question.
5. All of this is within our generator and modelling assumptions. It is not evidence of
   real-world breach reduction.

Earlier figures: a 30-seed run (23 usable networks) gave 5.8 / 1.0 / 0.0 / 0.0 / 0.0% for
graph-aware, 56.2 / 37.1 / 13.3 / 4.5 / 2.8% for CVSS-first and 97.4 / 83.6 / 58.5 / 39.9 /
32.2% for EPSS-first. Its conclusions are the same, but quote the 100-seed run.

## E5 — Scalability and vulnerability density

```
python -m scripts.scale_experiment --seeds 20
```

Parameters: workstations ∈ {10, 30, 60, 100, 200}; vulnerability rate ∈ {0.20, 0.35, 0.50};
20 seeds per configuration (300 networks); k = 50 (maximum 150 retained paths); graph-aware
plan of 5 patches (default `--patches 5`), of which "Risk after 1 patch" reports the first
step. Total hosts = workstations + 12 servers.

Timing columns: *Graph ms* is attack-graph construction; *Path ms* is path discovery for
all crown jewels; *Remed ms* is the 5-patch greedy plan (zero for networks with no path,
which are included in the mean); *Total ms* is end to end including network generation.

The structural columns (hosts, edges, paths, risk after one patch, usable networks) are
deterministic. They were reproduced exactly on a second machine. Timings depend on hardware
and vary between runs.

Timings below: team laptop, Windows, Python 3.12.10, 13th Gen Intel(R) Core(TM) i3-1315U, run on
22 October 2026.

| Workstations | Vuln. rate | Mean hosts | Mean edges | Mean paths | Graph ms | Path ms | Remed. ms | Total ms | Risk after 1 patch | Usable |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.20 | 22 | 174.9 | 64.1 | 0.88 | 10.36 | 4.96 | 16.64 | 2.8% | 9/20 |
| 10 | 0.35 | 22 | 222.1 | 112.5 | 1.09 | 19.29 | 15.68 | 36.69 | 7.4% | 15/20 |
| 10 | 0.50 | 22 | 270.1 | 135.0 | 1.53 | 22.87 | 29.11 | 54.23 | 22.8% | 18/20 |
| 30 | 0.20 | 42 | 676.7 | 62.5 | 2.88 | 19.61 | 8.24 | 31.21 | 2.5% | 9/20 |
| 30 | 0.35 | 42 | 940.8 | 112.5 | 4.32 | 40.41 | 27.22 | 72.63 | 7.2% | 15/20 |
| 30 | 0.50 | 42 | 1,153.5 | 135.0 | 5.36 | 48.37 | 37.85 | 92.36 | 23.0% | 18/20 |
| 60 | 0.20 | 72 | 1,953.5 | 57.5 | 8.11 | 35.96 | 11.25 | 55.85 | 3.8% | 8/20 |
| 60 | 0.35 | 72 | 2,835.8 | 107.5 | 12.87 | 67.85 | 36.90 | 118.48 | 8.7% | 15/20 |
| 60 | 0.50 | 72 | 3,620.4 | 135.0 | 16.99 | 90.81 | 44.09 | 152.74 | 23.2% | 18/20 |
| 100 | 0.20 | 112 | 4,785.8 | 65.0 | 20.79 | 70.65 | 18.34 | 110.52 | 3.6% | 9/20 |
| 100 | 0.35 | 112 | 6,980.1 | 110.0 | 32.43 | 140.55 | 47.59 | 221.52 | 8.1% | 15/20 |
| 100 | 0.50 | 112 | 9,009.1 | 135.0 | 54.81 | 179.30 | 51.24 | 286.58 | 23.8% | 18/20 |
| 200 | 0.20 | 212 | 16,476.1 | 65.0 | 90.33 | 181.47 | 28.60 | 302.30 | 2.6% | 9/20 |
| 200 | 0.35 | 212 | 25,056.9 | 110.0 | 159.74 | 354.59 | 48.22 | 564.04 | 9.3% | 15/20 |
| 200 | 0.50 | 212 | 33,010.2 | 135.0 | 250.73 | 341.64 | 48.84 | 642.85 | 23.5% | 18/20 |

Denominators: "Risk after 1 patch" averages over usable networks only. The other columns
average over all 20 networks in the configuration, so mean paths and mean remediation time
include networks that had no path at all.

On a 2-core cloud Linux container (Python 3.13, NetworkX 3.7), the same command gave a total
of 1,180 ms at 200 / 0.50. The structural columns were identical.

### Interpretation

- Cost grows with network size and vulnerability density, mainly through attack-graph edges
  (about 33,000 at the largest setting). Timings are not perfectly monotonic because each
  configuration generates different graphs.
- At the largest tested setting (212 hosts, about 33,010 edges), mean end-to-end analysis
  stayed under about 1.2 s on both machines. This shows practicality at the tested scale
  **with the path cap**. It does not show unbounded enterprise-scale performance, and it is
  not compared against other tools.
- Mean paths plateau at 135 because of the cap (k = 50 × 3 crown jewels). The cap is what
  keeps path discovery and remediation time bounded.
- At vulnerability rate 0.50, one graph-aware patch leaves about 23% fixed-path residual risk,
  compared with about 3–9% at lower densities. A plausible model-level reading is that denser
  vulnerability creates more alternative routes, so a single patch removes less. This is
  an observation about our generator, not a general law.

## Reproducing everything

```cmd
cd "C:\Users\Nazia Kashif\Desktop\Rayyan\fyp\fypgithub"
.venv\Scripts\activate.bat
python -m pytest -q
python -m scripts.run_demo
python -m scripts.compare_seeds --seeds 100
python -m scripts.reachability_check --seeds 100
python -m scripts.scale_experiment --seeds 20
python -m scripts.import_scan evidence\real_scan\metasploitable-vulners.xml --criticality 192.168.56.102=9
```

Do not run `scripts.fetch_feeds` before the defence. It would replace the snapshots above.
