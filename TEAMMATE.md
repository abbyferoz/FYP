# Start here — handover for Rayyan

Everything in this repo runs offline. No API keys, no database, no Docker. You should be
from clone to a working dashboard in about five minutes.

---

## 1. Get it running

```bash
git clone https://github.com/abbyferoz/FYP.git
cd FYP

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Branches.** `main` is the live trunk — work here. `milestone-1` is a frozen snapshot of
exactly what we submitted for M1; leave it alone so we can always show the jury the state
the proposal describes. `git checkout milestone-1` to look at it, but commit to `main`.

You need Python 3.10 or newer (`python3 --version`). On a fresh Mac:
`xcode-select --install`, then Homebrew, then `brew install python@3.12 git`.

Now check it works, in this order:

```bash
python -m pytest -q                            # expect: 128 passed
python -m scripts.run_demo                     # attack paths, chokepoints, patch ranking
python -m scripts.compare_seeds --seeds 100    # graph-aware vs highest-CVSS-first
streamlit run app.py                           # dashboard, opens a browser tab
```

The vulnerability data (69 real CVEs from NVD, cross-referenced with the CISA KEV
catalog) is committed under `data/`, which is why none of this needs internet. To refresh
it from the live feeds later: `python -m scripts.fetch_feeds` (about 8 minutes — NVD
rate-limits anonymous callers to 5 requests per 30 seconds).

**If `pytest` fails**, the most likely cause is a missing or corrupted data cache. The
test `test_catalog_came_from_the_feed_not_the_fallback` exists specifically to catch
that — it fails loudly rather than letting you demo illustrative numbers believing they
are real. Re-run `python -m scripts.fetch_feeds` and try again.

### Try it on scan data without a lab

```bash
python -m scripts.import_scan tests/fixtures/lab_scan.xml \
    --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data
```

This is the single most persuasive output in the project. It shows the severity-first
plan spending four patches on 9.8- and 10.0-rated CVEs and breaking **zero** paths to the
database, while the graph-aware plan breaks all five with one 8.8-rated patch. That is
the entire argument for the project, on one screen.

---

## 2. Read these, in this order

| | |
|---|---|
| `README.md` | What it is, how it works, results, limitations |
| `docs/WALKTHROUGH.md` | **The important one.** Module by module: what it does, why it is built that way, likely jury questions, and a modification to rehearse for each |
| `PROPOSAL.md` | The M1 written proposal |
| `CHANGELOG.md` | Development log and the AI-tool disclosure the FYP policy requires |

`docs/WALKTHROUGH.md` was written specifically because the M2 viva picks a component and
asks each of us to explain or modify it **unaided**. Work through it with the source open.
There is a rehearsal checklist at the end.

---

## 3. What is already done

- CVSS v3.1 calculator, validated against NVD — our computed scores match NVD's published
  base scores on **69 of 69** cached CVEs.
- Real NVD + CISA KEV ingestion (62 of our 69 CVEs are known-exploited, 44 ransomware-linked).
- Seeded synthetic network generator; derived attack graph with exploit and
  credential-reuse edges.
- Top-k attack paths (Yen's algorithm), chokepoint analysis, patch prioritisation.
- Real `nmap -oX` parsing, including multi-vantage-point scan merging.
- Neo4j Cypher export (idempotent, `MERGE`-based).
- Streamlit + PyVis dashboard.
- 128 tests.

---

## 4. What still needs doing

### 4.1 Run a real scan against a lab VM — **yours, and the highest priority**

This is the one gap that matters for M1. The parser is finished and tested, but the test
fixtures under `tests/fixtures/` were **hand-built to mirror real nmap output — no host
was actually scanned to produce them**. The M1 brief asks for a working technical
demonstrator, and real scan input is what separates that from a simulation.

You own this one — it is squarely the Information Security half of the project.

Rough shape:

1. VirtualBox or UTM, with a **host-only** adapter (not bridged, not NAT).
2. Metasploitable 2 is the standard target and is deliberately full of real, old CVEs.
   A Windows Server evaluation VM with SMBv1 enabled gives you EternalBlue and
   PrintNightmare, which exercises the credential-reuse side of the model.
3. `brew install nmap`, then install the `vulners` NSE script (it is what reports CVE IDs;
   without it the importer will warn that it found no CVEs and the attack graph will be
   empty — that warning is deliberate, not a bug).
4. Scan:
   ```bash
   nmap -sV --script vulners -oX scans/lab.xml 192.168.56.0/24
   python -m scripts.import_scan scans/lab.xml --zone 192.168.56.0/24=dmz
   ```
5. Any CVE nmap reports that is not in our catalog gets dropped **and reported** in the
   warnings. Add those IDs to `data/cve_seeds.txt`, re-run `python -m scripts.fetch_feeds`,
   and re-run the import.
6. Scanning from a second vantage point (e.g. from inside the DMZ VM) turns assumed
   reachability into measured reachability — see `merge_scans()` and §8 of the walkthrough.

> **Only scan machines we own, on a host-only adapter.** Never the university network,
> never an employer's, never anything else. Pakistan's PECA 2016 applies, and this would
> end the project.

`scans/*.xml` is gitignored so your scan output stays out of the repo. Commit a small
sanitised one if we want it as evidence in the report.

### 4.2 Fill in your half of the AI disclosure — **yours**

`CHANGELOG.md` has `_(fill in)_` markers. The FYP policy (booklet §0.3) requires an
"AI Tools Used" paragraph in every deliverable, stating which tools did what and roughly
how much. The entries currently there were inferred from the project history, not from
what either of us actually remembers doing.

Correct them: what did you write, change, reject or debug yourself? Be specific about the
Session 2 (Cowork) work, because that session is where the modelling assumptions in
PROPOSAL §5 were established, and those assumptions are the intellectual core of the
project. An accurate modest disclosure beats an inaccurate flattering one — and the viva
tests understanding directly anyway.

### 4.3 Reformat the proposal onto the department template — **either of us**

`PROPOSAL.md` is written to map onto the department's template section by section, but it
is Markdown, not the template. Get the template from the booklet's linked repository
(title page pattern is in §0.5.2) and move the content across.

### 4.4 Rehearse `docs/WALKTHROUGH.md` — **both of us, separately**

M2 grades us individually. The jury picks a component and asks you to explain or modify
it with no tool assistance. The checklist at the end of the walkthrough is the bar:

- Trace one attack path back to the CVEs and firewall rules that created it.
- Compute a CVSS base score by hand and match the code.
- Explain why Heartbleed creates no attack-graph edge despite scoring 7.5.
- Add a zone to the generator and show the paths change.
- Explain the `−ln p` transform and why Yen's algorithm applies.
- Explain why iterating a Python set broke reproducibility.

---

## 5. One thing to know before you present it

The headline result — graph-aware patching reaching 0% residual risk in 3 patches against
18.6% for highest-CVSS-first, winning or tying on 71 of 71 networks — has a deliberate
weak point, and it is documented rather than hidden (PROPOSAL §6.6, and captioned in the
dashboard).

**The greedy planner directly optimises the same residual-risk metric the comparison then
reports, on the same model. So it is *expected* to win.** The table demonstrates that the
implementation works; it does not establish that the margin generalises to real networks.

The defensible claim is narrower: reachability-aware ordering beats severity-only
ordering on this model, and the mechanism by which it does so (§4.1 above — a 10.0 CVE
that sits on no path contributes nothing, while the one 8.8 on the target is everything)
is a mechanism that genuinely occurs in real networks.

**Say this before a jury member finds it.** Volunteering a limitation reads as rigour;
conceding it under questioning reads as overselling. Establishing a real effect size, with
stronger baselines (CVSS+KEV, EPSS, internet-facing-first), is exactly what M4's
real-conditions validation is for.

---

## 6. Division of work from here

Per PROPOSAL §7:

- **Rayyan** — threat model, lab environment, scan collection, security correctness of the
  modelling assumptions.
- **Abdullah** — graph algorithms, scoring and remediation optimisation, data pipeline,
  and the Term 2 GNN work.

Both of us review each other's modules, because M2 examines each of us on any component.

## 7. Working on it

```bash
git checkout main
git pull
# ... make changes ...
python -m pytest -q          # must stay at 128 passing (add tests as you add code)
git add -A && git commit -m "describe what changed"
git push
```

Never commit to `milestone-1`. It is the M1 submission snapshot. If we need to correct
something in what was submitted, we talk about it first.

For anything larger than a small fix, branch off `main` (`git checkout -b lab-scans`) and
merge back, so `main` always runs.

`CLAUDE.md` holds the working rules if you use Claude Code on this — most importantly:
never hand-type a CVSS vector (add the CVE to `data/cve_seeds.txt` and refetch instead).
A hand-typed vector was wrong once already: EternalBlue was entered as 8.1 where NVD
scores it 8.8, and the hand-written test agreed with the hand-written vector, so nothing
caught it until we switched to real data.
