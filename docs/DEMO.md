# Defence demo script

About 12 minutes of demo, followed by questions. Every command below runs offline in
a few seconds, except the scalability run, which you show from saved output. Every
number you will say is in `docs/EXPERIMENTS.md`.

The order follows the argument: **the mechanism on one network → the same engine on a
real scan → does it hold across many networks → does it hold on a metric we did not
optimise → does it scale → what it does not prove.**

---

## Before the day

**The night before**, on the laptop you will present from:

```cmd
cd "C:\Users\Nazia Kashif\Desktop\Rayyan\fyp\fypgithub"
.venv\Scripts\activate.bat
git checkout main
git pull
python -m pytest -q
```

Expect `146 passed`. Then save the fallback outputs (next section).

**Turn Wi-Fi off and run every command in this script once.** Nothing should need the
internet. If something does, you have found out a day early instead of in the room.

**Do not run `scripts.fetch_feeds`** between now and the defence. It replaces the cached
EPSS and KEV data, and the EPSS-first numbers would stop matching the report.

### Save fallback outputs

If anything fails live, open the saved file instead and keep talking. Run this once:

```cmd
mkdir evidence\demo_outputs
python -m scripts.run_demo > evidence\demo_outputs\1_run_demo.txt
python -m scripts.import_scan evidence\real_scan\metasploitable-vulners.xml --criticality 192.168.56.102=9 > evidence\demo_outputs\2_real_scan.txt
python -m scripts.import_scan tests\fixtures\lab_scan.xml --zone 192.168.56.0/24=dmz --zone 192.168.57.0/24=servers --zone 192.168.58.0/24=data > evidence\demo_outputs\3_fixture.txt
python -m scripts.compare_seeds --seeds 100 > evidence\demo_outputs\4_compare_seeds.txt
python -m scripts.reachability_check --seeds 100 > evidence\demo_outputs\5_reachability.txt
python -m scripts.scale_experiment --seeds 20 > evidence\demo_outputs\6_scale.txt
python -m pytest -q > evidence\demo_outputs\0_tests.txt
```

The scale run takes a few minutes. Check that `4_compare_seeds.txt` ends with `71/71` and
`5_reachability.txt` with `71/71`, `55/71` and `19/71`. Then commit the folder, so the
outputs are also on GitHub if the laptop fails:

```cmd
git add evidence\demo_outputs
git commit -m "Save demo fallback outputs"
git push
```

### 30 minutes before

- Laptop charged and plugged in. Notifications off. Close everything else.
- Command Prompt maximised, font large (right-click the title bar → Properties → Font,
  size 20 or more). The scan output has long lines, so make the window wide.
- Activate the environment and `cd` into the project.
- Start the dashboard now, in a **second** Command Prompt, because its first launch is slow:
  `streamlit run app.py`. Leave the browser tab open on it.
- Open `docs\EXPERIMENTS.md` and `evidence\demo_outputs\6_scale.txt` in a viewer, ready to
  show.
- Between steps, type `cls` to clear the screen so the examiners only see the current output.

---

## Step 1 — The problem (30 seconds, no command)

> "Scanners find more vulnerabilities than any team can patch, so teams sort by CVSS
> severity. But CVSS scores a vulnerability on its own, and an attacker uses a chain. Our
> question is: given a network, which patches cut the most routes to the assets that
> matter — and how does that compare with patching by CVSS or by EPSS?"

## Step 2 — One synthetic network, end to end (2½ minutes)

```cmd
python -m scripts.run_demo
```

Scroll as you talk. Point at, in order:

1. **First line.** "42 hosts, 34 users, an attack graph of 932 edges. Three crown jewels:
   two databases and the domain controller. The network is generated from seed 7, so it is
   identical every time."
2. **A path.** "This is the most probable route to `db-01`: Log4Shell on the web server,
   Spring4Shell on `app-03`, SMBGhost on the file server, then reusing the domain admin's
   credentials. Probability 0.485 — the product of the step probabilities."
3. **Chokepoints.** "`app-03` sits on all 150 retained paths."
4. **Remediation comparison, n=1.** This is the key moment:

   > "Graph-aware patches Spring4Shell on `app-03` — CVSS 9.8 — and breaks all 150 paths.
   > CVSS-first patches a 10.0 on the file server and breaks 115. EPSS-first patches a CVE
   > with EPSS 1.0 on `app-01`, which is on none of these paths, so it breaks nothing.
   > Same network, same budget of one patch: what matters is *where* the vulnerability is."

5. **Say this before anyone asks:**

   > "One network proves nothing general — this one was chosen to illustrate. We did check
   > that it is real, though: if you rebuild the graph after that patch, all three crown
   > jewels are unreachable. And EPSS doing badly here is not a criticism of EPSS — it
   > predicts exploitation in the wild, not position in our network."

## Step 3 — The same engine on a real scan (2 minutes)

```cmd
cls
python -m scripts.import_scan evidence\real_scan\metasploitable-vulners.xml --criticality 192.168.56.102=9
```

> "This is a real scan: nmap with the vulners script, against a Metasploitable 2 VM on a
> host-only network in our lab. The XML is committed in the repository."

Point at:

1. **The imported host.** "23 open ports. Our importer guessed the role `db` from the MySQL
   and PostgreSQL ports."
2. **The warnings.** "416 CVEs were dropped — vulners reported 417, and our catalog had only
   one of them. Dropped means *unknown to the model*, not *safe*. The tool says so instead
   of hiding it. That is a real limitation we found by running a real scan."
3. **The evidence labels** — this is the provenance feature, slow down here:

   > "Each step says where its evidence came from. nmap **observed** port 21 open. It
   > **observed** vsftpd 2.3.4. The vulners script **correlated** that version with
   > CVE-2011-2523. Then the *model* **inferred** that it gives a foothold, with
   > probability 0.99. The first two are measurements; the last two are our conclusions."

4. **Say what it does not prove:**

   > "This validates the pipeline on real scanner output. It does not validate multi-hop
   > paths — there is one host and one edge — and it cannot compare strategies, because
   > with one finding all three pick the same patch. We did not execute the exploit."

**If asked for a multi-hop scan example,** run the fixture
(`evidence\demo_outputs\3_fixture.txt`), and say clearly that it is **hand-built**, not a
real scan.

## Step 4 — Across 100 networks (1½ minutes)

```cmd
cls
python -m scripts.compare_seeds --seeds 100
```

> "100 generated networks. 29 had no route to a crown jewel, so 71 are usable. After one
> patch, graph-aware leaves 5.6 % of the modelled risk, CVSS-first 58 %, EPSS-first 98 %.
> Graph-aware was at least as good as both on all 71."

Then immediately:

> "But this table is partly expected by design. Our planner chooses patches to minimise
> exactly this number. So we needed a check it does not optimise."

## Step 5 — A metric the planner does not optimise (1½ minutes)

```cmd
cls
python -m scripts.reachability_check --seeds 100
```

> "After each plan's patches we rebuild the attack graph and search again from scratch.
> After five patches, graph-aware cuts off every crown jewel in 71 of 71 networks.
> CVSS-first does it in 55, EPSS-first in 19."

Then the honest part, which examiners respect:

> "This check also exposed a weakness in our own headline metric. After one patch, the
> fixed-path number says 5.6 % residual risk. Searching again finds 22.4 %, because routes
> outside our top 50 paths were never counted. So '0 %' in the earlier table means every
> *retained* path is broken, not that the crown jewels are unreachable."

## Step 6 — Scale (1 minute, saved output)

Show `evidence\demo_outputs\6_scale.txt` or the E5 table in `EXPERIMENTS.md`. Do not run it
live: it takes minutes.

> "We varied network size from 22 to 212 hosts at three vulnerability densities, 20
> networks each. At 212 hosts and about 33,000 attack-graph edges, the full analysis took
> about 643 ms on this laptop. That is with a cap of 50 paths per crown jewel, so it shows
> practicality at this scale, not unbounded enterprise scale."

One more observation worth making:

> "At the densest setting one patch leaves about 23 % risk instead of 3–9 %. Denser
> vulnerability means more alternative routes, so a single chokepoint matters less."

## Step 7 — Dashboard (1 minute, optional)

Switch to the browser tab already open on the dashboard.

- **Green banner:** "Real data: 70 CVEs from NVD, the KEV catalog version."
- **Attack paths tab:** drag the path-rank slider and watch the red route move.
- **Patch plan tab:** the graph-aware line drops to zero faster. Say: "The dashboard compares
  graph-aware with CVSS-first; the EPSS comparison is the command-line run you just saw."

Skip this step if time is short. Everything it shows has already been shown.

## Step 8 — Close (30 seconds)

> "So: a transparent, locally runnable pipeline that turns scanner output into attack
> paths, labels which parts are observed and which are inferred, and compares remediation
> strategies reproducibly. Within our model, topology-aware ordering cuts off crown jewels
> that score-only ordering misses. What we have not shown is real-world breach reduction:
> our multi-host results are synthetic, and our real scan is one host. The next step
> would be a multi-VM lab scanned from two vantage points."

---

## If something goes wrong

| Problem | Do this |
|---|---|
| `ModuleNotFoundError` | The environment is not active: `.venv\Scripts\activate.bat` |
| A command errors or hangs | Open the matching file in `evidence\demo_outputs\` and carry on. Say "this is the saved output from the same command." |
| Dashboard will not load | Skip step 7. It adds nothing that the earlier steps did not show. |
| Laptop fails entirely | Every output is committed on GitHub under `evidence/demo_outputs/`, and every number is in `docs/EXPERIMENTS.md`. |
| Numbers differ from this script | Do not improvise. Say what you expected, and show the saved output. Then check whether `fetch_feeds` was run. |

## Numbers to know without looking

| | |
|---|---|
| Catalog | 70 CVEs; 62 in KEV; EPSS for all 70 |
| Tests | 146 passing |
| Seed 7 | 42 hosts, 932 attack-graph edges, 150 retained paths |
| Seed 7, first patch | graph-aware 150/150 broken · CVSS-first 115/150 · EPSS-first 0/150 |
| Real scan | 23 ports · 417 CVEs reported · 1 kept · 416 dropped · 1 path, p = 0.990, risk 8.91 |
| 100 seeds | 71 usable · after 1 patch: 5.6 % / 58.1 % / 97.7 % |
| Reachability, 5 patches | all crown jewels cut off: 71 / 55 / 19 of 71 |
| One graph-aware patch | 5.6 % fixed-path vs 22.4 % re-discovered |
| Scale | 212 hosts · ~33,000 edges · ~643 ms · cap 50 paths per crown jewel |
