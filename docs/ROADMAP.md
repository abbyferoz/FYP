# Status and roadmap

What works, what does not, and what comes next. Every figure here comes from
[`EXPERIMENTS.md`](EXPERIMENTS.md).

---

## Working now

| | Evidence |
|---|---|
| CVSS v3.1 calculator | Agrees with NVD on **70 of 70** cached CVEs |
| Real vulnerability data | 70 CVEs from the NVD API (snapshot 2026-10-20); 62 in CISA KEV, 44 ransomware-linked; EPSS scores for all 70 (snapshot 2026-10-21) |
| Data model | Hosts, services, users, logon sessions, admin rights, zone firewall; services carry evidence status and labels |
| Synthetic network generator | Seeded and reproducible; 42 hosts by default |
| Attack graph | Exploit + credential-reuse edges, each with a probability. 932 edges in ~2 ms for the default network |
| Attack-path discovery | Yen's k most probable paths, each step carrying observed / correlated / inferred provenance |
| Chokepoint analysis | Risk-weighted path participation and betweenness centrality |
| Patch prioritisation | Greedy graph-aware plan vs **CVSS-first** and **EPSS-first** baselines |
| Multi-seed comparison | 100 networks, 71 usable; graph-aware ≤ both baselines on 71/71 (`compare_seeds`) |
| Independent reachability check | Rebuilds the graph after patching; graph-aware cuts off every crown jewel in 71/71 networks after 5 patches, vs 55/71 (CVSS-first) and 19/71 (EPSS-first) (`reachability_check`) |
| Scalability experiment | 22–212 hosts × three vulnerability densities, 300 networks; ~643 ms mean at 212 hosts / ~33,000 edges with a 50-path cap (`scale_experiment`) |
| Real scan ingestion | `nmap -oX` parsing, multi-vantage-point merging; **exercised on a real Metasploitable 2 scan** (`evidence/real_scan/`) |
| Neo4j export | Idempotent `MERGE`-based Cypher plus example queries |
| Dashboard | Streamlit + PyVis, synthetic or uploaded scan |
| Tests | 146 passing, including direct tests for EPSS, provenance and the real scan |

---

## Known gaps

Ordered by how much they matter.

### 1. Real-world validation is one host

The real Metasploitable 2 scan proves the pipeline runs on genuine scanner output, end to
end, with provenance. But it produced a single host, a single edge and a single path, so it
cannot validate multi-hop path accuracy or show any difference between remediation
strategies (all three choose the same patch). The multi-hop and comparative results all
come from synthetic networks.

**Next step:** a multi-VM lab — Metasploitable 2 plus a second vulnerable VM (for example a
Windows Server evaluation image) in a different subnet — scanned from two vantage points
and merged, so the real-data path has more than one hop.

### 2. Catalog coverage

The real scan reported 417 CVE identifiers. The 69-CVE catalog contained none of them;
after adding CVE-2011-2523 it contained one. The other 416 are dropped and reported, not
silently treated as safe — but they are invisible to the attack graph.

**Next step:** bulk-fetch every CVE a scan reports (`scripts.fetch_feeds` already merges
into the cache; an NVD API key makes this practical), with CVEs lacking a CVSS v3 vector
still dropped and reported.

### 3. The fixed-path metric has blind spots

The headline comparison scores plans on a fixed set of top-50 paths per crown jewel, and
the graph-aware planner optimises that metric directly, so it is expected to win on it.
The reachability check addresses this with a metric the planner does not optimise, and
it also exposed the blind spot: after **one** graph-aware patch, fixed-path residual
risk is 5.6 % but re-discovered risk is 22.4 %, because alternative routes were never in
the retained set.

Still missing: a simple topology-aware baseline (patch whatever appears on the most
retained paths), to separate "uses the graph at all" from "uses the greedy planner".

### 4. Two probability constants are judgement calls

`CRED_THEFT_P = 0.5` (credential reuse succeeds) and `KEV_BOOST = 1.25` (known-exploited
multiplier) are not measured quantities. They are stated as assumptions rather than
hidden, but they are the weakest numbers in the model.

- **EPSS is not yet in the edge probability.** It is cached and used as a remediation
  baseline, but `scoring.exploit_probability` still uses the CVSS sub-score and the KEV
  multiplier. Using EPSS there is possible, but it answers "will this be exploited somewhere
  in the next 30 days", not "will this step succeed against this host", so it is not a
  drop-in replacement.
- **CRED_THEFT_P → real identity data.** BloodHound/SharpHound collection gives observed
  privilege relationships instead of a constant.

### 5. Scale beyond the tested range

The attack graph has O(hosts²) edges within permitted zone pairs: ~33,000 edges at 212
hosts. Analysis stays sub-second at that size only because path discovery is capped. The
10,000-node target in the original outline is not demonstrated. The fix is zone-level
aggregation — represent "any host in zone X reaches any host in zone Y" implicitly rather
than enumerating every pair.

### 6. Smaller items

- **Near-duplicate paths.** The top-k paths to a crown jewel are dominated by the same
  route via `web-01` vs `web-02`. Fix: group by path *pattern* — the sequence of (role, zone)
  pairs — and keep the best of each group.
- **Greedy filler.** Once residual risk reaches 0, further greedy steps all score 0 and
  are chosen by tie-break, so patches 2–5 of a graph-aware plan can be arbitrary.
- **Independence assumption.** Edge probabilities are multiplied as if independent. Two
  steps exploiting the same CVE are correlated, so path probability is understated.
- **NVD vectors sometimes understate impact.** CVE-2017-10271 is scored `C:N/I:N/A:H`, so
  the integrity-impact foothold rule excludes a CVE that is in practice remote code
  execution.
- **Neo4j is exported, not loaded.** The Cypher is generated and tested; running it
  against a live instance and cross-checking the core queries is still to do.
- **Identity data is synthetic.** A scan-derived graph has exploit edges only, because
  nmap cannot see sessions or admin rights.
- **Dashboard shows two strategies.** The patch-plan tab compares graph-aware with
  CVSS-first only; the three-way comparison is in the command-line scripts.
- **EPSS is time-dependent.** Re-fetching feeds changes EPSS-first results. The snapshot
  used is committed in `data/epss.json`.

---

## Next

### Near term (after the defence)

1. **Multi-VM lab** with two vantage points, so real data produces multi-hop paths (§1).
2. **Catalog coverage** for every CVE a real scan reports (§2).
3. **Path-participation baseline** for the comparison (§3).
4. **Stand up Neo4j**, load the exported graph, and cross-check that Cypher and NetworkX
   agree on the reachable set.
5. **Deduplicate paths** by pattern (§6).

### Later

- **Zone-aware graph representation** for scale (§5).
- **Identity ingestion** in BloodHound/SharpHound format (§4).
- **Predictive layer** — a graph neural network (GraphSAGE / R-GCN) to score the
  probability of *unmapped* lateral movement from topological node features.
- **Minimum patch set** — a directed minimum-cut or integer-linear-programming formulation
  that finds the provably fewest patches or firewall changes needed to break the most
  critical paths.
- **Automated remediation output** — concrete remediation steps (Ansible playbooks,
  firewall rule changes) from a chosen patch plan.
- **Live ingestion** — update the graph continuously from a scanner rather than from a
  one-off file.

---

## Non-code work

- Reformat `PROPOSAL.md` onto the department's template.
- Both team members rehearse `docs/WALKTHROUGH.md` — the viva grades each of us
  individually on any component, unaided. There is a checklist at the end of that
  document.
