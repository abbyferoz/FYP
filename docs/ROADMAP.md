# Status and roadmap

What works, what does not, and what comes next.

---

## Working now

| | Evidence |
|---|---|
| CVSS v3.1 calculator | Agrees with NVD on **69 of 69** cached CVEs |
| Real vulnerability data | 69 CVEs from the NVD API; 62 in CISA KEV, 44 ransomware-linked |
| Data model | Hosts, services, users, logon sessions, admin rights, zone firewall |
| Synthetic network generator | Seeded and reproducible; 42 hosts by default |
| Attack graph | Exploit + credential-reuse edges, each with a probability. 932 edges in ~2 ms |
| Attack-path discovery | Yen's k most probable paths |
| Chokepoint analysis | Risk-weighted path participation and betweenness centrality |
| Patch prioritisation | Greedy graph-aware plan vs highest-CVSS-first baseline |
| Real scan ingestion | `nmap -oX` parsing, including multi-vantage-point merging |
| Neo4j export | Idempotent `MERGE`-based Cypher plus example queries |
| Dashboard | Streamlit + PyVis, synthetic or uploaded scan |
| Tests | 128 passing |

---

## Known gaps

Ordered by how much they matter.

### 1. No real scan has been run

**This is the most important gap.** The parser is complete and tested, but the fixtures in
`tests/fixtures/` were **hand-built to mirror real nmap 7.94 output — no host was actually
scanned to produce them**.

Everything needed is in place: `docs/RUNNING.md` §6 has the full lab setup (VirtualBox +
Metasploitable 2 on a host-only adapter), the exact nmap invocation, and what to do with
CVEs the catalog does not recognise. It is an afternoon of work, and it is what turns a
convincing simulation into a demonstrator.

### 2. The benchmark evaluates itself

The graph-aware planner directly optimises the same residual-risk metric the headline
comparison reports, on the same model, so it is *expected* to win. The mechanism transfers
to real networks; the margin does not.

Fixing this properly needs:
- real scan data at meaningful scale,
- stronger baselines — CVSS+KEV, EPSS, internet-facing-first — rather than plain CVSS,
- an evaluation metric the planner does not directly optimise.

### 3. Two probability constants are judgement calls

`CRED_THEFT_P = 0.5` (credential reuse succeeds) and `KEV_BOOST = 1.25` (known-exploited
multiplier) are not measured quantities. They are stated as assumptions rather than
hidden, but they are the weakest numbers in the model.

- **KEV_BOOST → EPSS.** FIRST's Exploit Prediction Scoring System gives an actual
  predicted probability of exploitation. Fetch `https://api.first.org/data/v1/epss`, add
  an `epss` field to `Vuln`, use it in `scoring.exploit_probability`. **This is the
  highest-value single change available.**
- **CRED_THEFT_P → real identity data.** BloodHound/SharpHound collection gives observed
  privilege relationships instead of a constant.

### 4. Scale

The attack graph has O(hosts²) edges within permitted zone pairs. 42 hosts → 932 edges in
2 ms, which is fine; the 10,000-node target in the project outline is not. The fix is
zone-level aggregation: represent "any host in zone X reaches any host in zone Y"
implicitly rather than enumerating every pair.

### 5. Near-duplicate paths

The top-k paths to a crown jewel are dominated by the same route via `web-01` vs `web-02`.
An analyst sees ten copies of one finding. Fix: group by path *pattern* — the sequence of
(role, zone) pairs — and keep the best of each group.

### 6. Smaller items

- **Independence assumption.** Edge probabilities are multiplied as if independent. Two
  steps exploiting the same CVE are correlated, so path probability is understated.
- **NVD vectors sometimes understate impact.** CVE-2017-10271 is scored `C:N/I:N/A:H`, so
  the integrity-impact foothold rule excludes a CVE that is in practice remote code
  execution. Consider CNA vectors or KEV descriptions as a secondary signal.
- **Neo4j is exported, not loaded.** The Cypher is generated and tested; running it
  against a live instance and porting the core queries is still to do.
- **Identity data is synthetic.** A scan-derived graph has exploit edges only, because
  nmap cannot see sessions or admin rights.

---

## Next

### Near term

1. **Run a real scan** against a lab VM (§1 above). Replace or supplement the fixtures.
2. **Add EPSS** in place of the KEV multiplier (§3).
3. **Stand up Neo4j**, load the exported graph, port the core queries to Cypher, and
   cross-check that both implementations agree on the reachable set.
4. **Deduplicate paths** by pattern (§5).
5. **Stronger baselines** for the comparison (§2).

### Later

- **Zone-aware graph representation** for scale (§4).
- **Identity ingestion** in BloodHound/SharpHound format (§3).
- **Predictive layer** — a graph neural network (GraphSAGE / R-GCN) to score the
  probability of *unmapped* lateral movement from topological node features, rather than
  only enumerating known paths.
- **Minimum patch set** — replace the greedy planner with a directed minimum-cut or
  integer-linear-programming formulation that finds the provably fewest patches or
  firewall changes needed to break the most critical paths.
- **Automated remediation output** — generate concrete remediation steps (Ansible
  playbooks, firewall rule changes) from a chosen patch plan.
- **Live ingestion** — update the graph continuously from a scanner rather than from a
  one-off file.

---

## Non-code work

- Reformat `PROPOSAL.md` onto the department's template.
- Both team members rehearse `docs/WALKTHROUGH.md` — the viva grades each of us
  individually on any component, unaided. There is a checklist at the end of that
  document.
