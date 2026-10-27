"""Direct tests for the October features: EPSS data and baseline, evidence provenance,
the real Metasploitable scan, and the reachability check.

Before these existed, the suite passed 129 tests but none of them exercised EPSS or
provenance directly. These tests pin the behaviour quoted in docs/EXPERIMENTS.md.
"""
import json
from pathlib import Path

import networkx as nx
import pytest

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.catalog import VULNS
from apg.feeds import FeedError, build_vulns, load_epss
from apg.generator import generate_network
from apg.nmap_import import network_from_scan, parse_nmap_xml
from apg.paths import paths_to_all, top_paths
from apg.remediation import all_patchable, cvss_plan, epss_plan, greedy_plan
from apg.scoring import cve_base_score
from scripts.reachability_check import rediscovered

ROOT = Path(__file__).parent.parent
LAB = ROOT / "tests" / "fixtures" / "lab_scan.xml"
REAL_SCAN = ROOT / "evidence" / "real_scan" / "metasploitable-vulners.xml"
ZONES = {"192.168.56.0/24": "dmz", "192.168.57.0/24": "servers", "192.168.58.0/24": "data"}

NVD = {
    "CVE-2021-44228": {"id": "CVE-2021-44228", "published": "2021-12-10",
                       "description": "Log4Shell",
                       "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                       "nvd_base_score": 10.0, "cwes": []},
    "CVE-2014-0160": {"id": "CVE-2014-0160", "published": "2014-04-07",
                      "description": "Heartbleed",
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                      "nvd_base_score": 7.5, "cwes": []},
}
EPSS = {"CVE-2021-44228": {"epss": 0.94358, "percentile": 0.99956}}


def _graph_and_paths(seed=7, k=50):
    net = generate_network(seed)
    A = derive_attack_graph(net)
    paths = [p for ps in paths_to_all(A, INTERNET, net.crown_jewels(), k).values() for p in ps]
    return net, A, paths


# --- EPSS data ---------------------------------------------------------------------

def test_epss_score_and_percentile_are_joined_onto_the_vulnerability():
    v = build_vulns(NVD, {}, EPSS)["CVE-2021-44228"]
    assert v.epss == pytest.approx(0.94358)
    assert v.epss_percentile == pytest.approx(0.99956)


def test_a_cve_missing_from_epss_gets_none_not_zero():
    """'No EPSS score' must stay distinguishable from 'EPSS says 0'."""
    vulns = build_vulns(NVD, {}, EPSS)
    assert vulns["CVE-2014-0160"].epss is None
    assert build_vulns(NVD, {}, None)["CVE-2021-44228"].epss is None


def test_load_epss_reads_entries_and_metadata(tmp_path):
    f = tmp_path / "epss.json"
    f.write_text(json.dumps({"_meta": {"count": 1, "fetched_at": "2026-10-21T18:49:51+00:00"},
                             "entries": EPSS}))
    entries, meta = load_epss(f)
    assert entries == EPSS
    assert meta["count"] == 1


def test_missing_epss_cache_raises_a_feed_error(tmp_path):
    with pytest.raises(FeedError):
        load_epss(tmp_path / "absent.json")


def test_every_catalog_cve_has_a_cached_epss_score():
    """The experiments assume full EPSS coverage of the 70-CVE catalog."""
    missing = sorted(c for c, v in VULNS.items() if v.epss is None)
    assert not missing, f"no EPSS score cached for {missing}"


# --- Baselines ---------------------------------------------------------------------

def test_epss_first_patches_in_descending_epss_order():
    net, A, paths = _graph_and_paths()
    plan = epss_plan(net, A, paths, 10)
    scores = [VULNS[s.patch[1]].epss for s in plan]
    assert scores == sorted(scores, reverse=True)
    best_anywhere = max(VULNS[c].epss for _, c in all_patchable(net))
    assert scores[0] == best_anywhere


def test_cvss_first_patches_in_descending_cvss_order():
    net, A, paths = _graph_and_paths()
    plan = cvss_plan(net, A, paths, 10)
    scores = [s.cvss for s in plan]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == max(cve_base_score(c) for _, c in all_patchable(net))


def test_seed_7_first_patch_of_each_strategy_matches_the_documented_demo():
    """Regression for EXPERIMENTS.md E1."""
    net, A, paths = _graph_and_paths()
    assert len(paths) == 150
    g, c, e = greedy_plan(A, paths, 1)[0], cvss_plan(net, A, paths, 1)[0], epss_plan(net, A, paths, 1)[0]
    assert g.patch == ("app-03", "CVE-2022-22965") and g.paths_broken == 150
    assert c.patch == ("fileserver-01", "CVE-2020-0796") and c.paths_broken == 115
    assert e.patch == ("app-01", "CVE-2022-26134") and e.paths_broken == 0


# --- Provenance on scan-derived services ---------------------------------------------

def test_scan_derived_services_are_marked_observed_with_labelled_evidence():
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES, known_cves=set(VULNS))
    for h in net.hosts.values():
        for s in h.services:
            assert s.evidence_status == "observed"
            assert s.evidence[0] == f"[OBSERVED] TCP/{s.port} observed open by nmap"
            assert s.evidence[1].startswith("[OBSERVED] service identified as ")
            correlated = [e for e in s.evidence if e.startswith("[CORRELATED]")]
            assert correlated == [f"[CORRELATED] {c} reported by nmap NSE/vulnerability enrichment"
                                  for c in s.cve_ids]


def test_dropped_cves_never_appear_as_correlated_evidence():
    """A CVE outside the catalogue is dropped. It must not survive in the evidence trail."""
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES,
                               known_cves={"CVE-2021-44228"})
    evidence = [e for h in net.hosts.values() for s in h.services for e in s.evidence]
    correlated = {e.split()[1] for e in evidence if e.startswith("[CORRELATED]")}
    assert correlated <= {"CVE-2021-44228"}


def test_synthetic_services_never_claim_to_be_observed():
    """Generated networks are a model, not a measurement."""
    net = generate_network(7)
    for h in net.hosts.values():
        for s in h.services:
            assert s.evidence_status != "observed"
            assert not any(e.startswith(("[OBSERVED]", "[CORRELATED]")) for e in s.evidence)


# --- Provenance on attack-path steps -------------------------------------------------

def test_every_path_step_carries_provenance_matching_the_path():
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES, known_cves=set(VULNS))
    A = derive_attack_graph(net)
    paths = top_paths(A, INTERNET, "db-01", k=5)
    assert paths
    for p in paths:
        assert len(p.provenance) == len(p.nodes) - 1
        for (u, v), step in zip(zip(p.nodes, p.nodes[1:]), p.provenance):
            assert (step["source"], step["target"]) == (u, v)
            assert step["kind"] == "exploit" and step["status"] == "inferred"
            assert step["probability"] == pytest.approx(A[u][v]["p"])


def test_path_evidence_runs_observed_then_correlated_then_inferred():
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES, known_cves=set(VULNS))
    A = derive_attack_graph(net)
    step = top_paths(A, INTERNET, "db-01", k=1)[0].provenance[-1]
    order = {"[OBSERVED]": 0, "[CORRELATED]": 1, "[INFERRED]": 2}
    labels = [order[e.split()[0]] for e in step["evidence"]]
    assert labels == sorted(labels)
    assert set(labels) == {0, 1, 2}
    assert f"[CORRELATED] {step['ref']} reported by nmap NSE/vulnerability enrichment" in step["evidence"]


# --- The real Metasploitable scan (EXPERIMENTS.md E3) --------------------------------

@pytest.fixture(scope="module")
def real_scan():
    if not REAL_SCAN.exists():
        pytest.skip("real scan evidence not present")
    scan = parse_nmap_xml(REAL_SCAN)
    net, warnings = network_from_scan(scan, criticality={"192.168.56.102": 9},
                                      known_cves=set(VULNS))
    return scan, net, warnings


def test_real_scan_reports_417_cves_of_which_one_is_in_the_catalog(real_scan):
    scan, net, warnings = real_scan
    reported = {c for h in scan.hosts for s in h.services for c in s.cve_ids}
    kept = {c for h in net.hosts.values() for s in h.services for c in s.cve_ids}
    assert len(reported) == 417
    assert kept == {"CVE-2011-2523"}
    assert any("416 CVE(s) reported by nmap are not in the local catalog" in w for w in warnings)


def test_real_scan_yields_exactly_one_single_hop_path(real_scan):
    _, net, _ = real_scan
    host = net.hosts["192.168.56.102"]
    assert len(host.services) == 23 and host.role == "db" and host.criticality == 9
    A = derive_attack_graph(net)
    assert A.number_of_edges() == 1
    paths = top_paths(A, INTERNET, "192.168.56.102", k=50)
    assert len(paths) == 1
    assert paths[0].nodes == [INTERNET, "192.168.56.102"]
    assert paths[0].probability == pytest.approx(0.99)
    assert paths[0].risk == pytest.approx(8.91)


# --- Reachability check (EXPERIMENTS.md E4b) -----------------------------------------

def test_seed_7_top_patch_genuinely_disconnects_every_crown_jewel():
    net = generate_network(7)
    _, before = rediscovered(net, set())
    risk, after = rediscovered(net, {("app-03", "CVE-2022-22965")})
    assert before == 3
    assert after == 0 and risk == 0.0


def test_rediscovered_risk_never_increases_when_a_patch_is_added():
    net, A, paths = _graph_and_paths()
    plan = cvss_plan(net, A, paths, 5)
    risks = [rediscovered(net, {s.patch for s in plan[:n]})[0] for n in range(6)]
    assert all(a >= b - 1e-9 for a, b in zip(risks, risks[1:]))
