"""The nmap importer: does a real scan file become a Network we can analyse?

Split the same way the module is, because the two halves fail differently:

  parsing     is right or wrong against the XML. Tested on fixtures.
  modelling   is a judgement call. Tested for the property we actually want -
              that the assumptions are pessimistic and that they are reported.
"""
from pathlib import Path

import pytest

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.catalog import VULNS
from apg.nmap_import import (ROLE_CRITICALITY, infer_role, infer_zone, merge_scans,
                             network_from_scan, parse_nmap_xml)
from apg.paths import top_paths

FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "lab_scan.xml"
METASPLOITABLE = FIXTURES / "metasploitable.xml"
DMZ = FIXTURES / "dmz_scan.xml"

ZONES = {"192.168.56.0/24": "dmz", "192.168.57.0/24": "servers", "192.168.58.0/24": "data"}


# --- Stage 1: parsing ---------------------------------------------------------------

def test_parses_hosts_and_skips_hosts_that_are_down():
    scan = parse_nmap_xml(LAB)
    assert len(scan.hosts) == 3                       # the 4th is state="down"
    assert {h.address for h in scan.hosts} == {"192.168.56.11", "192.168.57.21",
                                               "192.168.58.31"}


def test_host_id_prefers_short_hostname_and_falls_back_to_ip():
    lab = {h.address: h for h in parse_nmap_xml(LAB).hosts}
    assert lab["192.168.56.11"].id == "web-01"        # from web-01.lab.local
    meta = parse_nmap_xml(METASPLOITABLE).hosts[0]
    assert meta.hostname == ""
    assert meta.id == "192.168.56.101"                # no PTR record: use the address


def test_only_open_ports_become_attack_surface():
    web = next(h for h in parse_nmap_xml(LAB).hosts if h.id == "web-01")
    ports = {s.port for s in web.services}
    assert ports == {22, 80, 443, 8080}               # 25 is "filtered", not open
    assert 25 not in ports


def test_reads_service_product_version_and_cpe():
    web = next(h for h in parse_nmap_xml(LAB).hosts if h.id == "web-01")
    https = next(s for s in web.services if s.port == 443)
    assert https.name == "https"
    assert https.product == "nginx 1.18.0"
    assert "cpe:/a:igor_sysoev:nginx:1.18.0" in https.cpes


def test_extracts_cves_from_both_nse_output_shapes():
    """vulners writes structured <table> elements; other scripts write plain text into
    the `output` attribute. Both must yield CVE IDs."""
    lab = {h.id: h for h in parse_nmap_xml(LAB).hosts}
    https = next(s for s in lab["web-01"].services if s.port == 443)
    assert https.cve_ids == ("CVE-2021-44228", "CVE-2021-45046")      # <table> form
    rdp = next(s for s in lab["fs-01"].services if s.port == 3389)
    assert rdp.cve_ids == ("CVE-2019-0708",)                          # output-attribute form
    smb = next(s for s in lab["fs-01"].services if s.port == 445)
    assert "CVE-2017-0143" in smb.cve_ids       # from smb-vuln-ms17-010, not vulners


def test_os_detection_is_captured():
    lab = {h.id: h for h in parse_nmap_xml(LAB).hosts}
    assert "Linux" in lab["web-01"].os_guess
    assert "Windows" in lab["fs-01"].os_guess


def test_rejects_xml_that_is_not_an_nmap_run(tmp_path):
    f = tmp_path / "not_nmap.xml"
    f.write_text("<?xml version='1.0'?><report><host/></report>")
    with pytest.raises(ValueError, match="not nmap XML"):
        parse_nmap_xml(f)


# --- Stage 2: inference -------------------------------------------------------------

def test_role_inference_prefers_the_most_specific_signature():
    assert infer_role({88, 389, 445}) == "dc"          # AD ports beat the SMB signal
    assert infer_role({1433, 445}) == "db"             # database beats SMB
    assert infer_role({445, 139}) == "fileserver"
    assert infer_role({80, 443}) == "web"
    assert infer_role({8080}) == "app"
    assert infer_role({22}) == "workstation"           # nothing matched: the default


def test_zone_inference_uses_the_map_then_falls_back_to_the_slash_24():
    assert infer_zone("192.168.56.11", ZONES) == "dmz"
    assert infer_zone("192.168.58.31", ZONES) == "data"
    assert infer_zone("10.1.2.3", ZONES) == "net-10.1.2"   # unmapped: keep the boundary
    assert infer_zone("10.1.2.3", None) == "net-10.1.2"
    assert infer_zone("not-an-ip", ZONES) == "unknown"


def test_builds_a_network_with_roles_zones_and_criticality():
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES, known_cves=set(VULNS))
    assert set(net.hosts) == {"web-01", "fs-01", "db-01"}
    assert net.hosts["web-01"].zone == "dmz"
    assert net.hosts["db-01"].role == "db"
    assert net.hosts["db-01"].criticality == ROLE_CRITICALITY["db"]
    assert "db-01" in net.crown_jewels()


def test_overrides_beat_inference():
    net, _ = network_from_scan(
        parse_nmap_xml(LAB), zone_map=ZONES,
        roles={"web-01": "app"}, criticality={"192.168.56.11": 10},
        known_cves=set(VULNS))
    assert net.hosts["web-01"].role == "app"
    assert net.hosts["web-01"].criticality == 10


def test_unknown_cves_are_dropped_and_reported_not_silently_kept():
    """A CVE we cannot score must not reach the engine, and the operator must be told:
    a silently dropped CVE hides a real attack path."""
    net, warnings = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES,
                                      known_cves={"CVE-2021-44228"})
    kept = {c for h in net.hosts.values() for s in h.services for c in s.cve_ids}
    assert kept == {"CVE-2021-44228"}
    assert any("not in the local catalog" in w for w in warnings)


def test_missing_firewall_policy_is_warned_about():
    _, warnings = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES,
                                    known_cves=set(VULNS))
    assert any("Firewall policy was not supplied" in w for w in warnings)
    assert any("no credential-reuse edges" in w for w in warnings)


def test_a_scan_with_no_cves_warns_instead_of_returning_an_empty_graph():
    """The Metasploitable fixture has no vulners output. Silently producing an attack
    graph with no edges would look like 'this network is safe'."""
    net, warnings = network_from_scan(parse_nmap_xml(METASPLOITABLE),
                                      known_cves=set(VULNS))
    assert any("No CVEs found in the scan" in w for w in warnings)
    assert derive_attack_graph(net).number_of_edges() == 0


def test_hosts_with_no_open_ports_are_excluded():
    scan = parse_nmap_xml(LAB)
    for h in scan.hosts:
        if h.id == "db-01":
            h.services = []
    net, _ = network_from_scan(scan, zone_map=ZONES, known_cves=set(VULNS))
    assert "db-01" not in net.hosts       # no open ports means no attack surface


def test_empty_scan_raises_a_useful_error():
    scan = parse_nmap_xml(METASPLOITABLE)
    scan.hosts = []
    with pytest.raises(ValueError, match="No hosts with open ports"):
        network_from_scan(scan)


# --- The point of it all: real scan -> real attack path ------------------------------

def test_the_engine_finds_a_path_from_the_internet_to_the_database():
    """End to end on scan data only: parse, model, derive, and find a path."""
    net, _ = network_from_scan(parse_nmap_xml(LAB), zone_map=ZONES, known_cves=set(VULNS))
    A = derive_attack_graph(net)
    paths = top_paths(A, INTERNET, "db-01", k=5)
    assert paths, "expected at least one internet -> db-01 attack path"
    best = paths[0]
    assert best.nodes[0] == INTERNET and best.nodes[-1] == "db-01"
    assert 0 < best.probability <= 1
    assert all("exploit CVE-" in s for s in best.steps)


def test_merging_vantage_points_measures_reachability_instead_of_assuming_it():
    """One scan has to assume zone-to-zone reachability. Two scans measure it, so the
    merged firewall contains exactly the rows we observed and nothing more."""
    scans = [parse_nmap_xml(LAB, vantage="internet"), parse_nmap_xml(DMZ, vantage="dmz")]
    net, warnings = merge_scans(scans, zone_map=ZONES, known_cves=set(VULNS))
    assert any("measured from 2 vantage point" in w for w in warnings)
    assert not any("Firewall policy was not supplied" in w for w in warnings)
    assert {src for src, _ in net.firewall} == {"internet", "dmz"}
    # The DMZ scan saw port 5985 on fs-01; the internet scan never did.
    assert 5985 in net.firewall[("dmz", "servers")]
    assert 5985 not in net.firewall.get(("internet", "servers"), frozenset())


def test_merging_unions_services_seen_from_different_places():
    scans = [parse_nmap_xml(LAB, vantage="internet"), parse_nmap_xml(DMZ, vantage="dmz")]
    net, _ = merge_scans(scans, zone_map=ZONES, known_cves=set(VULNS))
    ports = {s.port for s in net.hosts["fs-01"].services}
    assert {135, 139, 445, 3389}.issubset(ports)      # from the internet-side scan
    assert 5985 in ports                              # only visible from the DMZ
