import networkx as nx
import pytest

from apg.attackgraph import INTERNET, derive_attack_graph
from apg.generator import generate_network
from apg.model import Host, Network, Service, User
from apg.paths import top_paths
from apg.remediation import baseline_risk, cvss_plan, evaluate, greedy_plan


def tiny_network() -> Network:
    """internet -> web (Log4Shell on :443) -> db (weak SQL auth on :1433). One chain, no alternatives."""
    web = Host("web", "web", "dmz", 3, [Service("https-app", 443, "app", ("CVE-2021-44228",))])
    db = Host("db", "db", "data", 10, [Service("mssql", 1433, "sql", ("SYN-2026-0003",))])
    fw = {("internet", "dmz"): frozenset({443}), ("dmz", "data"): frozenset({1433})}
    return Network({"web": web, "db": db}, {}, [], [], fw)


def test_tiny_network_has_single_path():
    A = derive_attack_graph(tiny_network())
    paths = top_paths(A, INTERNET, "db")
    assert len(paths) == 1
    assert paths[0].nodes == [INTERNET, "web", "db"]
    assert 0 < paths[0].probability <= 1
    assert paths[0].risk == pytest.approx(paths[0].probability * 10)


def test_patching_the_only_entry_breaks_the_path():
    net = tiny_network()
    A = derive_attack_graph(net)
    paths = top_paths(A, INTERNET, "db")
    _, broken = evaluate(A, paths, frozenset({("web", "CVE-2021-44228")}))
    assert broken == 1
    # Rebuilding the graph with the patch applied agrees: no path any more.
    assert top_paths(derive_attack_graph(net, {("web", "CVE-2021-44228")}), INTERNET, "db") == []


def test_credential_reuse_edge():
    """Attacker on a workstation harvests an admin session and reaches a file server."""
    ws = Host("ws", "workstation", "corp", 2, [Service("smb", 445, "smb", ("CVE-2021-34527",))])
    fs = Host("fs", "fileserver", "servers", 6, [Service("smb", 445, "smb", ())])
    fw = {("internet", "corp"): frozenset({445}), ("corp", "servers"): frozenset({445})}
    net = Network({"ws": ws, "fs": fs}, {"adm": User("adm", "admin")},
                  [("adm", "ws")], [("adm", "fs")], fw)
    A = derive_attack_graph(net)
    assert [o.kind for o in A["ws"]["fs"]["options"]] == ["cred"]
    assert top_paths(A, INTERNET, "fs")[0].nodes == [INTERNET, "ws", "fs"]


def test_generator_is_deterministic():
    a, b = generate_network(seed=3), generate_network(seed=3)
    assert a.hosts.keys() == b.hosts.keys()
    assert [s.cve_ids for h in a.hosts.values() for s in h.services] == \
           [s.cve_ids for h in b.hosts.values() for s in h.services]


def test_default_network_has_internet_foothold_and_crown_jewels():
    net = generate_network()
    A = derive_attack_graph(net)
    assert A.out_degree(INTERNET) > 0          # the guaranteed foothold really is reachable
    assert net.crown_jewels()
    assert all(0 < d["p"] <= 0.99 for _, _, d in A.edges(data=True))


def test_heartbleed_alone_creates_no_foothold():
    web = Host("web", "web", "dmz", 3, [Service("tls", 443, "openssl", ("CVE-2014-0160",))])
    net = Network({"web": web}, {}, [], [], {("internet", "dmz"): frozenset({443})})
    assert derive_attack_graph(net).number_of_edges() == 0


def test_greedy_plan_is_monotone_and_beats_or_ties_cvss_at_one_patch():
    net = generate_network(seed=7)
    A = derive_attack_graph(net)
    from apg.paths import paths_to_all
    paths = [p for ps in paths_to_all(A, INTERNET, net.crown_jewels(), 30).values() for p in ps]
    base = baseline_risk(A, paths)
    g = greedy_plan(A, paths, 5)
    residuals = [s.residual_risk for s in g]
    assert residuals == sorted(residuals, reverse=True)
    assert residuals[0] < base
    assert residuals[0] <= cvss_plan(net, A, paths, 1)[0].residual_risk + 1e-9
