"""The Cypher exporter: is the emitted script valid, idempotent and complete?

We cannot assert Neo4j accepts it without running Neo4j, so we test the properties we
can: escaping, idempotency by construction, and that every node and edge in the model
appears in the output.
"""
from apg.generator import generate_network
from apg.model import Host, Network, Service, User
from apg.neo4j_export import CONSTRAINTS, props, q, to_cypher


def test_escapes_quotes_and_backslashes():
    """A CVE title containing an apostrophe must not break out of the string literal."""
    assert q("it's") == r"'it\'s'"
    assert q("back\\slash") == r"'back\\slash'"
    assert q("both\\'s") == r"'both\\\'s'"
    assert q(True) == "true"
    assert q(False) == "false"
    assert q(None) == "null"
    assert q(7) == "7"
    assert q(8.8) == "8.8"
    assert q([443, 80]) == "[443, 80]"


def test_props_drops_none_values():
    assert props(a=1, b=None, c="x") == "{a: 1, c: 'x'}"


def test_every_write_is_a_merge_so_reloading_is_idempotent():
    """CREATE would duplicate the whole estate on a nightly refresh."""
    cypher = to_cypher(generate_network(seed=1, workstations=3))
    for line in cypher.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("CREATE CONSTRAINT"):
            continue
        assert "MERGE" in line, f"non-MERGE write: {line}"
        assert not line.startswith("CREATE ("), f"bare CREATE: {line}"


def test_constraints_come_before_any_data():
    cypher = to_cypher(generate_network(seed=1, workstations=2))
    lines = [l for l in cypher.splitlines() if l.strip() and not l.startswith("//")]
    last_constraint = max(i for i, l in enumerate(lines) if l.startswith("CREATE CONSTRAINT"))
    first_merge = min(i for i, l in enumerate(lines) if l.startswith("MERGE"))
    assert last_constraint < first_merge
    assert len(CONSTRAINTS) == 4


def test_contains_every_host_user_and_relationship_type():
    net = Network(
        hosts={"web": Host("web", "web", "dmz", 3,
                           [Service("https", 443, "nginx", ("CVE-2021-44228",))]),
               "db": Host("db", "db", "data", 10, [Service("mssql", 1433, "sql", ())])},
        users={"dba": User("dba", "admin")},
        sessions=[("dba", "web")], admin_of=[("dba", "db")],
        firewall={("internet", "dmz"): frozenset({443}),
                  ("dmz", "data"): frozenset({1433})})
    c = to_cypher(net)
    for token in ("(:Subnet {name: 'dmz'})", "(h:Host {id: 'web'})", "(u:User {id: 'dba'})",
                  "(c:CVE {id: 'CVE-2021-44228'})", ":IN_SUBNET", ":HAS_VULN",
                  ":EXPOSED_TO", ":HAS_SESSION", ":CAN_ACCESS"):
        assert token in c, f"missing {token}"
    assert "h.criticality = 10" in c
    assert "c.kev = true" in c


def test_only_internet_reachable_services_get_an_exposed_to_edge():
    net = Network(
        hosts={"web": Host("web", "web", "dmz", 3,
                           [Service("https", 443, "nginx", ()),
                            Service("ssh", 22, "openssh", ())])},
        users={}, sessions=[], admin_of=[],
        firewall={("internet", "dmz"): frozenset({443})})
    c = to_cypher(net)
    assert "MERGE (i)-[r:EXPOSED_TO]->(h) SET r.port = 443" in c
    assert "SET r.port = 22" not in c


def test_a_large_network_exports_without_error():
    cypher = to_cypher(generate_network(seed=7))
    assert cypher.count("MERGE (h:Host") == 42
    assert cypher.endswith("\n")
