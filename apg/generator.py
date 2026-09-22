"""Seeded synthetic enterprise network generator.

Produces a small but realistic segmented network: internet -> DMZ web tier ->
application/file/domain servers -> data tier, plus a corporate workstation zone with
helpdesk, DBA and domain-admin accounts whose logon sessions can be harvested.
The same seed always yields the same network (needed for reproducible experiments).
"""
from __future__ import annotations

import random

from apg.catalog import GUARANTEED_ENTRY, SERVICE_TEMPLATES
from apg.model import Host, Network, Service, User

FIREWALL: dict[tuple[str, str], frozenset[int]] = {
    ("internet", "dmz"): frozenset({80, 443}),
    ("dmz", "servers"): frozenset({8080}),
    ("corp", "dmz"): frozenset({80, 443}),
    ("corp", "corp"): frozenset({445, 3389}),
    ("corp", "servers"): frozenset({445, 3389, 8080, 135}),
    ("servers", "servers"): frozenset({445, 3389, 8080, 135, 1433}),
    ("servers", "corp"): frozenset({445, 3389}),
    ("servers", "data"): frozenset({1433, 445}),
}

_CRITICALITY = {"web": 3, "app": 5, "fileserver": 6, "dc": 9, "workstation": 2}
_ZONE = {"web": "dmz", "app": "servers", "fileserver": "servers", "dc": "servers",
         "db": "data", "workstation": "corp"}


def generate_network(seed: int = 7, workstations: int = 30, web: int = 3, app: int = 4,
                     fileservers: int = 2, dbs: int = 2, vuln_rate: float = 0.35) -> Network:
    rng = random.Random(seed)
    hosts: dict[str, Host] = {}

    def add(role: str, n: int) -> list[str]:
        ids = []
        for i in range(1, n + 1):
            hid = f"{'ws' if role == 'workstation' else role}-{i:02d}"
            crit = _CRITICALITY.get(role, 2)
            if role == "db":
                crit = 10 if i == 1 else 8
            services = []
            for name, port, product, candidates in SERVICE_TEMPLATES[role]:
                # Roll once per service, then pick one of the CVEs that service could
                # plausibly have. Two hosts of the same role therefore end up with
                # different weaknesses, which is what makes chokepoint analysis and
                # patch prioritisation a real problem rather than a lookup.
                present = bool(candidates) and rng.random() < vuln_rate
                chosen = (rng.choice(candidates),) if present else ()
                services.append(Service(name, port, product, chosen))
            hosts[hid] = Host(hid, role, _ZONE[role], crit, services)
            ids.append(hid)
        return ids

    web_ids = add("web", web)
    app_ids = add("app", app)
    fs_ids = add("fileserver", fileservers)
    dc_ids = add("dc", 1)
    db_ids = add("db", dbs)
    ws_ids = add("workstation", workstations)

    # Guarantee an internet-reachable foothold: web-01's public HTTPS app is always
    # vulnerable to the entry CVE (Log4Shell). Without this, a low vuln_rate can produce
    # a network with no way in at all, and experiments across seeds stop being comparable.
    for svc in hosts[web_ids[0]].services:
        if svc.name == "https-app":
            svc.cve_ids = (GUARANTEED_ENTRY,)

    users: dict[str, User] = {}
    sessions: list[tuple[str, str]] = []
    admin_of: list[tuple[str, str]] = []

    for i, ws in enumerate(ws_ids, 1):
        uid = f"user{i:02d}"
        users[uid] = User(uid, "user")
        sessions.append((uid, ws))

    for name in ("helpdesk1", "helpdesk2"):           # helpdesk log into a few workstations
        users[name] = User(name, "admin")
        for ws in rng.sample(ws_ids, k=min(2, len(ws_ids))):
            sessions.append((name, ws))
        admin_of += [(name, h) for h in ws_ids + fs_ids]

    users["dba"] = User("dba", "admin")               # DBA leaves a session on an app server
    sessions.append(("dba", rng.choice(app_ids)))
    admin_of += [("dba", d) for d in db_ids]

    users["domadmin"] = User("domadmin", "domain_admin")   # domain admin: DC + a file server
    sessions.append(("domadmin", dc_ids[0]))
    sessions.append(("domadmin", rng.choice(fs_ids)))
    admin_of += [("domadmin", h) for h in hosts if _ZONE[hosts[h].role] != "dmz"]

    return Network(hosts=hosts, users=users, sessions=sessions, admin_of=admin_of,
                   firewall=dict(FIREWALL))
