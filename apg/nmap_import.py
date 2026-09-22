"""Build a Network from real `nmap -oX` scan output.

This is what separates a simulation from a demonstrator: the same engine that runs on
the synthetic generator runs on a real scan of a real lab network, unchanged.

    nmap -sV -oX scans/lab.xml 192.168.56.0/24          # service/version detection
    nmap -sV --script vulners -oX scans/lab.xml TARGET  # plus CVE detection
    python -m scripts.import_scan scans/lab.xml

ONLY SCAN NETWORKS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST. A Metasploitable or
Windows VM on a host-only adapter is the right target for this project.

Two stages, deliberately kept apart:

  parse_nmap_xml()     pure XML -> facts. No modelling, no guessing. Testable against
                       a fixture file with no network and no nmap installed.
  network_from_scan()  facts -> Network. Every inference here is a modelling choice,
                       and each one is documented below because a jury will ask.

What nmap can and cannot tell us
--------------------------------
CAN:    which hosts are up, which TCP ports are open, what software answers on them
        (with -sV), the OS guess, and - with the `vulners` NSE script - CVE IDs.
CANNOT: the firewall policy, who is logged in where, which accounts are admin of what,
        or what the business considers a crown jewel.

So the parser fills in what nmap saw, and everything else must be supplied by the
operator (a zone map, a criticality map, an identity file) or defaulted to an
explicitly stated worst case. The defaults are pessimistic on purpose: assuming more
reachability than exists produces *extra* attack paths, which is the safe direction to
be wrong in for a security tool.
"""
from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from apg.model import Host, Network, Service, User

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Port -> role evidence. A host is given the role with the strongest evidence found.
# Ordered most specific first: a domain controller also has 445 open, so the AD ports
# must win over the generic SMB signal.
ROLE_SIGNATURES: list[tuple[str, frozenset[int]]] = [
    ("dc", frozenset({88, 389, 464, 636, 3268})),          # Kerberos / LDAP / global catalog
    ("db", frozenset({1433, 1521, 3306, 5432, 27017})),    # MSSQL / Oracle / MySQL / PG / Mongo
    ("fileserver", frozenset({139, 445, 2049})),           # SMB / NFS
    ("app", frozenset({8080, 8443, 8000, 9090, 7001})),    # app servers, WebLogic
    ("web", frozenset({80, 443, 8081})),
]
DEFAULT_ROLE = "workstation"

# Same business-impact table the synthetic generator uses, so results are comparable.
ROLE_CRITICALITY = {"db": 9, "dc": 9, "fileserver": 6, "app": 5, "web": 3, "workstation": 2}


@dataclass
class ScannedService:
    port: int
    protocol: str
    name: str                     # nmap's service name, e.g. "https"
    product: str                  # "nginx 1.18.0" - product + version, as reported
    cpes: tuple[str, ...] = ()    # CPE identifiers, the hook for CVE matching
    cve_ids: tuple[str, ...] = () # CVEs reported by an NSE script on this port


@dataclass
class ScannedHost:
    address: str                  # IPv4 address - the stable identity
    hostname: str = ""            # PTR/user hostname if nmap resolved one
    os_guess: str = ""
    services: list[ScannedService] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Prefer a hostname: `web-01` reads better in a path than `192.168.56.11`.
        Strip the domain so the label stays short on the dashboard graph."""
        return self.hostname.split(".")[0] if self.hostname else self.address


@dataclass
class ScanResult:
    hosts: list[ScannedHost] = field(default_factory=list)
    vantage: str = "internet"     # the zone the scanner itself sat in
    args: str = ""                # the nmap command line, kept for the report
    started: str = ""
    source: str = ""              # file it was parsed from

    def all_cves(self) -> set[str]:
        return {c for h in self.hosts for s in h.services for c in s.cve_ids}


# ---------------------------------------------------------------------------
# Stage 1: XML -> facts
# ---------------------------------------------------------------------------

def _service_cves(port_el: ET.Element) -> tuple[str, ...]:
    """CVE IDs from NSE script output on this port.

    Handles both shapes `vulners` emits: the structured <table> form and the plain
    text form. We regex the whole serialised element rather than walking the table
    schema, because vulners, vulscan and custom scripts all format it differently and
    a CVE ID is unambiguous wherever it appears.
    """
    found: set[str] = set()
    for script in port_el.findall("script"):
        blob = (script.get("output") or "") + ET.tostring(script, encoding="unicode")
        found.update(CVE_RE.findall(blob))
    return tuple(sorted(found))


def _parse_host(host_el: ET.Element) -> ScannedHost | None:
    status = host_el.find("status")
    if status is not None and status.get("state") != "up":
        return None

    address = ""
    for a in host_el.findall("address"):
        if a.get("addrtype") == "ipv4":
            address = a.get("addr", "")
            break
    if not address:
        return None

    hostname = ""
    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name", "")

    os_guess = ""
    osm = host_el.find("os/osmatch")
    if osm is not None:
        os_guess = osm.get("name", "")

    services: list[ScannedService] = []
    for p in host_el.findall("ports/port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue                     # filtered/closed ports are not attack surface
        svc = p.find("service")
        name = svc.get("name", "unknown") if svc is not None else "unknown"
        product = ""
        cpes: tuple[str, ...] = ()
        if svc is not None:
            product = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
            cpes = tuple(c.text for c in svc.findall("cpe") if c.text)
        services.append(ScannedService(
            port=int(p.get("portid", 0)),
            protocol=p.get("protocol", "tcp"),
            name=name,
            product=product or name,
            cpes=cpes,
            cve_ids=_service_cves(p),
        ))
    return ScannedHost(address=address, hostname=hostname, os_guess=os_guess,
                       services=services)


def parse_nmap_xml(path: str | Path, vantage: str = "internet") -> ScanResult:
    """Parse one `nmap -oX` file. `vantage` is the zone the scan was launched from.

    Pure function: no network, no nmap binary, no modelling. Everything it returns is
    something nmap literally reported.
    """
    path = Path(path)
    root = ET.parse(path).getroot()
    if root.tag != "nmaprun":
        raise ValueError(f"{path} is not nmap XML (root element is <{root.tag}>)")
    hosts = [h for h in (_parse_host(e) for e in root.findall("host")) if h]
    return ScanResult(hosts=hosts, vantage=vantage, args=root.get("args", ""),
                      started=root.get("startstr", ""), source=str(path))


# ---------------------------------------------------------------------------
# Stage 2: facts -> Network (every step here is a modelling choice)
# ---------------------------------------------------------------------------

def infer_role(svc_ports: set[int]) -> str:
    """Guess what a host is for from its open ports.

    Modelling choice: first signature to match wins, most specific first. This is a
    heuristic and it is allowed to be wrong - `--roles` on the import script lets the
    operator override it, which is what you would do with real asset inventory.
    """
    for role, ports in ROLE_SIGNATURES:
        if svc_ports & ports:
            return role
    return DEFAULT_ROLE


def infer_zone(address: str, zone_map: dict[str, str] | None) -> str:
    """Map an IP to a network zone.

    With a zone map ({"192.168.56.0/24": "dmz"}), use it. Without one, fall back to one
    zone per /24 named `net-192.168.56`, which at least preserves real segmentation
    boundaries instead of flattening everything into a single zone.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    for cidr, zone in (zone_map or {}).items():
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return zone
        except ValueError:
            continue
    if isinstance(ip, ipaddress.IPv4Address):
        return "net-" + ".".join(address.split(".")[:3])
    return "unknown"


def observed_firewall(hosts: list[Host], vantage: str) -> dict[tuple[str, str], frozenset[int]]:
    """Reachability we are willing to assert, given we only scanned from one place.

    Modelling choice, and the most important one in this file. We assert:
      1. vantage -> every zone, on the ports we actually saw open there. This is
         *measured*: the scanner reached those ports from where it sat.
      2. every zone -> every zone, on every open port. This is *assumed*, and it is the
         pessimistic assumption - real segmentation can only remove paths, never add
         them, so the engine reports a superset of the true attack paths.

    To replace assumption (2) with measurement, scan again from inside each zone and
    merge the results with `merge_scans()`; each scan contributes a measured row.
    """
    ports_by_zone: dict[str, set[int]] = {}
    for h in hosts:
        ports_by_zone.setdefault(h.zone, set()).update(s.port for s in h.services)
    fw: dict[tuple[str, str], frozenset[int]] = {}
    for dst, ports in ports_by_zone.items():
        fw[(vantage, dst)] = frozenset(ports)
        for src in ports_by_zone:
            fw.setdefault((src, dst), frozenset(ports))
    return fw


def network_from_scan(scan: ScanResult,
                      zone_map: dict[str, str] | None = None,
                      roles: dict[str, str] | None = None,
                      criticality: dict[str, int] | None = None,
                      firewall: dict[tuple[str, str], frozenset[int]] | None = None,
                      known_cves: set[str] | None = None) -> tuple[Network, list[str]]:
    """Turn scan facts into a Network the engine can analyse.

    Returns the Network and a list of warnings - things the operator should know are
    assumptions rather than measurements. Print them; do not hide them.

    `known_cves` is the set of CVE IDs our catalog can actually score. CVEs nmap found
    that we cannot score are dropped and reported, because an unscoreable CVE would
    otherwise silently become a zero-probability edge and quietly hide a real path.
    """
    warnings: list[str] = []
    hosts: dict[str, Host] = {}
    dropped: set[str] = set()

    for sh in scan.hosts:
        if not sh.services:
            continue                     # a host with no open ports has no attack surface
        hid = sh.id
        if hid in hosts:                 # two hosts resolving to the same short name
            hid = f"{sh.id}-{sh.address.split('.')[-1]}"
        ports = {s.port for s in sh.services}
        role = (roles or {}).get(sh.address) or (roles or {}).get(hid) or infer_role(ports)
        zone = infer_zone(sh.address, zone_map)
        crit = ((criticality or {}).get(sh.address)
                or (criticality or {}).get(hid)
                or ROLE_CRITICALITY.get(role, 2))

        services = []
        for s in sh.services:
            cves = tuple(c for c in s.cve_ids if known_cves is None or c in known_cves)
            dropped.update(set(s.cve_ids) - set(cves))
            services.append(Service(name=s.name, port=s.port,
                                    product=s.product or s.name, cve_ids=cves))
        hosts[hid] = Host(id=hid, role=role, zone=zone, criticality=crit, services=services)

    if not hosts:
        raise ValueError(f"No hosts with open ports in {scan.source}. "
                         "Did the scan run with -sV against live targets?")

    fw = firewall if firewall is not None else observed_firewall(list(hosts.values()),
                                                                 scan.vantage)
    if firewall is None:
        warnings.append(
            f"Firewall policy was not supplied. Reachability from '{scan.vantage}' is "
            "measured; traffic between all other zone pairs is ASSUMED open on every "
            "observed port. This over-reports paths (the safe direction). Supply a "
            "policy, or scan from inside each zone and merge, to tighten it.")
    if not any(s.cve_ids for h in hosts.values() for s in h.services):
        warnings.append(
            "No CVEs found in the scan, so the attack graph will have no exploit edges. "
            "Re-run nmap with `--script vulners` (or supply CVEs another way).")
    if dropped:
        warnings.append(
            f"{len(dropped)} CVE(s) reported by nmap are not in the local catalog and were "
            f"dropped: {', '.join(sorted(dropped)[:8])}"
            f"{'...' if len(dropped) > 8 else ''}. Add them to data/cve_seeds.txt and "
            "re-run `python -m scripts.fetch_feeds` to include them.")
    warnings.append(
        "No identity data: nmap cannot see logon sessions or admin rights, so the graph "
        "has exploit edges only and no credential-reuse edges. Real deployments get this "
        "from BloodHound/SharpHound or Active Directory.")

    net = Network(hosts=hosts, users={}, sessions=[], admin_of=[], firewall=fw)
    if not net.crown_jewels():
        top = max(hosts.values(), key=lambda h: h.criticality)
        warnings.append(
            f"No host reached the crown-jewel threshold (criticality >= 8); the most "
            f"critical is {top.id} at {top.criticality}. Pass a criticality map, or call "
            "crown_jewels(min_criticality=...) with a lower bar.")
    return net, warnings


def merge_scans(scans: list[ScanResult],
                zone_map: dict[str, str] | None = None,
                **kwargs) -> tuple[Network, list[str]]:
    """Combine scans taken from different vantage points into one Network.

    This is how you replace the pessimistic reachability assumption with measurement:
    scan the same estate from the internet, from the DMZ and from a corporate
    workstation, and each scan contributes one measured `(vantage_zone, dst_zone)` row
    of the firewall matrix. Ports nobody could reach from anywhere stay unreachable.
    """
    if not scans:
        raise ValueError("merge_scans() needs at least one scan")
    merged = ScanResult(vantage=scans[0].vantage,
                        args=" | ".join(s.args for s in scans),
                        source=", ".join(s.source for s in scans))
    by_addr: dict[str, ScannedHost] = {}
    for scan in scans:
        for h in scan.hosts:
            if h.address not in by_addr:
                by_addr[h.address] = h
            else:
                seen = {s.port for s in by_addr[h.address].services}
                by_addr[h.address].services += [s for s in h.services if s.port not in seen]
    merged.hosts = list(by_addr.values())

    net, warnings = network_from_scan(merged, zone_map=zone_map, firewall={}, **kwargs)
    fw: dict[tuple[str, str], frozenset[int]] = {}
    for scan in scans:                               # one measured row per vantage point
        reachable: dict[str, set[int]] = {}
        for h in scan.hosts:
            z = infer_zone(h.address, zone_map)
            reachable.setdefault(z, set()).update(s.port for s in h.services)
        for dst, ports in reachable.items():
            fw[(scan.vantage, dst)] = fw.get((scan.vantage, dst), frozenset()) | frozenset(ports)
    net.firewall = fw
    warnings = [w for w in warnings if not w.startswith("Firewall policy")]
    warnings.insert(0, f"Reachability measured from {len(scans)} vantage point(s): "
                       f"{', '.join(sorted({s.vantage for s in scans}))}.")
    return net, warnings
