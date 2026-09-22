"""Core data model: what an enterprise network looks like to the engine."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Vuln:
    """One vulnerability, as the engine sees it.

    The first four fields are all the attack-path engine actually needs; everything
    after them is provenance carried over from the NVD/KEV feeds so the dashboard and
    the report can show where a number came from. `nvd_base` is NVD's own published
    base score, kept alongside the vector so tests can prove apg/cvss.py reproduces it
    rather than us quietly trusting a stored value.
    """
    cve_id: str
    title: str
    vector: str          # CVSS v3.1 vector string
    kev: bool = False    # listed in CISA Known Exploited Vulnerabilities
    nvd_base: float | None = None    # NVD's published base score, for cross-checking
    published: str = ""              # NVD publication date, YYYY-MM-DD
    ransomware: bool = False         # KEV flags known use in ransomware campaigns
    kev_date: str = ""               # date CISA added it to KEV
    cwes: tuple[str, ...] = ()       # CWE weakness classes
    source: str = "nvd"              # "nvd" | "manual"


@dataclass
class Service:
    name: str
    port: int
    product: str
    cve_ids: tuple[str, ...] = ()   # vulnerabilities actually present on this instance


@dataclass
class Host:
    id: str
    role: str            # web | app | fileserver | dc | db | workstation
    zone: str            # dmz | corp | servers | data
    criticality: int     # business impact of losing this host, 1-10
    services: list[Service] = field(default_factory=list)


@dataclass
class User:
    id: str
    privilege: str       # user | admin | domain_admin


@dataclass
class Network:
    hosts: dict[str, Host]
    users: dict[str, User]
    sessions: list[tuple[str, str]]     # (user_id, host_id): user has a logon session there
    admin_of: list[tuple[str, str]]     # (user_id, host_id): user has admin rights on host
    firewall: dict[tuple[str, str], frozenset[int]]   # (src_zone, dst_zone) -> allowed ports

    def allows(self, src_zone: str, dst_zone: str, port: int) -> bool:
        return port in self.firewall.get((src_zone, dst_zone), frozenset())

    def crown_jewels(self, min_criticality: int = 8) -> list[str]:
        return sorted(h.id for h in self.hosts.values() if h.criticality >= min_criticality)
