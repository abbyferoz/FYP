"""The vulnerability catalog the engine scores against, and what runs on each host role.

Two different kinds of thing live here, and the difference matters:

  VULNS              FACTS about real vulnerabilities - CVSS vectors, KEV status.
                     Loaded from the NVD and CISA KEV caches by apg/feeds.py. Not
                     invented here, not editable here.
  SERVICE_TEMPLATES  A MODEL of what software a given kind of host runs. This is our
                     design, it is synthetic, and it only drives the synthetic
                     generator. A network imported from a real nmap scan never touches
                     it - the scan supplies the real services.

If the NVD cache is missing (fresh clone, no `python -m scripts.fetch_feeds` yet), we
fall back to a small hand-entered set so the project still runs, and say so loudly via
`FEED_META.summary()`. Falling back silently would be the dangerous option: you would
demo illustrative numbers believing they were real.
"""
from __future__ import annotations

from apg.feeds import FeedError, FeedMeta, load_catalog
from apg.model import Vuln

# Hand-entered emergency fallback. Verified against nvd.nist.gov at time of writing, but
# the feed cache is the source of truth - this exists so a fresh clone is never broken.
_FALLBACK: list[Vuln] = [
    Vuln("CVE-2021-44228", "Apache Log4Shell (Log4j2 JNDI RCE)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev=True, nvd_base=10.0, source="manual"),
    Vuln("CVE-2017-0144", "Microsoft EternalBlue (SMBv1 RCE)",
         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=8.8, source="manual"),
    Vuln("CVE-2019-0708", "Microsoft BlueKeep (RDP RCE)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=9.8, source="manual"),
    Vuln("CVE-2021-34527", "Microsoft PrintNightmare (Print Spooler RCE)",
         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=8.8, source="manual"),
    Vuln("CVE-2020-1472", "Microsoft Zerologon (Netlogon EoP)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev=True, nvd_base=10.0, source="manual"),
    Vuln("CVE-2014-0160", "OpenSSL Heartbleed (TLS heartbeat memory disclosure)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", kev=True, nvd_base=7.5, source="manual"),
    Vuln("CVE-2022-22965", "VMware Spring4Shell (Spring Framework RCE)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=9.8, source="manual"),
    Vuln("CVE-2017-5638", "Apache Struts2 Content-Type RCE",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=9.8, source="manual"),
    Vuln("CVE-2020-0618", "Microsoft SQL Server Reporting Services RCE",
         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=8.8, source="manual"),
    Vuln("CVE-2021-4034", "polkit PwnKit (pkexec local privilege escalation)",
         "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", kev=True, nvd_base=7.8, source="manual"),
]

try:
    VULNS, FEED_META = load_catalog()
    if not VULNS:
        raise FeedError("NVD cache is empty")
except FeedError:
    VULNS = {v.cve_id: v for v in _FALLBACK}
    FEED_META = FeedMeta(nvd_count=len(VULNS), kev_matched=sum(v.kev for v in VULNS.values()),
                         source="fallback")


def have(*cve_ids: str) -> tuple[str, ...]:
    """Keep only CVEs the loaded catalog can actually score.

    The service templates below name more CVEs than a minimal fallback catalog holds.
    Filtering here means the generator degrades to fewer vulnerabilities instead of
    raising a KeyError deep inside the attack-graph build.
    """
    return tuple(c for c in cve_ids if c in VULNS)


# ---------------------------------------------------------------------------
# Synthetic-network modelling: what each kind of host runs, and what may be wrong
# with it. Each entry is (service name, port, product, candidate CVEs). The generator
# rolls `vuln_rate` per service and, on a hit, picks one candidate - so two hosts of
# the same role get different weaknesses, which is what makes chokepoint analysis and
# patch prioritisation non-trivial.
# ---------------------------------------------------------------------------
SERVICE_TEMPLATES: dict[str, list[tuple[str, int, str, tuple[str, ...]]]] = {
    "web": [
        ("https-app", 443, "Java web app behind nginx (Log4j 2.14)",
         have("CVE-2021-44228", "CVE-2021-45046")),
        ("tls", 443, "OpenSSL 1.0.1f", have("CVE-2014-0160")),
        ("http-admin", 80, "Apache httpd 2.4.49 admin panel",
         have("CVE-2021-41773", "CVE-2017-5638", "CVE-2018-7600")),
        ("app-backend", 8080, "Internal API gateway", ()),
    ],
    "app": [
        ("http-app", 8080, "Spring MVC / Tomcat",
         have("CVE-2022-22965", "CVE-2020-14882", "CVE-2017-10271")),
        ("confluence", 8090, "Atlassian Confluence",
         have("CVE-2022-26134", "CVE-2021-26084")),
        ("smb", 445, "Windows SMB", have("CVE-2017-0144", "CVE-2020-0796")),
    ],
    "fileserver": [
        ("smb", 445, "Windows SMBv1 file share",
         have("CVE-2017-0144", "CVE-2017-0143", "CVE-2020-0796")),
        ("rdp", 3389, "Windows RDP", have("CVE-2019-0708", "CVE-2019-1181")),
        ("spooler", 135, "Windows Print Spooler",
         have("CVE-2021-34527", "CVE-2021-1675")),
    ],
    "dc": [
        ("netlogon", 135, "Windows Netlogon RPC",
         have("CVE-2020-1472", "CVE-2022-34718")),
        ("ldap", 389, "Active Directory LDAP",
         have("CVE-2021-42278", "CVE-2021-42287", "CVE-2022-26923")),
        ("smb", 445, "Windows Print Spooler on DC",
         have("CVE-2021-34527", "CVE-2019-1040")),
    ],
    "db": [
        ("mssql", 1433, "Microsoft SQL Server 2017",
         have("CVE-2020-0618", "CVE-2019-1068")),
        ("smb", 445, "Windows SMB", have("CVE-2017-0144", "CVE-2023-21554")),
    ],
    "workstation": [
        ("smb", 445, "Windows SMB / Print Spooler",
         have("CVE-2021-34527", "CVE-2022-21999", "CVE-2017-0144")),
        ("rdp", 3389, "Windows RDP", have("CVE-2019-0708", "CVE-2019-1181")),
    ],
}

# The one CVE the generator guarantees on the internet-facing web server, so every
# generated network has at least one foothold and experiments are comparable.
GUARANTEED_ENTRY = "CVE-2021-44228" if "CVE-2021-44228" in VULNS else next(iter(VULNS))
