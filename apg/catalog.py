"""Small bundled vulnerability catalog for the M1 demonstrator.

The CVE IDs and CVSS vectors below are well-known public vulnerabilities, entered by
hand. VERIFY them against the NVD (nvd.nist.gov) and the CISA KEV catalog before
quoting numbers in the proposal or report. IDs starting with SYN- are synthetic
placeholders. A real NVD/KEV loader replaces this file in the data-pipeline step.
"""
from __future__ import annotations

from apg.model import Vuln

VULNS: dict[str, Vuln] = {v.cve_id: v for v in [
    Vuln("CVE-2021-44228", "Log4Shell: Apache Log4j2 JNDI remote code execution",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev=True),
    Vuln("CVE-2017-0144", "EternalBlue: Microsoft SMBv1 remote code execution",
         "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True),
    Vuln("CVE-2019-0708", "BlueKeep: Windows RDP remote code execution",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True),
    Vuln("CVE-2021-34527", "PrintNightmare: Windows Print Spooler remote code execution",
         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", kev=True),
    Vuln("CVE-2020-1472", "Zerologon: Netlogon elevation of privilege",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev=True),
    Vuln("CVE-2014-0160", "Heartbleed: OpenSSL TLS heartbeat memory disclosure",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", kev=True),
    Vuln("CVE-2022-22965", "Spring4Shell: Spring Framework remote code execution",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True),
    Vuln("SYN-2026-0001", "Synthetic: outdated intranet CMS with authenticated file upload",
         "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    Vuln("SYN-2026-0002", "Synthetic: admin panel exposed with default credentials",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    Vuln("SYN-2026-0003", "Synthetic: SQL Server weak authentication",
         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
]}

# role -> service templates: (name, port, product, cve that may be present)
SERVICE_TEMPLATES: dict[str, list[tuple[str, int, str, str]]] = {
    "web": [
        ("https-app", 443, "Java web app behind nginx (Log4j 2.14)", "CVE-2021-44228"),
        ("tls", 443, "OpenSSL 1.0.1f", "CVE-2014-0160"),
        ("http-admin", 80, "Admin panel", "SYN-2026-0002"),
        ("app-backend", 8080, "Internal API", ""),
    ],
    "app": [
        ("http-app", 8080, "Spring MVC app", "CVE-2022-22965"),
        ("smb", 445, "Windows SMB", "CVE-2017-0144"),
    ],
    "fileserver": [
        ("smb", 445, "Windows SMBv1", "CVE-2017-0144"),
        ("rdp", 3389, "Windows RDP", "CVE-2019-0708"),
    ],
    "dc": [
        ("netlogon", 135, "Windows Netlogon RPC", "CVE-2020-1472"),
        ("smb", 445, "Windows Print Spooler", "CVE-2021-34527"),
    ],
    "db": [
        ("mssql", 1433, "SQL Server", "SYN-2026-0003"),
        ("smb", 445, "Windows SMB", "CVE-2017-0144"),
    ],
    "workstation": [
        ("smb", 445, "Windows SMB / Print Spooler", "CVE-2021-34527"),
        ("rdp", 3389, "Windows RDP", "CVE-2019-0708"),
    ],
}
