"""Real vulnerability data: the NVD CVE cache and the CISA KEV catalog.

This module is the boundary between "facts about vulnerabilities in the world" and
"our model of them". Everything downstream (scoring, attack graph, remediation) takes
its CVSS vectors and its known-exploited flags from here, so there is exactly one
place to look when a jury member asks where a number came from.

It only *reads*; `scripts/fetch_feeds.py` does the downloading. That split matters:
loading is pure and deterministic, so tests can run it against fixtures with no
network, and the demonstrator works in a room with no internet.

    from apg.feeds import load_catalog
    vulns, meta = load_catalog()
    vulns["CVE-2021-44228"].kev        # True
    meta.nvd_fetched_at                # snapshot the numbers came from
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from apg.model import Vuln

DATA = Path(__file__).resolve().parent.parent / "data"
NVD_CACHE = DATA / "nvd_cves.json"
KEV_CACHE = DATA / "kev.json"


class FeedError(RuntimeError):
    """A cache file is missing or malformed. Caller decides whether to fall back."""


@dataclass(frozen=True)
class FeedMeta:
    """Provenance of the loaded data - quote this in the report, not 'about 70 CVEs'."""
    nvd_count: int = 0
    nvd_fetched_at: str = ""
    kev_count: int = 0
    kev_version: str = ""
    kev_fetched_at: str = ""
    kev_matched: int = 0        # how many of our CVEs are in KEV
    ransomware_matched: int = 0
    source: str = "cache"       # "cache" | "fallback"

    def summary(self) -> str:
        if self.source == "fallback":
            return ("hand-entered catalog (no NVD cache found - "
                    "run `python -m scripts.fetch_feeds`)")
        return (f"{self.nvd_count} CVEs from NVD (snapshot {self.nvd_fetched_at[:10]}), "
                f"{self.kev_matched} of them in CISA KEV "
                f"(catalog {self.kev_version}, {self.kev_count} entries)")


def _read(path: Path) -> dict:
    if not path.exists():
        raise FeedError(f"{path} not found - run `python -m scripts.fetch_feeds`")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise FeedError(f"{path} is not valid JSON: {e}") from e


def load_kev(path: Path = KEV_CACHE) -> tuple[dict[str, dict], dict]:
    """CISA Known Exploited Vulnerabilities: CVE id -> entry, plus the feed metadata.

    KEV is the single most useful signal we have that is *not* in CVSS: it means the
    vulnerability has been observed being exploited in the wild, not merely that it
    could be. apg/scoring.py uses it to raise exploit probability.
    """
    raw = _read(path)
    return raw.get("entries", {}), raw.get("_meta", {})


def load_nvd(path: Path = NVD_CACHE) -> tuple[dict[str, dict], dict]:
    """Cached NVD records: CVE id -> trimmed record, plus the feed metadata."""
    raw = _read(path)
    return raw.get("entries", {}), raw.get("_meta", {})


def _title(rec: dict, kev_entry: dict | None) -> str:
    """A short human label. KEV's curated vulnerability name is far more readable than
    NVD's first sentence, so prefer it when the CVE is in KEV."""
    if kev_entry and kev_entry.get("name"):
        vendor = kev_entry.get("vendor", "")
        return f"{vendor} {kev_entry['name']}".strip() if vendor else kev_entry["name"]
    desc = rec.get("description", "")
    return (desc[:117] + "...") if len(desc) > 120 else desc or rec["id"]


def build_vulns(nvd: dict[str, dict], kev: dict[str, dict]) -> dict[str, Vuln]:
    """Join the two feeds into the Vuln objects the engine uses.

    NVD supplies the CVSS vector; KEV supplies the exploited-in-the-wild flag. A CVE
    with no v3 vector cannot be scored by apg/cvss.py, so it is dropped rather than
    silently defaulted - a wrong score is worse than a missing one.
    """
    out: dict[str, Vuln] = {}
    for cve_id, rec in nvd.items():
        vector = rec.get("vector", "")
        if not vector.startswith("CVSS:3"):
            continue
        k = kev.get(cve_id)
        out[cve_id] = Vuln(
            cve_id=cve_id,
            title=_title(rec, k),
            vector=vector,
            kev=k is not None,
            nvd_base=rec.get("nvd_base_score"),
            published=rec.get("published", ""),
            ransomware=bool(k and k.get("ransomware")),
            kev_date=(k or {}).get("date_added", ""),
            cwes=tuple(rec.get("cwes", ())),
            source="nvd",
        )
    return out


def load_catalog(nvd_path: Path = NVD_CACHE,
                 kev_path: Path = KEV_CACHE) -> tuple[dict[str, Vuln], FeedMeta]:
    """The whole pipeline: read both caches, join them, report what was loaded.

    Raises FeedError if the NVD cache is missing. A missing *KEV* cache is survivable
    (every CVE simply looks not-known-exploited), so it degrades instead of failing.
    """
    nvd, nvd_meta = load_nvd(nvd_path)
    try:
        kev, kev_meta = load_kev(kev_path)
    except FeedError:
        kev, kev_meta = {}, {}
    vulns = build_vulns(nvd, kev)
    return vulns, FeedMeta(
        nvd_count=len(vulns),
        nvd_fetched_at=nvd_meta.get("fetched_at", ""),
        kev_count=kev_meta.get("count", len(kev)),
        kev_version=kev_meta.get("catalog_version", ""),
        kev_fetched_at=kev_meta.get("fetched_at", ""),
        kev_matched=sum(1 for v in vulns.values() if v.kev),
        ransomware_matched=sum(1 for v in vulns.values() if v.ransomware),
        source="cache",
    )
