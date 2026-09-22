"""Download real vulnerability data: NVD CVE records + the CISA KEV catalog.

    python -m scripts.fetch_feeds                 # refresh both caches
    python -m scripts.fetch_feeds --kev-only      # just the KEV catalog (one request)
    python -m scripts.fetch_feeds --api-key KEY   # faster: 50 req/30s instead of 5

Why a cache instead of live calls: the engine must produce identical results every run
(reproducible experiments), the NVD rate-limits anonymous callers to 5 requests per 30
seconds, and the demonstrator has to work in a room with no internet. The caches under
data/ are committed to git and carry a `fetched_at` timestamp so the report can state
exactly which snapshot the numbers came from.

Uses only the standard library on purpose: one less thing to install before a demo.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
SEEDS = DATA / "cve_seeds.txt"
NVD_CACHE = DATA / "nvd_cves.json"
KEV_CACHE = DATA / "kev.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = "attack-path-intel/1.0 (IBA FYP; academic research)"


def _get(url: str, api_key: str | None = None, timeout: int = 45) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def read_seeds(path: Path = SEEDS) -> list[str]:
    """CVE IDs from the seed file, ignoring comments and inline `# ...` notes."""
    ids = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line.startswith("CVE-"):
            ids.append(line)
    return ids


def pick_cvss(metrics: dict) -> dict | None:
    """The CVSS v3.x metric to trust, in preference order.

    NVD often carries several scorings for one CVE: its own analyst score plus scores
    submitted by the vendor (a CNA). We prefer NVD's Primary v3.1 so every CVE is scored
    on the same basis, then any v3.1, then v3.0. CVEs older than 2015 may only have v2,
    which this project does not model - those are skipped and reported.
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        for want_primary in (True, False):
            for e in entries:
                is_primary = e.get("source") == "nvd@nist.gov" or e.get("type") == "Primary"
                if is_primary == want_primary:
                    return e
    return None


def trim_cve(cve: dict) -> dict | None:
    """NVD's API record -> the small record we cache. Returns None if there is no v3 score."""
    metric = pick_cvss(cve.get("metrics", {}))
    if not metric:
        return None
    d = metric["cvssData"]
    english = next((x["value"] for x in cve.get("descriptions", []) if x["lang"] == "en"), "")
    cwes = sorted({x["value"] for w in cve.get("weaknesses", [])
                   for x in w.get("description", []) if x["value"].startswith("CWE-")})
    return {
        "id": cve["id"],
        "published": cve.get("published", "")[:10],
        "description": " ".join(english.split())[:400],
        "vector": d["vectorString"],
        "cvss_version": d.get("version", ""),
        "cvss_source": metric.get("source", ""),
        # NVD's own numbers, kept so tests can prove apg/cvss.py reproduces them.
        "nvd_base_score": d["baseScore"],
        "nvd_exploitability": metric.get("exploitabilityScore"),
        "nvd_impact": metric.get("impactScore"),
        "cwes": cwes,
    }


def fetch_kev(api_key: str | None = None) -> dict:
    print(f"KEV: fetching {KEV_URL}")
    raw = _get(KEV_URL)
    entries = {}
    for v in raw.get("vulnerabilities", []):
        entries[v["cveID"]] = {
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
        }
    print(f"KEV: {len(entries)} known-exploited vulnerabilities "
          f"(catalog version {raw.get('catalogVersion', '?')})")
    return {
        "_meta": {
            "source": KEV_URL,
            "catalog_version": raw.get("catalogVersion", ""),
            "date_released": raw.get("dateReleased", ""),
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "count": len(entries),
        },
        "entries": entries,
    }


def fetch_nvd(cve_ids: list[str], api_key: str | None, delay: float,
              existing: dict | None = None) -> dict:
    """One request per CVE. NVD has no bulk-by-id endpoint, so we pace ourselves:
    5 requests / 30s anonymously, 50 / 30s with a free API key from nvd.nist.gov."""
    out = dict((existing or {}).get("entries", {}))
    skipped: list[str] = []
    failed: list[str] = []
    for i, cve_id in enumerate(cve_ids, 1):
        try:
            data = _get(NVD_API + cve_id, api_key)
            items = data.get("vulnerabilities", [])
            if not items:
                failed.append(f"{cve_id} (not found)")
            else:
                rec = trim_cve(items[0]["cve"])
                if rec is None:
                    skipped.append(cve_id)
                else:
                    out[cve_id] = rec
                    print(f"  [{i:>3}/{len(cve_ids)}] {cve_id}  base={rec['nvd_base_score']:<4} "
                          f"{rec['vector']}")
        except urllib.error.HTTPError as e:
            failed.append(f"{cve_id} (HTTP {e.code})")
            if e.code == 403:
                print("  rate limited - backing off 30s", file=sys.stderr)
                time.sleep(30)
        except Exception as e:                                    # noqa: BLE001
            failed.append(f"{cve_id} ({type(e).__name__})")
        if i < len(cve_ids):
            time.sleep(delay)

    if skipped:
        print(f"\nNo CVSS v3 score (CVSS v2 only), skipped: {', '.join(skipped)}")
    if failed:
        print(f"Failed: {', '.join(failed)}", file=sys.stderr)
    return {
        "_meta": {
            "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "requested": len(cve_ids),
            "count": len(out),
            "skipped_no_v3": skipped,
            "failed": failed,
        },
        "entries": out,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api-key", help="NVD API key (free from nvd.nist.gov/developers/request-an-api-key)")
    ap.add_argument("--delay", type=float, default=None,
                    help="seconds between NVD requests (default 6.5 anonymous, 0.8 with a key)")
    ap.add_argument("--kev-only", action="store_true", help="refresh only the KEV catalog")
    ap.add_argument("--nvd-only", action="store_true", help="refresh only the NVD cache")
    a = ap.parse_args()
    DATA.mkdir(exist_ok=True)

    if not a.nvd_only:
        KEV_CACHE.write_text(json.dumps(fetch_kev(), indent=1, sort_keys=True))
        print(f"KEV: wrote {KEV_CACHE.relative_to(DATA.parent)} "
              f"({KEV_CACHE.stat().st_size // 1024} KB)\n")

    if not a.kev_only:
        ids = read_seeds()
        delay = a.delay if a.delay is not None else (0.8 if a.api_key else 6.5)
        eta = len(ids) * delay / 60
        print(f"NVD: {len(ids)} CVEs, {delay}s apart, about {eta:.1f} min"
              f"{' (using API key)' if a.api_key else ' (anonymous: 5 requests / 30s)'}")
        existing = json.loads(NVD_CACHE.read_text()) if NVD_CACHE.exists() else None
        cache = fetch_nvd(ids, a.api_key, delay, existing)
        NVD_CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))
        print(f"\nNVD: {cache['_meta']['count']}/{cache['_meta']['requested']} cached in "
              f"{NVD_CACHE.relative_to(DATA.parent)} ({NVD_CACHE.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
