"""The feed layer: do NVD and KEV records become correct Vuln objects?

Tested against fixtures written inline rather than the real cache, so these tests pin
the parsing logic and keep passing when the cache is refreshed and scores move.
"""
import json

import pytest

from apg.feeds import FeedError, build_vulns, load_catalog, load_kev, load_nvd

NVD_FIXTURE = {
    "_meta": {"fetched_at": "2026-09-22T08:00:00+00:00", "count": 3, "requested": 4},
    "entries": {
        "CVE-2021-44228": {
            "id": "CVE-2021-44228", "published": "2021-12-10",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_version": "3.1", "cvss_source": "nvd@nist.gov",
            "nvd_base_score": 10.0, "nvd_exploitability": 3.9, "nvd_impact": 6.0,
            "cwes": ["CWE-502", "CWE-917"],
        },
        "CVE-2014-0160": {
            "id": "CVE-2014-0160", "published": "2014-04-07",
            "description": "The TLS heartbeat extension in OpenSSL does not properly handle Heartbeat packets.",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_version": "3.1", "cvss_source": "nvd@nist.gov",
            "nvd_base_score": 7.5, "cwes": ["CWE-125"],
        },
        # No v3 vector: must be dropped, not defaulted to something plausible.
        "CVE-1999-0001": {
            "id": "CVE-1999-0001", "published": "1999-12-30",
            "description": "Old vulnerability with only a CVSS v2 score.",
            "vector": "", "nvd_base_score": None, "cwes": [],
        },
    },
}

KEV_FIXTURE = {
    "_meta": {"catalog_version": "2026.09.21", "count": 2,
              "fetched_at": "2026-09-22T08:00:00+00:00"},
    "entries": {
        "CVE-2021-44228": {"name": "Apache Log4j2 Remote Code Execution Vulnerability",
                           "vendor": "Apache", "product": "Log4j2",
                           "date_added": "2021-12-10", "due_date": "2021-12-24",
                           "ransomware": True},
        "CVE-2014-0160": {"name": "OpenSSL Information Disclosure Vulnerability",
                          "vendor": "OpenSSL", "product": "OpenSSL",
                          "date_added": "2022-05-04", "due_date": "2022-05-25",
                          "ransomware": False},
    },
}


@pytest.fixture
def caches(tmp_path):
    nvd = tmp_path / "nvd.json"
    kev = tmp_path / "kev.json"
    nvd.write_text(json.dumps(NVD_FIXTURE))
    kev.write_text(json.dumps(KEV_FIXTURE))
    return nvd, kev


def test_joins_nvd_vectors_with_kev_status(caches):
    vulns, meta = load_catalog(*caches)
    log4shell = vulns["CVE-2021-44228"]
    assert log4shell.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert log4shell.nvd_base == 10.0
    assert log4shell.kev is True
    assert log4shell.ransomware is True
    assert log4shell.kev_date == "2021-12-10"
    assert log4shell.cwes == ("CWE-502", "CWE-917")
    assert log4shell.source == "nvd"


def test_kev_supplies_the_readable_title(caches):
    vulns, _ = load_catalog(*caches)
    assert vulns["CVE-2021-44228"].title == "Apache Apache Log4j2 Remote Code Execution Vulnerability"


def test_cves_without_a_v3_vector_are_dropped_not_defaulted(caches):
    """A CVE we cannot score must not reach the engine with an invented score."""
    vulns, meta = load_catalog(*caches)
    assert "CVE-1999-0001" not in vulns
    assert meta.nvd_count == 2


def test_metadata_records_provenance(caches):
    _, meta = load_catalog(*caches)
    assert meta.source == "cache"
    assert meta.nvd_fetched_at.startswith("2026-09-22")
    assert meta.kev_version == "2026.09.21"
    assert meta.kev_matched == 2
    assert meta.ransomware_matched == 1
    assert "2026-09-22" in meta.summary()


def test_a_missing_kev_cache_degrades_instead_of_failing(caches, tmp_path):
    """KEV only raises exploit probability. Without it everything simply looks
    not-known-exploited, which is worse analysis but still analysis."""
    nvd, _ = caches
    vulns, meta = load_catalog(nvd, tmp_path / "does_not_exist.json")
    assert len(vulns) == 2
    assert all(not v.kev for v in vulns.values())
    assert meta.kev_matched == 0


def test_a_missing_nvd_cache_raises_so_the_caller_can_fall_back(tmp_path):
    with pytest.raises(FeedError, match="fetch_feeds"):
        load_nvd(tmp_path / "nope.json")


def test_malformed_cache_raises_feed_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(FeedError, match="not valid JSON"):
        load_kev(bad)


def test_build_vulns_without_any_kev_data():
    vulns = build_vulns(NVD_FIXTURE["entries"], {})
    assert len(vulns) == 2
    assert not any(v.kev for v in vulns.values())
    # Falls back to the NVD description when KEV has no curated name.
    assert vulns["CVE-2021-44228"].title.startswith("Apache Log4j2 JNDI")
