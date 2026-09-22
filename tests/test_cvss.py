import pytest

from apg import cvss
from apg.catalog import VULNS

# Published NVD base scores for these well-known vectors.
KNOWN = {
    "CVE-2021-44228": 10.0,
    "CVE-2017-0144": 8.1,
    "CVE-2019-0708": 9.8,
    "CVE-2021-34527": 8.8,
    "CVE-2020-1472": 10.0,
    "CVE-2014-0160": 7.5,
    "CVE-2022-22965": 9.8,
}


@pytest.mark.parametrize("cve,expected", KNOWN.items())
def test_base_scores_match_nvd(cve, expected):
    assert cvss.score(VULNS[cve].vector).base == expected


def test_exploitability_is_bounded():
    for v in VULNS.values():
        assert 0 < cvss.score(v.vector).exploitability <= cvss.MAX_EXPLOITABILITY


def test_rejects_non_v3_vector():
    with pytest.raises(ValueError):
        cvss.score("AV:N/AC:L/Au:N/C:P/I:P/A:P")
