"""Is our CVSS v3.1 implementation actually correct?

Three independent levels of evidence, weakest to strongest:

1. Reference vectors - scores for vectors that are published and widely cited.
2. Arithmetic edge cases - the Roundup function, which is where naive implementations
   quietly disagree with the specification.
3. The NVD cross-check - every CVE in the local cache, scored from its vector by our
   code and compared against the base score NVD itself published. This is the real
   test: ~70 independent ground truths we did not choose, produced by someone else.

An earlier version of this project hard-coded seven expected scores by hand. One of
them was wrong: EternalBlue (CVE-2017-0144) was entered as AV:N/AC:H/PR:N -> 8.1, while
NVD scores it AV:N/AC:L/PR:L -> 8.8. The test passed anyway, because it was checking a
hand-typed vector against a hand-typed score. Cross-checking against the feed is what
caught it, and is why the catalog now comes from NVD rather than from us.
"""
import pytest

from apg import cvss
from apg.catalog import FEED_META, VULNS

# Vectors whose base scores are published and widely reproduced. These pin the
# implementation independently of whatever happens to be in the local cache.
REFERENCE = {
    # Worst case: network, no privileges, no interaction, total impact, scope changed.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    # Same but scope unchanged - the standard "critical unauthenticated RCE".
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    # Requires low privileges: the usual authenticated RCE.
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
    # High attack complexity drops it about a point.
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    # Local privilege escalation, the PwnKit/DirtyPipe shape.
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    # Information disclosure only - Heartbleed's shape. No integrity impact.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    # Denial of service only.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
    # Reflected XSS: user interaction, scope change, low impacts.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    # Physical access, high complexity, high privileges - about as low as it goes.
    # Worked by hand: Exploitability = 8.22 * 0.2 * 0.44 * 0.27 * 0.62 = 0.121;
    # ISS = 1 - 0.78^3 = 0.5254, Impact = 6.42 * 0.5254 = 3.373;
    # Base = Roundup(3.373 + 0.121) = Roundup(3.494) = 3.5.
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L": 3.5,
    # No impact at all must score exactly zero, not a small positive number.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
}


@pytest.mark.parametrize("vector,expected", REFERENCE.items())
def test_reference_vectors(vector, expected):
    assert cvss.score(vector).base == expected


# --- The important one: agreement with NVD ----------------------------------------

def test_catalog_came_from_the_feed_not_the_fallback():
    """Guard against demoing illustrative numbers while believing they are real.

    If this fails, run `python -m scripts.fetch_feeds`.
    """
    assert FEED_META.source == "cache", FEED_META.summary()
    assert FEED_META.nvd_count >= 50, f"only {FEED_META.nvd_count} CVEs cached"


@pytest.mark.parametrize("cve", sorted(v.cve_id for v in VULNS.values()
                                       if v.nvd_base is not None))
def test_matches_nvd_published_score(cve):
    """Our score, computed from the vector string, equals NVD's published base score."""
    v = VULNS[cve]
    assert cvss.score(v.vector).base == v.nvd_base, f"{cve} {v.vector}"


def test_every_cached_cve_is_scoreable():
    """No CVE reaches the engine without a v3.1 vector we can parse."""
    for v in VULNS.values():
        assert v.vector.startswith("CVSS:3"), f"{v.cve_id} has vector {v.vector!r}"
        cvss.score(v.vector)


# --- Arithmetic edge cases ---------------------------------------------------------

def test_roundup_is_the_spec_version_not_math_ceil():
    """CVSS 3.1 replaced 3.0's round-half-up with a Roundup defined on integer
    arithmetic, precisely because floating point made 3.0 implementations disagree.
    A value already at one decimal place must not be pushed up to the next."""
    assert cvss._roundup(4.02) == 4.1
    assert cvss._roundup(4.00) == 4.0
    assert cvss._roundup(0.0) == 0.0
    # The classic float trap: 8.9 is not exactly representable in binary.
    assert cvss._roundup(8.9) == 8.9


def test_exploitability_and_impact_are_bounded():
    for v in VULNS.values():
        s = cvss.score(v.vector)
        assert 0 < s.exploitability <= cvss.MAX_EXPLOITABILITY
        assert 0 <= s.impact <= 6.1          # 6.0 unchanged scope, ~6.05 changed
        assert 0 <= s.base <= 10


def test_scope_change_raises_the_score():
    """Everything else equal, a scope change makes a vulnerability worse."""
    unchanged = cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").base
    changed = cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").base
    assert changed > unchanged


# --- Input validation ---------------------------------------------------------------

def test_rejects_cvss_v2_vector():
    with pytest.raises(ValueError):
        cvss.score("AV:N/AC:L/Au:N/C:P/I:P/A:P")


def test_rejects_garbage():
    with pytest.raises((ValueError, KeyError)):
        cvss.score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
