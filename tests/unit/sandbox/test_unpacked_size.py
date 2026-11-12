from __future__ import annotations

import pytest

from pkgwatch.models import RejectionCode
from pkgwatch.sandbox import ArchiveRejected, cross_check_unpacked_size


def test_matching_size_passes() -> None:
    cross_check_unpacked_size(1000, 1000)


def test_within_five_percent_tolerance_passes() -> None:
    cross_check_unpacked_size(1050, 1000)  # exactly +5%
    cross_check_unpacked_size(950, 1000)  # exactly -5%
    cross_check_unpacked_size(1040, 1000)


@pytest.mark.parametrize("observed", [1051, 940, 0, 2000])
def test_beyond_tolerance_is_rejected(observed: int) -> None:
    with pytest.raises(ArchiveRejected) as excinfo:
        cross_check_unpacked_size(observed, 1000)
    assert excinfo.value.rejection.reason_code is RejectionCode.LIMITS_DISAGREE_WITH_REGISTRY


@pytest.mark.parametrize("declared", [None, 0, -5, "1000", True, 1.5])
def test_absent_or_invalid_declared_size_skips_the_check(declared: object) -> None:
    cross_check_unpacked_size(1000, declared)
