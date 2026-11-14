"""SPEC §6.3: salted SHA-256, no hash(), no clock, one split per package forever."""

from __future__ import annotations

import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

from pkgwatch.dataset.split import SPLIT_SALT, TRAIN_MAX, VAL_MAX, assign_split, split_bucket
from pkgwatch.models import Split


def _spec_bucket(ecosystem: str, name: str) -> int:
    token = f"pkgwatch-split-v1|{ecosystem}|{name}"
    return int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:8], 16) % 1000


def test_the_bucket_is_the_spec_formula() -> None:
    assert split_bucket("npm", "demo-pkg") == _spec_bucket("npm", "demo-pkg")


def test_the_constants_are_the_spec_values() -> None:
    assert (SPLIT_SALT, TRAIN_MAX, VAL_MAX) == ("pkgwatch-split-v1", 700, 850)


@given(st.text(min_size=1, max_size=40))
@settings(max_examples=200)
def test_the_same_package_always_lands_in_the_same_split(name: str) -> None:
    assert assign_split("npm", name) is assign_split("npm", name)
    assert split_bucket("npm", name) == _spec_bucket("npm", name)


def test_the_ecosystem_is_part_of_the_identity() -> None:
    # Both values computed offline from the spec formula: npm 686, pypi 128.
    assert split_bucket("npm", "demo-pkg") == 686
    assert split_bucket("pypi", "demo-pkg") == 128
    assert split_bucket("pypi", "demo-pkg") == _spec_bucket("pypi", "demo-pkg")


def test_names_exist_on_both_sides_of_each_threshold() -> None:
    # All four exact buckets occur within p0..p3999 (verified: p1052, p433, p54, p1783).
    at = {split_bucket("npm", f"p{i}"): f"p{i}" for i in range(4000)}
    assert assign_split("npm", at[699]) is Split.TRAIN
    assert assign_split("npm", at[700]) is Split.VAL
    assert assign_split("npm", at[849]) is Split.VAL
    assert assign_split("npm", at[850]) is Split.TEST


def test_the_distribution_is_roughly_seventy_fifteen_fifteen() -> None:
    names = [f"pkg-{index}" for index in range(2000)]
    counts = dict.fromkeys(Split, 0)
    for name in names:
        counts[assign_split("npm", name)] += 1
    assert abs(counts[Split.TRAIN] / 2000 - 0.70) < 0.05
    assert abs(counts[Split.VAL] / 2000 - 0.15) < 0.05
    assert abs(counts[Split.TEST] / 2000 - 0.15) < 0.05
