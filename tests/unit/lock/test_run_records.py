"""The record seam must not change one byte of an existing lock report."""

from __future__ import annotations

from dataclasses import fields

from pkgwatch.lock.run import ActiveFindings


def test_active_findings_carries_the_unfiltered_set_and_the_augmented_context() -> None:
    names = {item.name for item in fields(ActiveFindings)}
    assert names == {
        "ctx",
        "all_findings",
        "scored",
        "informational",
        "result",
        "ignored",
        "baselined",
    }
