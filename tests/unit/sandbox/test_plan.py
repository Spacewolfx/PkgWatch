from __future__ import annotations

import pytest

from pkgwatch.models import ManifestKind, RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected
from pkgwatch.sandbox.plan import PlanBuilder


def _clock_expiring_after_first_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """The entry deadline check passes; every later check is past the deadline."""
    calls = {"n": 0}

    def fake() -> float:
        calls["n"] += 1
        return 0.0 if calls["n"] == 1 else 20.0

    monkeypatch.setattr("pkgwatch.sandbox.plan.time.monotonic", fake)


def test_finish_rechecks_deadline_while_validating_parents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = PlanBuilder(SandboxLimits(), compressed_bytes=100, deadline=10.0)
    builder.add("a", ManifestKind.DIR, 0, 0o755)
    builder.add("a/b", ManifestKind.FILE, 1, 0o644)
    _clock_expiring_after_first_check(monkeypatch)
    with pytest.raises(ArchiveRejected) as excinfo:
        builder.finish()
    assert excinfo.value.rejection.reason_code is RejectionCode.DEADLINE_EXCEEDED


def test_finish_rechecks_deadline_while_resolving_hardlinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = PlanBuilder(SandboxLimits(), compressed_bytes=100, deadline=10.0)
    builder.add("a", ManifestKind.FILE, 1, 0o644)
    builder.add("b", ManifestKind.HARDLINK, 0, 0o644, link_target="a")
    # Entry check + one parent-loop check per entry (2) pass; the clock then
    # expires during hardlink resolution.
    calls = {"n": 0}

    def fake() -> float:
        calls["n"] += 1
        return 0.0 if calls["n"] <= 3 else 20.0

    monkeypatch.setattr("pkgwatch.sandbox.plan.time.monotonic", fake)
    with pytest.raises(ArchiveRejected) as excinfo:
        builder.finish()
    assert excinfo.value.rejection.reason_code is RejectionCode.DEADLINE_EXCEEDED
