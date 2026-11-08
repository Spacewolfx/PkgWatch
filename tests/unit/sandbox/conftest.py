from __future__ import annotations

import pytest

from pkgwatch.models import SandboxLimits


@pytest.fixture
def limits() -> SandboxLimits:
    return SandboxLimits()
