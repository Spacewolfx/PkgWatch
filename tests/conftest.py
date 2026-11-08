from __future__ import annotations

from hypothesis import HealthCheck, settings

settings.register_profile(
    "pkgwatch",
    max_examples=60,
    deadline=10_000,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    print_blob=True,
)
settings.load_profile("pkgwatch")
