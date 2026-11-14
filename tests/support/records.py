"""Shared builders for cross-module records.

Kept in ``tests/support`` so production modules never carry test-only factories and
so store, diff and integration tests build identical releases.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pkgwatch.models import AnalysisRecord, Ecosystem, Release

T0 = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


def make_release(**overrides: Any) -> Release:
    values: dict[str, Any] = {
        "ecosystem": Ecosystem.NPM,
        "package_name": "demo-pkg",
        "version": "1.1.0",
        "published_at": T0,
        "previous_version": "1.0.0",
        "previous_published_at": T1,
        "tarball_url": "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.1.0.tgz",
        "sha256": "b" * 64,
        "size": 4096,
        "registry_snapshot": {"dist-tags": {"latest": "1.1.0"}},
        "source_endpoint": "https://registry.npmjs.org/demo-pkg",
    }
    values.update(overrides)
    return Release.model_validate(values)


def make_previous_release(**overrides: Any) -> Release:
    values: dict[str, Any] = {
        "package_name": "demo-pkg",
        "version": "1.0.0",
        "published_at": T1,
        "previous_version": None,
        "previous_published_at": None,
        "tarball_url": "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
        "sha256": "a" * 64,
        "source_endpoint": "https://registry.npmjs.org/demo-pkg",
    }
    values.update(overrides)
    return make_release(**values)


def make_analysis_record(**overrides: Any) -> AnalysisRecord:
    values: dict[str, Any] = {
        "ecosystem": Ecosystem.NPM,
        "package_name": "demo-pkg",
        "old_version": "1.0.0",
        "new_version": "1.1.0",
        "published_at": T0,
        "features": {"ecosystem": "npm", "file_dominant_role": "source"},
        "findings": (),
        "rule_score": 0,
        "rule_set_version": "abc123def456",
        "weights_version": "w1",
        "artifact_sha256_old": "a" * 64,
        "artifact_sha256_new": "b" * 64,
        "config_sha256": "c" * 64,
        "experimental": False,
    }
    values.update(overrides)
    return AnalysisRecord.model_validate(values)
