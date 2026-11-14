"""Numeric and categorical features derived from the diff and the findings (SPEC §6.2).

Pure: no file re-reads, no network, no clock, no ``hash()``. Every record carries the full
closed catalog, so a missing feature is a schema error rather than a silent zero.
"""

from __future__ import annotations

from collections.abc import Sequence

from pkgwatch.models import (
    ChangeType,
    DiffContext,
    FeatureValue,
    FileChange,
    FileRole,
    Finding,
    ParseErrorKind,
    ScoreResult,
    Severity,
)

FLOAT_PRECISION = 6

_COUNTED_TYPES = (ChangeType.ADDED, ChangeType.REMOVED, ChangeType.MODIFIED)

_SIZE_NAMES = (
    "size_added_bytes",
    "size_removed_bytes",
    "size_modified_delta_bytes",
    "size_net_delta_bytes",
    "size_total_new_bytes",
    "size_unknown_count",
)
_FILE_COUNT_NAMES = tuple(
    f"file_{change.value}_{role.value}_count" for change in _COUNTED_TYPES for role in FileRole
)
_FILE_OTHER_NAMES = (
    "file_renamed_count",
    "file_unchanged_count",
    "file_binary_count",
    "file_nested_archive_count",
    "file_mode_only_count",
    "file_total_count",
    "file_lines_added",
    "file_lines_removed",
    "file_text_ratio",
    "file_dominant_role",
)
_DEP_NAMES = (
    "dep_added_count",
    "dep_total_new",
    "dep_added_ratio",
    "dep_metadata_available",
)
_CAPABILITY_NAMES = (
    "capability_shell_exec_count",
    "capability_dynamic_eval_count",
    "capability_net_access_count",
    "capability_fs_write_count",
    "capability_env_read_count",
    "capability_total_count",
)
_OBFUS_NAMES = (
    "obfus_blob_count",
    "obfus_blob_max_length",
    "obfus_entropy_max_bits",
    "obfus_entropy_mean_bits",
    "obfus_escape_max_count",
    "obfus_likely_minified_count",
)
_MANIFEST_NAMES = (
    "manifest_install_hook_added",
    "manifest_script_injection",
    "manifest_repository_changed",
    "manifest_invalid",
)
_SCORE_NAMES = (
    "score_value",
    "score_finding_count",
    "score_critical_count",
    "score_high_count",
    "score_medium_count",
    "score_low_count",
    "score_info_count",
    "score_boost_count",
)

_CAPABILITY_RULES: dict[str, tuple[str, ...]] = {
    "capability_shell_exec_count": ("JS_CHILD_PROCESS_ADDED", "PYPI_SHELL_EXEC_ADDED"),
    "capability_dynamic_eval_count": ("DYNAMIC_EVAL_ADDED", "PYPI_EVAL_EXEC_ADDED"),
    "capability_net_access_count": ("NET_ACCESS_ADDED", "PYPI_NET_ACCESS_ADDED"),
    "capability_fs_write_count": ("FS_WRITE_OUTSIDE_PACKAGE_ADDED",),
    "capability_env_read_count": ("ENV_ENUMERATION_ADDED", "PYPI_ENV_ENUM_ADDED"),
}
_DEP_RULES = ("DEPENDENCY_ADDED", "PYPI_DEPENDENCY_ADDED")

FEATURE_NAMES: frozenset[str] = frozenset(
    _SIZE_NAMES
    + _FILE_COUNT_NAMES
    + _FILE_OTHER_NAMES
    + _DEP_NAMES
    + _CAPABILITY_NAMES
    + _OBFUS_NAMES
    + _MANIFEST_NAMES
    + _SCORE_NAMES
    + ("ecosystem",)
)


def _size_features(changes: Sequence[FileChange]) -> dict[str, FeatureValue]:
    added = sum(c.size_new or 0 for c in changes if c.change_type is ChangeType.ADDED)
    removed = sum(c.size_old or 0 for c in changes if c.change_type is ChangeType.REMOVED)
    delta = sum(
        (c.size_new or 0) - (c.size_old or 0)
        for c in changes
        if c.change_type is ChangeType.MODIFIED
        and c.size_new is not None
        and c.size_old is not None
    )
    total_new = sum(c.size_new for c in changes if c.size_new is not None)
    unknown = sum(
        1
        for c in changes
        if (c.change_type is ChangeType.REMOVED and c.size_old is None)
        or (c.change_type is not ChangeType.REMOVED and c.size_new is None)
    )
    return {
        "size_added_bytes": added,
        "size_removed_bytes": removed,
        "size_modified_delta_bytes": delta,
        "size_net_delta_bytes": added + delta - removed,
        "size_total_new_bytes": total_new,
        "size_unknown_count": unknown,
    }


def _dominant_role(changes: Sequence[FileChange]) -> str:
    lines: dict[str, int] = {}
    for change in changes:
        lines[change.role.value] = lines.get(change.role.value, 0) + change.lines_added
    if not any(lines.values()):
        return FileRole.OTHER.value
    return min(sorted(lines), key=lambda role: (-lines[role], role))


def _file_features(ctx: DiffContext) -> dict[str, FeatureValue]:
    changes = ctx.changes
    features: dict[str, FeatureValue] = {}
    for change_type in _COUNTED_TYPES:
        for role in FileRole:
            features[f"file_{change_type.value}_{role.value}_count"] = sum(
                1 for c in changes if c.change_type is change_type and c.role is role
            )
    for change_type in (
        ChangeType.RENAMED,
        ChangeType.UNCHANGED,
        ChangeType.BINARY,
        ChangeType.NESTED_ARCHIVE,
        ChangeType.MODE_ONLY,
    ):
        features[f"file_{change_type.value}_count"] = sum(
            1 for c in changes if c.change_type is change_type
        )
    total = len(changes)
    text = sum(1 for c in changes if c.is_text)
    features["file_total_count"] = total
    features["file_lines_added"] = sum(c.lines_added for c in changes)
    features["file_lines_removed"] = sum(c.lines_removed for c in changes)
    features["file_text_ratio"] = round(text / total, FLOAT_PRECISION) if total else 0.0
    features["file_dominant_role"] = _dominant_role(changes)
    return features


def _dep_features(ctx: DiffContext, findings: Sequence[Finding]) -> dict[str, FeatureValue]:
    added = sum(1 for item in findings if item.rule_id in _DEP_RULES)
    if ctx.ecosystem.value == "npm":
        raw = ctx.metadata_after.get("dependencies")
        total = len(raw) if (available := isinstance(raw, dict)) else 0
    else:
        raw = ctx.metadata_after.get("requires_dist")
        total = len(raw) if (available := isinstance(raw, list)) else 0
    return {
        "dep_added_count": added,
        "dep_total_new": total,
        "dep_added_ratio": round(added / total, FLOAT_PRECISION) if total else 0.0,
        "dep_metadata_available": available,
    }


def _detail_number(item: Finding, key: str) -> float:
    value = item.details.get(key)
    return float(value) if isinstance(value, int | float) else 0.0


def _obfus_features(findings: Sequence[Finding]) -> dict[str, FeatureValue]:
    blobs = [item for item in findings if item.rule_id == "BASE64_BLOB_PRESENT"]
    entropy = [
        _detail_number(item, "entropy_bits")
        for item in findings
        if item.rule_id == "HIGH_ENTROPY_STRINGS"
    ]
    escapes = [
        _detail_number(item, "escapes") for item in findings if item.rule_id == "HEX_ESCAPE_DENSITY"
    ]
    return {
        "obfus_blob_count": len(blobs),
        "obfus_blob_max_length": int(max((_detail_number(i, "length") for i in blobs), default=0)),
        "obfus_entropy_max_bits": round(max(entropy, default=0.0), FLOAT_PRECISION),
        "obfus_entropy_mean_bits": round(
            sum(entropy) / len(entropy) if entropy else 0.0, FLOAT_PRECISION
        ),
        "obfus_escape_max_count": int(max(escapes, default=0)),
        "obfus_likely_minified_count": sum(
            1 for item in findings if item.details.get("likely_minified") is True
        ),
    }


def _manifest_features(ctx: DiffContext, findings: Sequence[Finding]) -> dict[str, FeatureValue]:
    ids = {item.rule_id for item in findings}
    return {
        "manifest_install_hook_added": bool(
            ids & {"NPM_INSTALL_SCRIPT_ADDED", "PYPI_INSTALL_HOOK_ADDED"}
        ),
        "manifest_script_injection": "NPM_SCRIPT_INJECTION_FROM_METADATA" in ids,
        "manifest_repository_changed": "REPOSITORY_URL_CHANGED" in ids,
        "manifest_invalid": any(
            error.kind is ParseErrorKind.MANIFEST for error in ctx.parse_errors
        ),
    }


def _score_features(findings: Sequence[Finding], result: ScoreResult) -> dict[str, FeatureValue]:
    features: dict[str, FeatureValue] = {
        "score_value": result.score,
        "score_finding_count": len(findings),
        "score_boost_count": len(result.boosts),
    }
    for severity in Severity:
        features[f"score_{severity.value}_count"] = sum(
            1 for item in findings if item.severity is severity
        )
    return features


def _capability_features(findings: Sequence[Finding]) -> dict[str, FeatureValue]:
    features: dict[str, FeatureValue] = {}
    total = 0
    for name, rule_ids in _CAPABILITY_RULES.items():
        count = sum(1 for item in findings if item.rule_id in rule_ids)
        features[name] = count
        total += count
    features["capability_total_count"] = total
    return features


def build_features(
    ctx: DiffContext,
    findings: Sequence[Finding],
    result: ScoreResult,
) -> dict[str, FeatureValue]:
    """The closed feature catalog for one analysed pair."""
    features: dict[str, FeatureValue] = {"ecosystem": ctx.ecosystem.value}
    features.update(_size_features(ctx.changes))
    features.update(_file_features(ctx))
    features.update(_dep_features(ctx, findings))
    features.update(_capability_features(findings))
    features.update(_obfus_features(findings))
    features.update(_manifest_features(ctx, findings))
    features.update(_score_features(findings, result))
    return dict(sorted(features.items()))
