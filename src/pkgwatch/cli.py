"""Command line entry point. Thin wrapper only; the pipeline lives in the library.

``compare`` fetches two exact npm versions, unpacks them exclusively through
``pkgwatch.sandbox``, builds the diff context with the registry's metadata, runs the
versioned rules, scores the findings, and reports. Nothing here executes, imports or
installs package content. v0.2 adds richer sections, --verbose, --explain, --ignore and a
versioned JSON schema (SPEC §4.5.1 / §6.5.1 / §6.2). v0.3 adds SARIF v2.1.0 export,
compare Markdown formatting, score-based CI gating, rule catalog inspection, and atomic
file outputs.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NotRequired, TypedDict

from pkgwatch import __version__
from pkgwatch.config import Config
from pkgwatch.diff import build_diff_context
from pkgwatch.diff.manifest import (
    ManifestChanges,
    diff_root_manifests,
    manifest_parse_errors,
)
from pkgwatch.fetch import pypi as pypi_fetch
from pkgwatch.fetch.cache import DownloadCache, default_cache_dir
from pkgwatch.fetch.npm import (
    FetchError,
    FetchErrorCode,
    FetchPair,
    HttpClient,
    UrllibClient,
    fetch_pair,
    parse_spec,
)
from pkgwatch.lock import plan_lock, run_lock
from pkgwatch.lock.baseline import (
    BASELINE_REASON_REQUIRED,
    BASELINE_WITH_PLAN,
    BASELINE_WRITE_FAILED,
    BaselineEntry,
    BaselineError,
    load_baseline,
    make_entries,
    write_baseline,
)
from pkgwatch.lock.report import LockReport, PlanOut, build_plan_json, build_report
from pkgwatch.lock.report import format_markdown as format_lock_markdown
from pkgwatch.lock.report import format_plan_text as format_lock_plan_text
from pkgwatch.lock.report import format_text as format_lock_text
from pkgwatch.lockfile import LockfileError, LockPlan
from pkgwatch.models import (
    ChangeType,
    Ecosystem,
    ExtractionResult,
    FileChange,
    Finding,
    RuleFamily,
    ScoreResult,
    Severity,
)
from pkgwatch.rules import RULES, explanations_for, families_by_rule_id, rule_set_version
from pkgwatch.rules.runner import (
    EXPERIMENTAL_FAMILIES,
    analysis_incomplete,
    run_rules,
)
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from pkgwatch.score.engine import score

DISCLAIMER = (
    "Detection quality has not been measured. Findings are signals for human "
    "review, not proof of malicious behaviour."
)
ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND"
CONFIG_INVALID = "CONFIG_INVALID"
CONFIG_WRITE_FAILED = "CONFIG_WRITE_FAILED"
INTERNAL_ERROR = "INTERNAL_ERROR"
INVALID_SPEC = "INVALID_SPEC"
OUTPUT_OPTIONS_CONFLICT = "OUTPUT_OPTIONS_CONFLICT"
OUTPUT_WRITE_FAILED = "OUTPUT_WRITE_FAILED"
UNKNOWN_RULE_ID = "UNKNOWN_RULE_ID"

CHANGED_FILES_LIMIT = 50
NOT_AVAILABLE = "(not available)"

# Version of the compare JSON report only. models.SCHEMA_VERSION versions the store and
# stays at 1; v0.2 L0 changed registry_metadata_changes to typed JSON, hence 2. The
# key set is ecosystem-conditional (npm: package_json_changes + registry_metadata_
# changes; PyPI: pypi_metadata_changes), so schema_version stays 2 and `ecosystem`
# tells the reader which block to expect.
COMPARE_JSON_SCHEMA_VERSION = 2

# Standard SARIF v2.1.0 schema URI for static analysis integration (GitHub/GitLab).
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

# Only fields SPEC §3 lists for the version document. `gpt` is excluded (SPEC §3 TODO:
# looks like a typo, no replacement guessed). `maintainers`, `_npmUser`, `deprecated`
# and `repository.url` are package-document-level snapshots, not versions[v] fields.
VERSION_DOCUMENT_FIELDS = (
    "dependencies",
    "devDependencies",
    "scripts",
    "engines",
    "os",
    "cpu",
    "bin",
    "dist.size",
    "dist.fileCount",
    "dist.unpackedSize",
)

# Per-version fields of the PyPI JSON document (/pypi/{name}/{version}/json) that
# pypi_metadata_changes diffs, mirroring VERSION_DOCUMENT_FIELDS for npm.
PYPI_METADATA_FIELDS = (
    "requires_dist",
    "requires_python",
    "classifiers",
    "project_urls",
    "entry_points",
    "yanked",
    "summary",
)

_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(_SEVERITY_ORDER)}

_SARIF_LEVEL_MAP: Mapping[str, str] = {
    Severity.INFO.value: "note",
    Severity.LOW.value: "note",
    Severity.MEDIUM.value: "warning",
    Severity.HIGH.value: "error",
    Severity.CRITICAL.value: "error",
}

_SARIF_SECURITY_SEVERITY_MAP: Mapping[str, str] = {
    Severity.INFO.value: "1.0",
    Severity.LOW.value: "3.0",
    Severity.MEDIUM.value: "5.5",
    Severity.HIGH.value: "8.0",
    Severity.CRITICAL.value: "9.5",
}

_INT_RE = re.compile(r"^[0-9]+$")


class FileCounts(TypedDict):
    added: int
    removed: int
    modified: int


class FindingOut(TypedDict):
    rule_id: str
    severity: str
    path: str | None
    line: int | None
    evidence: str
    details: dict[str, str | int | float | bool]


class BoostOut(TypedDict):
    name: str
    points: int


class ChangedFileOut(TypedDict):
    status: str
    path: str
    size_old: int
    size_new: int


class SectionChangesOut(TypedDict):
    added: list[str]
    removed: list[str]
    changed: list[str]


class ParseProblemOut(TypedDict):
    side: str
    code: str


class PackageJsonChangesOut(TypedDict):
    sections: dict[str, SectionChangesOut]
    repository: dict[str, str | None]
    parse_problems: list[ParseProblemOut]


# One side of one registry field. Exactly one of these shapes, so that a field the
# document omits is never confused with a field that is present but empty or null:
#   {"state": "absent"}                   — the key is missing somewhere along the path
#   {"state": "null"}                     — the key is present with a JSON null (live dist.size)
#   {"state": "present", "value": <JSON>} — the real decoded value, object included
FieldSideOut = dict[str, Any]


class RegistryMetadataChangesOut(TypedDict):
    fields: dict[str, dict[str, FieldSideOut]]


class PypiMetadataChangesOut(TypedDict):
    fields: dict[str, dict[str, FieldSideOut]]


class ExplanationOut(TypedDict):
    why_it_matters: str
    common_benign_causes: str


class IgnoredRuleOut(TypedDict):
    rule_id: str
    findings: int


class CompareReport(TypedDict):
    schema_version: int
    ecosystem: str
    package: str
    old_version: str
    new_version: str
    files: FileCounts
    findings: list[FindingOut]
    score: int
    boosts: list[BoostOut]
    digests: dict[str, str]
    changed_files: list[ChangedFileOut]
    changed_files_omitted: int
    # Ecosystem-conditional blocks: npm carries the package.json and registry-metadata
    # views, PyPI the pypi_metadata_changes view. Exactly one set is present.
    package_json_changes: NotRequired[PackageJsonChangesOut]
    registry_metadata_changes: NotRequired[RegistryMetadataChangesOut]
    pypi_metadata_changes: NotRequired[PypiMetadataChangesOut]
    explanations: dict[str, ExplanationOut]
    ignored_rules: list[IgnoredRuleOut]
    rule_set_version: str
    measured: bool
    warnings: list[str]
    disclaimer: str


class RuleCatalogEntryOut(TypedDict):
    rule_id: str
    families: list[str]
    ecosystems: list[str]
    why_it_matters: str
    common_benign_causes: str


class RuleCatalogReport(TypedDict):
    rule_set_version: str
    total_rules: int
    rules: list[RuleCatalogEntryOut]
    measured: bool
    disclaimer: str


class CompareError(Exception):
    """Carries a stable code only, never an exception message."""

    def __init__(self, code: str, *, parse_problems: Sequence[str] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.parse_problems = tuple(sorted(set(parse_problems)))


def _positive_int(text: str) -> int:
    # Reject "1_000", "+5", " 5", "0x10" etc. that int() would otherwise accept.
    if not _INT_RE.match(text):
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}")
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _non_negative_int(text: str) -> int:
    if not _INT_RE.match(text):
        raise argparse.ArgumentTypeError(f"expected a non-negative integer, got {text!r}")
    return int(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgwatch",
        description="Static supply-chain diff and lockfile analyzer for npm and PyPI packages.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="print the version")

    config_init = sub.add_parser("config-init", help="write a default config file")
    config_init.add_argument("--path", default="pkgwatch.toml")
    config_init.add_argument("--force", action="store_true")

    config_check = sub.add_parser("config-check", help="load and print a config file")
    config_check.add_argument("--path", default="pkgwatch.toml")

    rules_cmd = sub.add_parser("rules", help="list available static analysis rules and metadata")
    rules_cmd.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    rules_cmd.add_argument(
        "--markdown",
        action="store_true",
        help="emit Markdown table of rules",
    )
    rules_cmd.add_argument(
        "--family",
        choices=[item.value for item in RuleFamily],
        default=None,
        help="filter rules by rule family",
    )
    rules_cmd.add_argument(
        "--rule",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="filter to specific rule ID(s) (repeatable)",
    )
    rules_cmd.add_argument(
        "--ecosystem",
        choices=sorted({eco.value for rule in RULES for eco in rule.ecosystems}),
        default=None,
        help="filter rules by ecosystem",
    )

    compare = sub.add_parser("compare", help="compare two exact npm or PyPI versions, statically")
    compare.add_argument("old", help="npm:<name>@<old-version> or pypi:<name>@<old-version>")
    compare.add_argument("new", help="npm:<name>@<new-version> or pypi:<name>@<new-version>")
    compare.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    compare.add_argument(
        "--markdown",
        action="store_true",
        help="emit Markdown report (PR-comment ready) instead of text",
    )
    compare.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF v2.1.0 JSON for GitHub/GitLab code scanning",
    )
    compare.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default=None,
        help="write the report to FILE atomically instead of stdout",
    )
    compare.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="suppress standard report output on stdout (exit code still reflects findings)",
    )
    compare.add_argument(
        "--fail-on",
        choices=[item.value for item in _SEVERITY_ORDER],
        default=Severity.MEDIUM.value,
        help="lowest severity that makes the command exit 1 (default: medium)",
    )
    compare.add_argument(
        "--fail-on-score",
        type=_non_negative_int,
        default=None,
        metavar="SCORE",
        help="also exit 1 if the computed package risk score is >= SCORE",
    )
    compare.add_argument(
        "--min-severity",
        choices=[item.value for item in _SEVERITY_ORDER],
        default=Severity.INFO.value,
        help="hide findings below this severity from display (default: info)",
    )
    compare.add_argument(
        "--verbose", action="store_true", help="show every changed file, not just 50"
    )
    compare.add_argument("--explain", action="store_true", help="print rule explanation copy")
    compare.add_argument(
        "--ignore",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="hide a rule from findings, score and the exit code (repeatable)",
    )
    compare.add_argument(
        "--experimental",
        action="store_true",
        help="also run experimental rule families 3 (obfuscation) and 4 (metadata); off by default",
    )
    compare.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        help="disable the verified download cache for this run",
    )

    lock = sub.add_parser("lock", help="report what a package-lock.json update changes, statically")
    lock.add_argument("--old", required=True, metavar="OLD_LOCK", help="old package-lock.json")
    lock.add_argument("--new", required=True, metavar="NEW_LOCK", help="new package-lock.json")
    lock.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    lock.add_argument(
        "--markdown",
        action="store_true",
        help="emit Markdown (PR-comment) instead of text",
    )
    lock.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF v2.1.0 JSON for GitHub/GitLab code scanning",
    )
    lock.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default=None,
        help="write the report to FILE atomically instead of stdout",
    )
    lock.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="suppress standard report output on stdout (exit code still reflects findings)",
    )
    lock.add_argument(
        "--fail-on",
        choices=[item.value for item in _SEVERITY_ORDER],
        default=None,
        help="lowest severity that makes the command exit 1 (default: config or medium)",
    )
    lock.add_argument(
        "--max-pairs",
        type=_positive_int,
        default=None,
        metavar="N",
        help="override [lock].max_pairs; over the limit exits 2, never truncates",
    )
    lock.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="read this TOML config (fail_on, max_pairs, ignored rules with reasons)",
    )
    lock.add_argument(
        "--baseline",
        metavar="FILE",
        default=None,
        help="baseline file; hide findings whose (package, rule_id, path, evidence hash) matches",
    )
    lock.add_argument(
        "--baseline-allow-lifecycle",
        action="store_true",
        help="also honour baseline entries for lifecycle findings (not honoured by default)",
    )
    lock.add_argument(
        "--update-baseline",
        metavar="FILE",
        default=None,
        dest="update_baseline",
        help="write this run's findings to FILE as acknowledged (needs --baseline-reason)",
    )
    lock.add_argument(
        "--baseline-reason",
        metavar="TEXT",
        default=None,
        dest="baseline_reason",
        help="reason recorded in every entry --update-baseline writes",
    )
    lock.add_argument(
        "--verbose", action="store_true", help="show every finding of a pair, not just 10"
    )
    lock.add_argument(
        "--ignore",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="hide a rule from findings, score and the exit code (repeatable)",
    )
    lock.add_argument(
        "--experimental",
        action="store_true",
        help="also run experimental rule families 3 (obfuscation) and 4 (metadata); off by default",
    )
    lock.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        help="disable the verified download cache for this run",
    )
    lock.add_argument(
        "--strict-skips",
        action="store_true",
        help="exit 2 when a changed or brand-new package could not be analysed",
    )
    lock.add_argument(
        "--no-new",
        dest="no_new",
        action="store_true",
        help="skip the no-baseline analysis of brand-new packages; they are only listed",
    )
    lock.add_argument(
        "--plan",
        action="store_true",
        help="print the plan only (no network, no analysis)",
    )

    return parser


def main(
    argv: list[str] | None = None,
    *,
    client: HttpClient | None = None,
    config: Config | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "config-init":
        return _cmd_config_init(args)

    if args.command == "config-check":
        return _cmd_config_check(args, config=config)

    if args.command == "rules":
        return _cmd_rules(args)

    if args.command == "compare":
        return _cmd_compare(args, client=client, config=config)

    if args.command == "lock":
        return _cmd_lock(args, client=client, config=config)

    parser.print_help()
    return 2


def _cmd_config_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        Config.write_default(path, overwrite=args.force)
    except FileExistsError:
        print(f"refusing to overwrite {path} (use --force)", file=sys.stderr)
        return 1
    except OSError:
        # Path comes from the user, not from package content; no sanitization needed.
        return _error(CONFIG_WRITE_FAILED, False)
    print(f"wrote {path}")
    return 0


def _cmd_config_check(args: argparse.Namespace, *, config: Config | None) -> int:
    try:
        active_config = config if config is not None else Config.load(Path(args.path))
    except FileNotFoundError:
        return _error(CONFIG_NOT_FOUND, False)
    except (OSError, ValueError):
        return _error(CONFIG_INVALID, False)
    print(json.dumps(active_config.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    json_mode = bool(args.as_json)
    markdown_mode = bool(args.markdown)
    if json_mode and markdown_mode:
        return _error(OUTPUT_OPTIONS_CONFLICT, json_mode)

    known_ids = {rule.rule_id for rule in RULES}
    requested_ids = list(dict.fromkeys(str(item) for item in (args.rule or [])))
    if any(item not in known_ids for item in requested_ids):
        return _error(UNKNOWN_RULE_ID, json_mode)

    families_map = families_by_rule_id()
    all_rule_ids = sorted(known_ids)
    if requested_ids:
        selected_ids = [rid for rid in all_rule_ids if rid in set(requested_ids)]
    else:
        selected_ids = all_rule_ids

    if args.family:
        target_family = RuleFamily(args.family)
        selected_ids = [
            rid for rid in selected_ids if target_family in families_map.get(rid, frozenset())
        ]

    ecosystems_map = {rule.rule_id: sorted(eco.value for eco in rule.ecosystems) for rule in RULES}
    if args.ecosystem:
        selected_ids = [rid for rid in selected_ids if args.ecosystem in ecosystems_map[rid]]

    explanations_map = explanations_for(tuple(selected_ids))
    entries: list[RuleCatalogEntryOut] = []
    for rid in selected_ids:
        fams = sorted(fam.value for fam in families_map.get(rid, frozenset()))
        why, benign = explanations_map.get(rid, ("", ""))
        entries.append(
            RuleCatalogEntryOut(
                rule_id=rid,
                families=fams,
                ecosystems=ecosystems_map[rid],
                why_it_matters=why,
                common_benign_causes=benign,
            )
        )

    catalog = RuleCatalogReport(
        rule_set_version=rule_set_version(),
        total_rules=len(entries),
        rules=entries,
        measured=False,
        disclaimer=DISCLAIMER,
    )

    if json_mode:
        print(json.dumps(catalog, indent=2, sort_keys=True))
    elif markdown_mode:
        print(_format_rules_markdown(catalog))
        print(DISCLAIMER)
    else:
        print(_format_rules_text(catalog))
        print(DISCLAIMER)
    return 0


def _cmd_compare(
    args: argparse.Namespace,
    *,
    client: HttpClient | None,
    config: Config | None,
) -> int:
    active_client: HttpClient = client if client is not None else UrllibClient()
    active_config = config if config is not None else Config()
    json_mode = bool(args.as_json)
    markdown_mode = bool(args.markdown)
    sarif_mode = bool(args.sarif)
    structured_json = json_mode or sarif_mode

    mode_count = sum([json_mode, markdown_mode, sarif_mode])
    if mode_count > 1:
        return _error(OUTPUT_OPTIONS_CONFLICT, structured_json)

    ignored = list(dict.fromkeys(str(item) for item in (args.ignore or [])))
    known = {rule.rule_id for rule in RULES}
    if any(item not in known for item in ignored):
        return _error(UNKNOWN_RULE_ID, structured_json)

    cache = None
    if not args.no_cache:
        cache = DownloadCache(active_config.fetch.cache_dir or default_cache_dir())
    try:
        report, exit_code = _compare(
            str(args.old),
            str(args.new),
            fail_on=Severity(str(args.fail_on)),
            fail_on_score=args.fail_on_score,
            min_severity=Severity(str(args.min_severity)),
            client=active_client,
            config=active_config,
            verbose=bool(args.verbose),
            explain=bool(args.explain) or sarif_mode,
            ignored=ignored,
            experimental=bool(args.experimental),
            cache=cache,
        )
    except FetchError as exc:
        return _error(exc.code.value, structured_json)
    except ArchiveRejected as exc:
        return _error(exc.rejection.reason_code.value, structured_json)
    except CompareError as exc:
        return _error(exc.code, structured_json, exc.parse_problems)
    except Exception:
        # An exception message can echo package-controlled text; print a code only.
        return _error(INTERNAL_ERROR, structured_json)

    if sarif_mode:
        rendered = json.dumps(_format_compare_sarif(report), indent=2, sort_keys=True)
        include_disclaimer = False
    elif json_mode:
        rendered = json.dumps(report, indent=2, sort_keys=True)
        include_disclaimer = False
    elif markdown_mode:
        rendered = _format_compare_markdown(report)
        include_disclaimer = True
    else:
        rendered = _format_text(report)
        include_disclaimer = True

    if not _emit_output(
        rendered,
        include_disclaimer=include_disclaimer,
        output_path=Path(args.output) if args.output else None,
        quiet=bool(args.quiet),
    ):
        return _error(OUTPUT_WRITE_FAILED, structured_json)

    for warning in report["warnings"]:
        print(f"warning: {_one_line(warning)}", file=sys.stderr)

    return exit_code


def _cmd_lock(
    args: argparse.Namespace,
    *,
    client: HttpClient | None,
    config: Config | None,
) -> int:
    active_client = client if client is not None else UrllibClient()
    json_mode = bool(args.as_json)
    markdown_mode = bool(args.markdown)
    sarif_mode = bool(args.sarif)
    structured_json = json_mode or sarif_mode

    try:
        active_config = (
            config
            if config is not None
            else (Config.load(Path(args.config)) if args.config else Config())
        )
    except FileNotFoundError:
        return _error(CONFIG_NOT_FOUND, structured_json)
    except (OSError, ValueError):
        return _error(CONFIG_INVALID, structured_json)

    mode_count = sum([json_mode, markdown_mode, sarif_mode])
    if mode_count > 1:
        return _error(OUTPUT_OPTIONS_CONFLICT, structured_json)
    if args.plan and sarif_mode:
        return _error(OUTPUT_OPTIONS_CONFLICT, structured_json)

    config_ignored = active_config.lock.ignored
    ignored = list(
        dict.fromkeys(
            [
                *(str(item) for item in (args.ignore or [])),
                *(item.rule for item in config_ignored),
            ]
        )
    )
    reasons = {item.rule: item.reason for item in config_ignored}
    fail_on = Severity(args.fail_on) if args.fail_on else active_config.lock.fail_on
    known = {rule.rule_id for rule in RULES}
    if any(item not in known for item in ignored):
        return _error(UNKNOWN_RULE_ID, structured_json)
    if args.plan and (args.baseline or args.update_baseline):
        return _error(BASELINE_WITH_PLAN, structured_json)
    if args.update_baseline and not args.baseline_reason:
        return _error(BASELINE_REASON_REQUIRED, structured_json)
    baseline_entries: tuple[BaselineEntry, ...] = ()
    if args.baseline:
        try:
            baseline_entries = load_baseline(Path(args.baseline))
        except BaselineError as exc:
            return _error(exc.code, structured_json)
        if not args.baseline_allow_lifecycle:
            baseline_entries = _without_lifecycle(baseline_entries)
    cache = None
    if not args.no_cache:
        cache = DownloadCache(active_config.lock.cache_dir or default_cache_dir())
    try:
        if args.plan:
            _plan, plan_data, lock_exit = _lock_plan(
                str(args.old),
                str(args.new),
                config=active_config,
                max_pairs=args.max_pairs,
                strict_skips=bool(args.strict_skips),
            )
            if json_mode:
                rendered = json.dumps(plan_data, indent=2, sort_keys=True)
                include_disclaimer = False
            else:
                rendered = format_lock_plan_text(_plan)
                include_disclaimer = True
            if not _emit_output(
                rendered,
                include_disclaimer=include_disclaimer,
                output_path=Path(args.output) if args.output else None,
                quiet=bool(args.quiet),
            ):
                return _error(OUTPUT_WRITE_FAILED, structured_json)
            return lock_exit

        lock_report, lock_exit = _lock(
            str(args.old),
            str(args.new),
            fail_on=fail_on,
            client=active_client,
            config=active_config,
            verbose=bool(args.verbose),
            ignored=ignored,
            max_pairs=args.max_pairs,
            strict_skips=bool(args.strict_skips),
            no_new=bool(args.no_new),
            experimental=bool(args.experimental),
            cache=cache,
            baseline=baseline_entries,
            ignored_reasons=reasons,
            update_baseline_path=(Path(args.update_baseline) if args.update_baseline else None),
            baseline_reason=args.baseline_reason or "",
        )
    except LockfileError as exc:
        return _error(exc.code.value, structured_json, argument=exc.argument)
    except BaselineError as exc:
        return _error(exc.code, structured_json)
    except Exception:
        # An exception message can echo lockfile- or package-controlled text.
        return _error(INTERNAL_ERROR, structured_json)

    if sarif_mode:
        rendered = json.dumps(_format_lock_sarif(lock_report), indent=2, sort_keys=True)
        include_disclaimer = False
    elif json_mode:
        rendered = json.dumps(lock_report, indent=2, sort_keys=True)
        include_disclaimer = False
    elif markdown_mode:
        rendered = format_lock_markdown(lock_report)
        include_disclaimer = True
    else:
        rendered = format_lock_text(lock_report)
        include_disclaimer = True

    if not _emit_output(
        rendered,
        include_disclaimer=include_disclaimer,
        output_path=Path(args.output) if args.output else None,
        quiet=bool(args.quiet),
    ):
        return _error(OUTPUT_WRITE_FAILED, structured_json)
    return lock_exit


def _emit_output(
    content: str,
    *,
    include_disclaimer: bool,
    output_path: Path | None,
    quiet: bool,
) -> bool:
    """Emit report to stdout and/or atomically write to disk."""
    full_text = f"{content}\n{DISCLAIMER}\n" if include_disclaimer else f"{content}\n"
    if output_path is not None:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=output_path.parent,
                prefix=".pkgwatch-out-",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(full_text)
            os.replace(temp_path, output_path)
        except OSError:
            return False

    if not quiet and output_path is None:
        print(content)
        if include_disclaimer:
            print(DISCLAIMER)
    return True


def _route(spec: str) -> tuple[Ecosystem, str, str]:
    """Resolve one ``compare`` spec to its ecosystem, name and exact version.

    ``pypi:`` routes to the PyPI parser; everything else stays on the npm path, so npm
    behaviour is unchanged. Each parser validates the name and version before any URL
    is built, so a bad spec raises a stable ``FetchError`` here, never at the network.
    """
    if spec.startswith("pypi:"):
        name, version = pypi_fetch.parse_spec(spec)
        return Ecosystem.PYPI, name, version
    name, version = parse_spec(spec)
    return Ecosystem.NPM, name, version


def _package_identity(ecosystem: Ecosystem, name: str) -> tuple[Ecosystem, str]:
    """The mismatch key: ecosystem plus the name in its ecosystem's canonical form."""
    if ecosystem is Ecosystem.PYPI:
        return ecosystem, pypi_fetch.normalize_name(name)
    return ecosystem, name


def _compare(
    first: str,
    second: str,
    *,
    fail_on: Severity,
    fail_on_score: int | None = None,
    min_severity: Severity = Severity.INFO,
    client: HttpClient,
    config: Config,
    verbose: bool,
    explain: bool,
    ignored: Sequence[str],
    experimental: bool = False,
    cache: DownloadCache | None = None,
) -> tuple[CompareReport, int]:
    ecosystem, old_name, old_version = _route(first)
    _new_ecosystem, new_name, new_version = _route(second)
    if _package_identity(ecosystem, old_name) != _package_identity(_new_ecosystem, new_name):
        raise CompareError(FetchErrorCode.PACKAGE_MISMATCH.value)

    # Temp files and temp extraction roots only: no writes to data/ or the store.
    # TODO(v0.2): ARCHITECTURE §2's content-addressed caches are a later optimisation.
    with tempfile.TemporaryDirectory(prefix="pkgwatch-compare-") as temporary:
        workdir = Path(temporary)
        if ecosystem is Ecosystem.PYPI:
            pair = pypi_fetch.fetch_pair_pypi(
                name=old_name,
                old_version=old_version,
                new_version=new_version,
                config=config,
                client=client,
                workdir=workdir,
                cache=cache,
            )
        else:
            pair = fetch_pair(
                name=old_name,
                old_version=old_version,
                new_version=new_version,
                config=config,
                client=client,
                workdir=workdir,
                cache=cache,
            )
        old_tree = _extract(pair.old.path, workdir / "extract-old", config)
        new_tree = _extract(pair.new.path, workdir / "extract-new", config)
        ctx = build_diff_context(
            ecosystem=ecosystem,
            package_name=old_name,
            old_version=old_version,
            new_version=new_version,
            published_at=pair.new.published_at,
            old=old_tree,
            new=new_tree,
            limits=config.sandbox,
            obfuscation=config.obfuscation,
            metadata_before=pair.old.metadata,
            metadata_after=pair.new.metadata,
        )

        manifest_changes = diff_root_manifests(ctx)
        extra_errors = manifest_parse_errors(manifest_changes)
        if extra_errors:
            ctx = ctx.model_copy(
                update={
                    "parse_errors": (*ctx.parse_errors, *extra_errors),
                    "views_incomplete": True,
                }
            )

        all_findings = run_rules(ctx, experimental=experimental)
        if analysis_incomplete(all_findings):
            raise CompareError(
                ANALYSIS_INCOMPLETE,
                parse_problems=[error.kind.value for error in ctx.parse_errors],
            )

        ignored_set = set(ignored)
        ignored_rules = [
            IgnoredRuleOut(
                rule_id=rule_id,
                findings=sum(1 for item in all_findings if item.rule_id == rule_id),
            )
            for rule_id in sorted(ignored_set)
        ]
        active = [item for item in all_findings if item.rule_id not in ignored_set]
        visible = [item for item in active if _at_or_above(item.severity, min_severity)]
        display = sorted(visible, key=_display_order)
        result = score(
            active,
            scoring=config.scoring,
            families=families_by_rule_id(),
            rule_set_version=rule_set_version(),
        )
        changed = _changed_files(ctx.changes)
        shown = changed if verbose else changed[:CHANGED_FILES_LIMIT]
        report = _report(
            old_name,
            old_version,
            new_version,
            ecosystem=ecosystem,
            pair=pair,
            changes=ctx.changes,
            display=display,
            result=result,
            changed_files=shown,
            omitted=len(changed) - len(shown),
            manifest_changes=manifest_changes,
            # Materialize: the callee may iterate more than once.
            explanations=(
                explanations_for(tuple(item.rule_id for item in display)) if explain else {}
            ),
            ignored_rules=ignored_rules,
        )
        severity_hit = any(_at_or_above(item.severity, fail_on) for item in active)
        score_hit = fail_on_score is not None and result.score >= fail_on_score
        return report, 1 if (severity_hit or score_hit) else 0


def _extract(path: Path, target: Path, config: Config) -> ExtractionResult:
    """The only route from a tarball to a file tree; rejection codes stay stable."""
    try:
        return extract_archive(path, target, config.sandbox)
    except ArchiveRejected as exc:
        raise CompareError(exc.rejection.reason_code.value) from None


def _without_lifecycle(
    entries: Sequence[BaselineEntry],
) -> tuple[BaselineEntry, ...]:
    """Drop lifecycle entries unless opted in: the only evidence of a lifecycle finding
    is the manifest line, so a baseline there can stay hidden while the script the line
    points at changes underneath (SPEC §9.1 decision 18)."""
    families = families_by_rule_id()
    return tuple(
        entry
        for entry in entries
        if RuleFamily.LIFECYCLE_SCRIPTS not in families.get(entry.rule_id, frozenset())
    )


def _lock(
    old_lock: str,
    new_lock: str,
    *,
    fail_on: Severity,
    client: HttpClient,
    config: Config,
    verbose: bool,
    ignored: Sequence[str],
    max_pairs: int | None,
    strict_skips: bool,
    no_new: bool,
    cache: DownloadCache | None,
    baseline: Sequence[BaselineEntry] = (),
    ignored_reasons: Mapping[str, str] | None = None,
    update_baseline_path: Path | None = None,
    baseline_reason: str = "",
    experimental: bool = False,
) -> tuple[LockReport, int]:
    result = run_lock(
        old_lock=Path(old_lock),
        new_lock=Path(new_lock),
        config=config,
        client=client,
        ignored=ignored,
        max_pairs=max_pairs,
        cache=cache,
        analyse_new=not no_new,
        baseline=baseline,
        experimental=experimental,
    )
    report = build_report(
        result,
        old_lockfile=old_lock,
        new_lockfile=new_lock,
        verbose=verbose,
        disclaimer=DISCLAIMER,
        ignored_reasons=ignored_reasons or {},
    )
    if update_baseline_path is not None:
        findings = [
            *(finding for item in result.pairs for finding in item.acknowledged),
            *(finding for item in result.new_analyses for finding in item.acknowledged),
        ]
        entries = make_entries(
            findings,
            reason=baseline_reason,
            today=datetime.date.today().isoformat(),
        )
        try:
            write_baseline(update_baseline_path, entries)
        except OSError:
            raise BaselineError(BASELINE_WRITE_FAILED) from None
    # SPEC §9.1(7): exit 2 wins over 1, and a failed pair never exits 0. For a brand-new
    # package only family 1 (lifecycle) findings count toward --fail-on: with no baseline,
    # every capability the package has looks "added" (operator decision 2026-11-07).
    families = families_by_rule_id()
    hit = any(
        _at_or_above(item.severity, fail_on) for pair in result.pairs for item in pair.findings
    ) or any(
        _at_or_above(item.severity, fail_on)
        and RuleFamily.LIFECYCLE_SCRIPTS in families.get(item.rule_id, frozenset())
        for analysis in result.new_analyses
        for item in analysis.findings
    )
    incomplete = result.incomplete or (strict_skips and bool(result.plan.unanalysed))
    return report, 2 if incomplete else (1 if hit else 0)


def _lock_plan(
    old_lock: str,
    new_lock: str,
    *,
    config: Config,
    max_pairs: int | None,
    strict_skips: bool,
) -> tuple[LockPlan, PlanOut, int]:
    """The plan only: parse and plan, shaped, with no network and no analysis."""
    plan = plan_lock(
        old_lock=Path(old_lock),
        new_lock=Path(new_lock),
        config=config,
        max_pairs=max_pairs,
    )
    incomplete = strict_skips and bool(plan.unanalysed)
    return plan, build_plan_json(plan), 2 if incomplete else 0


def _report(
    name: str,
    old_version: str,
    new_version: str,
    *,
    ecosystem: Ecosystem,
    pair: FetchPair,
    changes: Sequence[FileChange],
    display: Sequence[Finding],
    result: ScoreResult,
    changed_files: list[ChangedFileOut],
    omitted: int,
    manifest_changes: ManifestChanges,
    explanations: Mapping[str, tuple[str, str]],
    ignored_rules: list[IgnoredRuleOut],
) -> CompareReport:
    counts = _counts(changes)
    report = CompareReport(
        schema_version=COMPARE_JSON_SCHEMA_VERSION,
        ecosystem=ecosystem.value,
        package=name,
        old_version=old_version,
        new_version=new_version,
        files=counts,
        findings=[
            FindingOut(
                rule_id=item.rule_id,
                severity=item.severity.value,
                path=item.path,
                line=item.line_start,
                evidence=item.evidence,
                details=dict(item.details),
            )
            for item in display
        ],
        score=result.score,
        boosts=[BoostOut(name=item.name, points=item.points) for item in result.boosts],
        digests={"old": pair.old.digest_method, "new": pair.new.digest_method},
        changed_files=changed_files,
        changed_files_omitted=omitted,
        explanations={
            rule_id: ExplanationOut(why_it_matters=copy[0], common_benign_causes=copy[1])
            for rule_id, copy in sorted(explanations.items())
        },
        ignored_rules=ignored_rules,
        rule_set_version=result.rule_set_version,
        measured=False,
        warnings=_noop_warnings(counts),
        disclaimer=DISCLAIMER,
    )
    if ecosystem is Ecosystem.PYPI:
        report["pypi_metadata_changes"] = _pypi_metadata_changes(pair)
    else:
        report["package_json_changes"] = _package_json_changes(manifest_changes)
        report["registry_metadata_changes"] = _registry_metadata_changes(pair)
    return report


def _noop_warnings(files: FileCounts) -> list[str]:
    """Warn when a same-package diff looks like a silent no-op.

    Zero modified files alongside adds and removes is the signature of two trees that
    never aligned (e.g. a versioned sdist root that was not stripped), which once
    reported a real version bump as all-added/all-removed. Surfacing it beats a clean
    score that means nothing.
    """
    if files["modified"] == 0 and files["added"] > 0 and files["removed"] > 0:
        return [
            f"{files['added']} files added and {files['removed']} removed but none "
            "modified for the same package; the two trees may not have aligned "
            "(possible silent no-op diff)"
        ]
    return []


def _counts(changes: Sequence[FileChange]) -> FileCounts:
    return FileCounts(
        added=sum(1 for item in changes if item.change_type is ChangeType.ADDED),
        removed=sum(1 for item in changes if item.change_type is ChangeType.REMOVED),
        modified=sum(1 for item in changes if item.change_type is ChangeType.MODIFIED),
    )


def _changed_files(changes: Sequence[FileChange]) -> list[ChangedFileOut]:
    statuses = {
        ChangeType.ADDED: "A",
        ChangeType.REMOVED: "D",
        ChangeType.MODIFIED: "M",
    }
    out: list[ChangedFileOut] = []
    for item in sorted(changes, key=lambda change: change.path_new or change.path_old or ""):
        status = statuses.get(item.change_type)
        if status is None:
            continue
        out.append(
            ChangedFileOut(
                status=status,
                path=item.path_new or item.path_old or "",
                size_old=item.size_old or 0,
                size_new=item.size_new or 0,
            )
        )
    return out


def _package_json_changes(changes: ManifestChanges) -> PackageJsonChangesOut:
    return PackageJsonChangesOut(
        sections={
            name: SectionChangesOut(
                added=list(section.added),
                removed=list(section.removed),
                changed=list(section.changed),
            )
            for name, section in changes.sections.items()
        },
        repository={"old": changes.repository_old, "new": changes.repository_new},
        parse_problems=[ParseProblemOut(side=side, code=code) for side, code in changes.problems],
    )


def _field_side(metadata: Mapping[str, Any], field: str) -> FieldSideOut:
    """Decode one dotted field, keeping absent, null and present-but-empty distinct."""
    value: Any = metadata
    for part in field.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return {"state": "absent"}
        value = value[part]
    if value is None:
        return {"state": "null"}
    return {"state": "present", "value": value}


def _side_text(side: FieldSideOut) -> str:
    """Text mode only: one bounded printable line per side, real JSON in --json mode."""
    state = side["state"]
    if state == "absent":
        return NOT_AVAILABLE
    if state == "null":
        return "null"
    return _one_line(json.dumps(side["value"], sort_keys=True, default=str))[:100]


def _registry_metadata_changes(pair: FetchPair) -> RegistryMetadataChangesOut:
    return RegistryMetadataChangesOut(
        fields={
            field: {
                "old": _field_side(pair.old.metadata, field),
                "new": _field_side(pair.new.metadata, field),
            }
            for field in VERSION_DOCUMENT_FIELDS
        }
    )


def _pypi_metadata_changes(pair: FetchPair) -> PypiMetadataChangesOut:
    return PypiMetadataChangesOut(
        fields={
            field: {
                "old": _field_side(pair.old.metadata, field),
                "new": _field_side(pair.new.metadata, field),
            }
            for field in PYPI_METADATA_FIELDS
        }
    )


def _display_order(item: Finding) -> tuple[int, str, str, int]:
    """Severity highest first, then rule_id, path, line."""
    return (
        -_SEVERITY_RANK.get(item.severity, 0),
        item.rule_id,
        item.path or "",
        item.line_start or 0,
    )


def _at_or_above(severity: Severity, threshold: Severity) -> bool:
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(threshold, 0)


def _one_line(text: str) -> str:
    """Package-controlled text stays on one printable line in text mode."""
    return "".join(
        " " if ord(ch) < 0x20 or ord(ch) in (0x7F, 0x2028, 0x2029) else ch for ch in text
    )


def _experimental_marker(rule_id: str, families: Mapping[str, frozenset[RuleFamily]]) -> str:
    """Suffix for an experimental rule reference in explanations output."""
    if not EXPERIMENTAL_FAMILIES.isdisjoint(families.get(rule_id, frozenset())):
        return " (experimental)"
    return ""


def _md_escape(text: str) -> str:
    """Sanitize package-controlled strings for safe inclusion inside Markdown table cells."""
    clean = _one_line(text)
    return clean.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


def _format_details(details: Mapping[str, str | int | float | bool]) -> str:
    """Bounded, sorted detail tokens — this is where likely_minified becomes visible."""
    return " ".join(
        f"{_one_line(key)}={_one_line(str(value))}" for key, value in sorted(details.items())
    )


def _format_text(report: CompareReport) -> str:
    files = report["files"]
    lines = [
        f"package: {report['package']}",
        f"ecosystem: {report['ecosystem']}",
        f"old version: {report['old_version']}",
        f"new version: {report['new_version']}",
        f"files: added={files['added']}, removed={files['removed']}, modified={files['modified']}",
    ]
    if report["findings"]:
        lines.append("findings:")
        for finding_item in report["findings"]:
            path = _one_line(finding_item["path"] or "-")
            line = "-" if finding_item["line"] is None else str(finding_item["line"])
            lines.append(
                f"  {finding_item['rule_id']} {finding_item['severity']} {path}:{line} "
                f"{_one_line(finding_item['evidence'])}"
            )
            if finding_item["details"]:
                lines.append(f"    details: {_format_details(finding_item['details'])}")
    else:
        lines.append("findings: (none)")
    lines.append(f"score: {report['score']}")
    if report["boosts"]:
        lines.append("boosts:")
        for boost in report["boosts"]:
            lines.append(f"  {boost['name']} {boost['points']:+d}")
    else:
        lines.append("boosts: (none)")
    digests = report["digests"]
    lines.append(f"digests: old={digests['old']}, new={digests['new']}")

    lines.append("changed files:")
    for changed_item in report["changed_files"]:
        lines.append(
            f"  {changed_item['status']} {_one_line(changed_item['path'])} "
            f"{changed_item['size_old']} -> {changed_item['size_new']}"
        )
    if not report["changed_files"]:
        lines.append("  (none)")
    if report["changed_files_omitted"]:
        lines.append(f"  ... {report['changed_files_omitted']} more")

    if report["ecosystem"] == "pypi":
        lines.append("pypi metadata changes:")
        for field, sides in report["pypi_metadata_changes"]["fields"].items():
            lines.append(f"  {field}: {_side_text(sides['old'])} -> {_side_text(sides['new'])}")
    else:
        lines.append("package.json changes:")
        for name, section in report["package_json_changes"]["sections"].items():
            added = ",".join(section["added"]) or "-"
            removed = ",".join(section["removed"]) or "-"
            changed = ",".join(section["changed"]) or "-"
            lines.append(f"  {name}: added={added} removed={removed} changed={changed}")
        repository = report["package_json_changes"]["repository"]
        old_repo = repository["old"] if repository["old"] is not None else NOT_AVAILABLE
        new_repo = repository["new"] if repository["new"] is not None else NOT_AVAILABLE
        lines.append(f"  repository: {_one_line(old_repo)} -> {_one_line(new_repo)}")
        for problem in report["package_json_changes"]["parse_problems"]:
            lines.append(f"  parse problem: {problem['side']} {problem['code']}")

        lines.append("registry metadata changes:")
        for field, sides in report["registry_metadata_changes"]["fields"].items():
            lines.append(f"  {field}: {_side_text(sides['old'])} -> {_side_text(sides['new'])}")

    for ignored_item in report["ignored_rules"]:
        lines.append(f"ignored: {ignored_item['rule_id']} ({ignored_item['findings']} findings)")

    if report["explanations"]:
        lines.append("explanations:")
        families = families_by_rule_id()
        for rule_id, copy in report["explanations"].items():
            lines.append(f"  {rule_id}{_experimental_marker(rule_id, families)}:")
            lines.append(f"    Why it matters: {copy['why_it_matters']}")
            lines.append(f"    Common benign causes: {copy['common_benign_causes']}")
    return "\n".join(lines)


def _format_compare_markdown(report: CompareReport) -> str:
    """Format a CompareReport as sanitized GitHub-Flavored Markdown for PR comments."""
    pkg = _md_escape(report["package"])
    old_v = _md_escape(report["old_version"])
    new_v = _md_escape(report["new_version"])
    files = report["files"]

    lines = [
        f"## pkgwatch compare: `{pkg}` (`{old_v}` -> `{new_v}`)",
        "",
        f"- **Ecosystem:** `{_md_escape(report['ecosystem'])}`",
        f"- **Risk Score:** `{report['score']}` (rule set `{report['rule_set_version']}`)",
        f"- **Files:** `+{files['added']}` added, "
        f"`-{files['removed']}` removed, `~{files['modified']}` modified",
        f"- **Digests:** old=`{report['digests']['old']}`, new=`{report['digests']['new']}`",
    ]
    if report["boosts"]:
        boost_tokens = ", ".join(f"`{b['name']}` ({b['points']:+d})" for b in report["boosts"])
        lines.append(f"- **Score Boosts:** {boost_tokens}")

    if report["warnings"]:
        lines.extend(["", "### Warnings", ""])
        for warning in report["warnings"]:
            lines.append(f"- {_md_escape(warning)}")

    lines.append("")
    lines.append("### Findings")
    if report["findings"]:
        lines.extend(
            [
                "",
                "| Rule | Severity | Location | Evidence | Details |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for item in report["findings"]:
            path = _md_escape(item["path"] or "-")
            loc = f"`{path}:{item['line']}`" if item["line"] is not None else f"`{path}`"
            ev = _md_escape(item["evidence"])
            det = _md_escape(_format_details(item["details"])) if item["details"] else "-"
            lines.append(
                f"| `{_md_escape(item['rule_id'])}` | **{item['severity'].upper()}** | "
                f"{loc} | `{ev}` | {det} |"
            )
    else:
        lines.append("\n_No findings reported._")

    if report["explanations"]:
        families = families_by_rule_id()
        lines.extend(["", "### Rule Explanations"])
        for rule_id, copy in report["explanations"].items():
            marker = _experimental_marker(rule_id, families)
            lines.append(f"- **`{_md_escape(rule_id)}`**{_md_escape(marker)}")
            lines.append(f"  - *Why it matters:* {_one_line(copy['why_it_matters'])}")
            lines.append(f"  - *Common benign causes:* {_one_line(copy['common_benign_causes'])}")

    if report["ecosystem"] == "pypi":
        lines.extend(["", "### PyPI Metadata", ""])
        for field, sides in report["pypi_metadata_changes"]["fields"].items():
            old = _md_escape(_side_text(sides["old"]))
            new = _md_escape(_side_text(sides["new"]))
            lines.append(f"- **{_md_escape(field)}:** {old} -> {new}")
    else:
        lines.extend(["", "### Package.json Changes", ""])
        for name, section in report["package_json_changes"]["sections"].items():
            added = ", ".join(section["added"]) or "-"
            removed = ", ".join(section["removed"]) or "-"
            changed = ", ".join(section["changed"]) or "-"
            lines.append(
                f"- **{_md_escape(name)}:** added={_md_escape(added)} "
                f"removed={_md_escape(removed)} changed={_md_escape(changed)}"
            )
        repository = report["package_json_changes"]["repository"]
        old_repo = repository["old"] if repository["old"] is not None else NOT_AVAILABLE
        new_repo = repository["new"] if repository["new"] is not None else NOT_AVAILABLE
        lines.append(f"- **repository:** {_md_escape(old_repo)} -> {_md_escape(new_repo)}")
        for problem in report["package_json_changes"]["parse_problems"]:
            lines.append(
                f"- parse problem: {_md_escape(problem['side'])} {_md_escape(problem['code'])}"
            )
        lines.extend(["", "### Registry Metadata", ""])
        for field, sides in report["registry_metadata_changes"]["fields"].items():
            old = _md_escape(_side_text(sides["old"]))
            new = _md_escape(_side_text(sides["new"]))
            lines.append(f"- **{_md_escape(field)}:** {old} -> {new}")

    lines.extend(["", "<details>", "<summary>Changed Files</summary>", ""])
    if report["changed_files"]:
        lines.extend(
            [
                "| Status | Path | Size (Old -> New) |",
                "| :--- | :--- | :--- |",
            ]
        )
        for cf in report["changed_files"]:
            lines.append(
                f"| `{cf['status']}` | `{_md_escape(cf['path'])}` | "
                f"{cf['size_old']} -> {cf['size_new']} |"
            )
        if report["changed_files_omitted"]:
            lines.append(f"\n_... and {report['changed_files_omitted']} more changed files._")
    else:
        lines.append("_No file changes._")
    lines.append("</details>")

    if report["ignored_rules"]:
        lines.append("")
        ignored_str = ", ".join(
            f"`{item['rule_id']}` ({item['findings']})" for item in report["ignored_rules"]
        )
        lines.append(f"**Ignored rules:** {ignored_str}")

    return "\n".join(lines)


def _format_compare_sarif(report: CompareReport) -> dict[str, Any]:
    """Build a valid SARIF v2.1.0 document from a single package CompareReport."""
    rule_ids = sorted({item["rule_id"] for item in report["findings"]})
    explanations = report["explanations"] or {
        rid: ExplanationOut(why_it_matters=copy[0], common_benign_causes=copy[1])
        for rid, copy in explanations_for(tuple(rule_ids)).items()
    }
    families = families_by_rule_id()

    sarif_rules: list[dict[str, Any]] = []
    for rid in rule_ids:
        exp = explanations.get(rid)
        why = exp["why_it_matters"] if exp else f"pkgwatch rule {rid}"
        benign = exp["common_benign_causes"] if exp else ""
        tags = sorted(fam.value for fam in families.get(rid, frozenset()))
        sarif_rules.append(
            {
                "id": rid,
                "shortDescription": {"text": why},
                "fullDescription": {"text": f"{why} Common benign causes: {benign}".strip()},
                "properties": {"tags": ["security", "supply-chain", *tags]},
            }
        )

    results: list[dict[str, Any]] = []
    for finding in report["findings"]:
        rid = finding["rule_id"]
        sev = finding["severity"]
        artifact_uri = finding["path"] or "package.json"
        line = finding["line"] if finding["line"] and finding["line"] >= 1 else 1
        results.append(
            {
                "ruleId": rid,
                "level": _SARIF_LEVEL_MAP.get(sev, "warning"),
                "message": {
                    "text": (
                        f"[{report['package']} {report['old_version']} -> {report['new_version']}] "
                        f"{finding['evidence']}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "package": report["package"],
                    "old_version": report["old_version"],
                    "new_version": report["new_version"],
                    "severity": sev,
                    "security-severity": _SARIF_SECURITY_SEVERITY_MAP.get(sev, "5.0"),
                    "details": finding["details"],
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pkgwatch",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": sarif_rules,
                    }
                },
                "properties": {
                    "ecosystem": report["ecosystem"],
                    "package": report["package"],
                    "old_version": report["old_version"],
                    "new_version": report["new_version"],
                    "score": report["score"],
                    "rule_set_version": report["rule_set_version"],
                    "measured": False,
                    "disclaimer": DISCLAIMER,
                },
                "results": results,
            }
        ],
    }


def _format_lock_sarif(report: LockReport) -> dict[str, Any]:
    """Build a valid SARIF v2.1.0 document from a LockReport."""
    target_lockfile = report["new_lockfile"]

    collected_rule_ids: set[str] = set()
    results: list[dict[str, Any]] = []

    for pair in report["pairs"]:
        package = pair["name"]
        for finding in pair["findings"]:
            rule_id = finding["rule_id"]
            collected_rule_ids.add(rule_id)
            results.append(
                _sarif_result(
                    report,
                    package=package,
                    old_version=pair["old_version"],
                    new_version=pair["new_version"],
                    finding=finding,
                    target_lockfile=target_lockfile,
                )
            )

    for item in report["new_packages"]:
        analysis = item["analysis"]
        if analysis is None:
            continue
        for finding in analysis["findings"]:
            rule_id = finding["rule_id"]
            collected_rule_ids.add(rule_id)
            results.append(
                _sarif_result(
                    report,
                    package=item["name"],
                    old_version=None,
                    new_version=item["version"],
                    finding=finding,
                    target_lockfile=target_lockfile,
                )
            )

    sorted_rids = sorted(collected_rule_ids)
    explanations = explanations_for(tuple(sorted_rids))
    families = families_by_rule_id()
    sarif_rules: list[dict[str, Any]] = []
    for rid in sorted_rids:
        why, benign = explanations.get(rid, (f"pkgwatch rule {rid}", ""))
        tags = sorted(fam.value for fam in families.get(rid, frozenset()))
        sarif_rules.append(
            {
                "id": rid,
                "shortDescription": {"text": why},
                "fullDescription": {"text": f"{why} Common benign causes: {benign}".strip()},
                "properties": {"tags": ["security", "supply-chain", *tags]},
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pkgwatch",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": sarif_rules,
                    }
                },
                "properties": {
                    "old_lockfile": report["old_lockfile"],
                    "new_lockfile": target_lockfile,
                    "measured": False,
                    "disclaimer": DISCLAIMER,
                },
                "results": results,
            }
        ],
    }


def _sarif_result(
    report: LockReport,
    *,
    package: str,
    old_version: str | None,
    new_version: str,
    finding: FindingOut,
    target_lockfile: str,
) -> dict[str, Any]:
    versions = _sarif_versions(package, old_version, new_version)
    return {
        "ruleId": finding["rule_id"],
        "level": _SARIF_LEVEL_MAP.get(finding["severity"], "warning"),
        "message": {"text": f"{versions} ({finding['path'] or '-'}) {finding['evidence']}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": target_lockfile},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "package": package,
            "old_version": old_version,
            "new_version": new_version,
            "package_path": finding["path"],
            "package_line": finding["line"],
            "severity": finding["severity"],
            "security-severity": _SARIF_SECURITY_SEVERITY_MAP.get(finding["severity"], "5.0"),
        },
    }


def _sarif_versions(package: str, old_version: str | None, new_version: str) -> str:
    if old_version is not None:
        return f"[{package} {old_version} -> {new_version}]"
    return f"[NEW {package}@{new_version}]"


def _format_rules_text(catalog: RuleCatalogReport) -> str:
    lines = [
        f"rule set version: {catalog['rule_set_version']}",
        f"total rules: {catalog['total_rules']}",
    ]
    for entry in catalog["rules"]:
        fams = ", ".join(entry["families"]) or "-"
        ecos = ", ".join(entry["ecosystems"]) or "-"
        lines.append(f"  {entry['rule_id']} (families: {fams}, ecosystems: {ecos})")
        if entry["why_it_matters"]:
            lines.append(f"    Why it matters: {entry['why_it_matters']}")
        if entry["common_benign_causes"]:
            lines.append(f"    Common benign causes: {entry['common_benign_causes']}")
    return "\n".join(lines)


def _format_rules_markdown(catalog: RuleCatalogReport) -> str:
    lines = [
        f"## pkgwatch rules (version `{catalog['rule_set_version']}`)",
        "",
        "| Rule ID | Families | Ecosystems | Why it matters | Common benign causes |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for entry in catalog["rules"]:
        fams = ", ".join(f"`{f}`" for f in entry["families"]) or "-"
        ecos = ", ".join(f"`{e}`" for e in entry["ecosystems"]) or "-"
        lines.append(
            f"| `{_md_escape(entry['rule_id'])}` | {fams} | {ecos} | "
            f"{_md_escape(entry['why_it_matters'])} | {_md_escape(entry['common_benign_causes'])} |"
        )
    return "\n".join(lines)


def _error(
    code: str,
    json_mode: bool,
    parse_problems: Sequence[str] = (),
    *,
    argument: str | None = None,
) -> int:
    # `argument` may be lockfile/package-controlled text (LockfileError.argument);
    # keep it on one printable line in text mode just like every other such value.
    if argument:
        print(f"{code} ({_one_line(argument)})", file=sys.stderr)
    else:
        print(code, file=sys.stderr)
    if json_mode:
        payload: dict[str, Any] = {"error": code, "measured": False}
        if argument:
            payload["argument"] = argument
        if parse_problems:
            payload["parse_problems"] = list(parse_problems)
        print(json.dumps(payload, sort_keys=True))
    else:
        if parse_problems:
            print(f"parse problems: {', '.join(parse_problems)}")
        # The disclaimer is unconditional in text mode, including on a failed run.
        print(DISCLAIMER)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        # Conventional exit code for SIGINT.
        raise SystemExit(130) from None
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `pkgwatch ... | head`); not an analysis error.
        # Redirect stdout to devnull so Python's shutdown flush doesn't re-raise.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0) from None
