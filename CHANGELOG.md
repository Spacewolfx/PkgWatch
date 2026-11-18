# Changelog

All notable changes to pkgwatch are documented here. The format is kept close to
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer, and every entry
states whether its detection quality was measured — most is not, and nothing here is proof
of malicious behaviour.

## Unreleased

No changes yet.

## 0.3.2 — 2026-11-18

Hardening and correctness release. No score weights changed. Detection semantics changed for a
small set of rules, so `rule_set_version` moves from `810fa2b88188` to `9f7f24f3935e`; the
recorded installer pair still scores 94 with the same four findings and the benign pair scores 0.
Detection quality remains unmeasured. Static analysis only; no package content is executed.

### Fixed

- PyPI metadata parsing now unfolds RFC 5322 continuation lines, so a folded `Requires-Dist`
  header can no longer hide a dependency. Python AST diffs keep the relative import level
  (`from . import x` is no longer reported as `import x`).
- Dataset export removes a partially written deterministic run directory on failure so a retry
  is possible; validation now rejects mixed toolchain/config records instead of silently
  joining them. The CLI reports non-UTF-8 dataset records as `DATASET_RECORD_INVALID` with exit 2.
- Extraction cleans up its temporary directory on digest mismatch and re-hashes the archive
  after materialisation; symlink targets with embedded backslashes are rejected and truncated
  ZIPs are classified as truncated. The download cache re-verifies a corrupt entry under the
  per-key lock before deleting it, so a concurrent valid write survives.
- npm workspace `link` entries without a version are skipped as unsupported sources rather
  than reported as invalid versions; lockfile baseline digests must be 64 lowercase hex chars.
- CLI numeric arguments reject trailing junk, config init returns a deterministic exit code on
  write failure, and Markdown escaping covers `~`.
- Six rules now emit the same `rule_version` the registry advertises; a registry test checks
  emitted finding versions so an exported dataset can no longer fail its own validator.

### Changed — detection semantics

- Capability grouping now treats equivalent spellings as one capability (dynamic eval,
  environment enumeration, eval/exec, network imports), so switching syntax no longer looks
  like a new capability. A `# system` comment on `from os import path` no longer fires
  `PYPI_SHELL_EXEC_ADDED`. Dependency names are compared before being clipped to the evidence
  cap, so a long name cannot hide an added dependency.
- `SPEC.md` and `docs/rules.md` now list `cmdclass` install hooks alongside setup.py hooks.

### Documentation

- `ARCHITECTURE.md` and `FILE_MAP.md` moved under `docs/` with history preserved; references
  in README, SPEC, CHANGELOG and the file map now use their new paths.
- Added `docs/README.md` as the documentation index, `CONTRIBUTING.md` (setup, gates, how to
  add a rule or ecosystem) and `BUILD.md` (build wheel/sdist, verify artifacts, version bumps,
  publishing status).
- Topic guides (`ci.md`, `dataset.md`, `pypi.md`, `rules.md`) link back to the index, and
  `ci.md` points to the build guide.
- Refreshed file/module counts and the architecture "at a glance" overview; build outputs
  were verified with `uv build`.

## 0.3.1 — 2026-11-16

Hardening release. No rule logic, score weights or detection claims changed: the recorded
installer pair still scores 94 with the same four findings, the benign pair scores 0, and
the rule set version stays `810fa2b88188`. Detection quality remains unmeasured. Static
analysis only; no package content is executed.

### Fixed

- Download cache keys are now a fixed 32-hex hash of the verified registry digest, so a
  sha512 key no longer overflows Windows `MAX_PATH`. Writes are guarded per key; cache I/O
  failures are misses and never change a verdict or exit code. Reads re-verify the file in
  bounded chunks instead of holding a second full copy in memory, and unrecognised digest
  algorithms are rejected rather than silently downgraded to SHA-1.
- Long package-controlled `details` values are clipped instead of raising, closing an
  `analysis_incomplete` evasion path. Detail, evidence and path text is sanitised to one
  printable line.
- Score corroboration evaluates the configured base weight (SPEC §5's `base >= 20`) and
  groups findings by `rule_id` only; PyPI local versions are ignored for precedence as
  specified, while remaining in the canonical form.
- The sandbox composes the stdlib tar data filter after its own checks, re-hashes the
  archive between planning and materialisation, and refuses an existing extraction target
  instead of unlinking a caller-supplied path.
- Dataset `run_id` is derived from the manifest digest alone, so identical inputs collide
  deterministically; `mkdir()` now detects collisions without a check-then-create race.

### Added / Changed

- Every simple JSON output (config check, rule catalog, lock plan, dataset export and
  validation, and error payloads) carries `schema_version: 1`. The compare (`3`) and lock
  (`4`) report schemas are unchanged.
- SARIF emits lockfile basenames instead of absolute operator paths, and the unused
  explanation fallback was removed.
- Compare and lock share their config/mode/ignore/cache/output setup; record directories
  are created only when a record is actually written.
- SPEC §4.5.2 records the operator decision that `getenv` spellings are intentionally not
  matched by `PYPI_ENV_ENUM_ADDED` (one key is configuration, not whole-environment reads).
- Documentation lists every stable error code and the current gate figures.

## 0.3.0 — 2026-11-15

Turns the pairs `compare` and `lock` already analyse into a sound, reproducible,
label-joined dataset, and adds a report-only symbol-level diff for Python files. The
unfinished crates.io support and the offline model layer are removed, so this release
covers npm and PyPI only. Static analysis only; no package content is executed. Detection
quality remains unmeasured.

### Added — symbol diff

- `compare` reports `ast_changes` and `ast_changes_omitted` for changed `.py` files:
  function, class and import additions/removals, plus body or signature changes matched by
  qualified name. Compare JSON `schema_version` is `3`.
- Bounded by `[ast]` (`max_nodes`, `max_depth`, `max_changes`, `max_total_bytes`): a module
  over a budget is skipped as a whole and recorded, never half-parsed. The aggregate byte
  budget stops a package full of generated Python from making parsing the dominant cost.
  AST failures go to `ast_errors`, not `parse_errors`, so they cannot flip
  `analysis_incomplete`.
- Skips surface as report warnings (capped) instead of silently reading as "no symbol
  changes". Duplicate definitions under one name are fingerprinted together, so a change to
  a shadowed earlier body is still reported.
- Report surface only: rules, features and the score never read the block.

### Added — record seam

- `compare --record-dir DIR` and `lock --record-dir DIR` write one `AnalysisRecord` JSON per
  analysed changed pair: the unfiltered findings (pre-`--ignore`, pre-baseline) re-scored,
  both artifact SHA-256 values, the resolved `config_sha256`, the `experimental` flag and a
  69-key feature catalog. The filename is the SHA-256 of the identity, so scoped npm names
  and `+`/`~` versions never reach the filesystem. Re-recording is byte-identical.
- Brand-new packages are not recorded (no old artifact), incomplete analyses are recorded
  but never exported, and a failed `lock` record write is a counted per-pair skip
  (`record_errors`) rather than an aborted run. Existing report bytes are unchanged.

### Added — labels

- `labeling/human.py`: reviewer CSV with whole-file rejection, stable `LABEL_CSV_INVALID` /
  `LABEL_VALUE_INVALID` / `HUMAN_LABEL_DUPLICATE` codes, and a `note` column that is parsed
  and then dropped.
- `labeling/advisory.py`: operator-supplied local OSV JSON (OpenSSF `malicious-packages`,
  Apache-2.0). Name match plus interval or `versions[]` membership ⇒ `malicious`; a name
  match with the version outside every interval ⇒ explicit `unknown` at 0.9. The OSV
  `introduced: "0"` sentinel is honoured and malformed bounds fail closed.
- `labeling/policy.py`: precedence `human` > `advisory_db` > `rule_derived` > `none`, with
  every losing claim kept in `label_conflicts.jsonl` (`precedence` / `advisory_duplicate`).

### Added — export and validation

- `features/`: a closed catalog of 69 features (size, file, dep, capability, obfuscation,
  manifest, score, ecosystem) derived from the diff and findings only, with every float
  rounded to 6 places. No path, evidence or source text can become a feature.
- `dataset/split.py`: the salted permanent split from SPEC §6.3.
- `dataset/export.py`: `export-dataset --records DIR [--labels DIR] [--out DIR] [--json]`
  joins labels, assigns splits, refuses inhomogeneous record sets and existing run
  directories, and writes `dataset.jsonl`, `manifest.json` and `label_conflicts.jsonl`.
- `dataset/validate.py`: `validate-dataset --path FILE [--json]` re-checks every invariant
  from the file. It exits `1` for invalid content (a verdict about the data) and `2` for a
  tool error.
- `LabelSource.NONE`, a closed categorical feature vocabulary, and `AnalysisRecord`; `unknown`
  is now never metric-eligible in any split.

### Changed

- Version is `0.3.0`, and the default `User-Agent` plus the README config example follow it.
- Compare JSON is `schema_version` 3: every report now carries `ast_changes` and
  `ast_changes_omitted`, so consumers pinned to 2 must accept the new keys. Lock and store
  schemas are unchanged.

### Removed

- **crates.io support.** The fetcher, `crates:` route, tests and the `[fetch]` contact field
  were never finished and shipped no rules, so they are gone rather than left half-built.
- **The offline model layer.** `model/`, the `[model]` config section and the planned
  `train`/`eval`/`explain` entry points are removed: with `data/labels/` empty a model
  could not be measured, so it is not part of this release.

### Notes

- `data/labels/` ships empty, so every export today is `unknown` or `rule_derived` and no
  classification metric may be reported on it.
- M3 adds **no** store migration: `user_version` stays 1 and the manifest records
  `sqlite_user_version: null`. Documentation: `docs/dataset.md`.

## 0.2.0 — 2026-11-12

Everything since `v0.1.0` (static npm `compare` + `lock`). Detection quality remains
unmeasured; findings are signals for human review.

### Added — PyPI support

- `compare pypi:<name>@<old> pypi:<name>@<new>` fetches the exact project document, selects
  the sdist (else a wheel) per version, verifies digests and diffs the two trees through the
  same sandbox, differ, rules and scorer as npm.
- Per-version registry metadata is fetched and diffed alongside the trees and reported under
  `pypi_metadata_changes` in the JSON report: `requires_dist`, `requires_python`,
  `classifiers`, `project_urls`, `entry_points`, `yanked` and `summary`.
- Six PyPI rules: `PYPI_INSTALL_HOOK_ADDED` (family 1), `PYPI_SHELL_EXEC_ADDED`,
  `PYPI_NET_ACCESS_ADDED`, `PYPI_ENV_ENUM_ADDED`, `PYPI_EVAL_EXEC_ADDED` (family 2) and
  `PYPI_DEPENDENCY_ADDED` (family 4, experimental) — the Python counterparts of the npm
  lifecycle and capability rules.
- `versions.py`: one version parser covering both npm semver and PEP 440, with property
  tests, used to order multi-version lockfile names.
- `--ecosystem` filter on `pkgwatch rules`, and the ecosystem catalog reports which
  ecosystems are actually supported.

### Added — output and ergonomics

- `--sarif` on both `compare` and `lock`: SARIF v2.1.0 for GitHub/GitLab code scanning, one
  run, fired rules in `tool.driver.rules`, one result per finding.
- `--markdown` PR-comment report for `lock`, and Markdown warnings/metadata sections for
  `compare`.
- Verified download cache for `compare` (`[fetch].cache_dir`, `--no-cache`), so a second run
  on the same pair does not re-download.
- `python -m pkgwatch` now works: the package ships `__main__.py`, which is exactly how
  `action.yml` invokes it.
- `compare --config PATH` reads the sandbox, fetch, scoring and obfuscation limits from
  `pkgwatch.toml`, the same way `lock --config` reads `[lock]`. The config is loaded before
  anything is fetched.

### Fixed — sandbox and registry reads

- A zip member carrying permission bits but no type bits was dropped instead of read as a
  regular file, so a mode-only entry could hide content from the diff.
- Member names are now measured in both UTF-8 bytes (POSIX) and UTF-16 units (NTFS), and a
  destination that would exceed Windows `MAX_PATH` is rejected with `PATH_TOO_LONG` instead
  of failing mid-extraction.
- The extract deadline is checked while entries are planned, not only at phase boundaries.
- Observed uncompressed bytes are cross-checked against the registry's declared
  `dist.unpackedSize` within 5% (SPEC §TB3); a missing or non-integer declaration skips it.
- A `sha512` integrity string of the wrong length is now `DIGEST_UNSUPPORTED` rather than a
  mismatch that can never be proven.
- PyPI artifact filenames are validated against a filesystem-safe allowlist with room for
  the internal `old-`/`new-` prefix.
- `SandboxRejection.detail` no longer caps at the evidence limit, which raised a
  `ValidationError` inside the rejection path.

### Fixed — rule and diff correctness

- Lines were counted with `str.splitlines`, which also breaks on `\v`, `\f`, `\x85`,
  `\u2028` and `\u2029` — characters that appear inside string literals — so reported line
  numbers could drift away from the file a consumer opens. The differ and the scanner now
  share one splitter that breaks on `\n` only and drops the CR of a CRLF pair.
- `NPM_INSTALL_SCRIPT_ADDED` matched any added line mentioning a hook key. It now locates
  the top-level `scripts` object with a string-aware brace scan and reports every hook key
  on an added line: a dependency named `install` is not a hook, a nested `scripts` table is
  not the hook table, and a minified line declaring two hooks yields two findings.
- `PYPI_INSTALL_HOOK_ADDED` gained a `cmdclass` pattern checked before `setup(`, so a new
  install command class is reported even when the call it rides on is old.
- Patterns that detect the same power in a different syntax now share a capability group,
  because SPEC §4.5 decides "absent before" per capability: ESM `import`/`export`/dynamic
  `import()` spellings of a `require`, and `from os import system`/`from subprocess import
  run` spellings of the call forms. Switching syntax no longer reads as a newly gained
  capability.
- Old-tree scans clip lines to the per-line cap so one huge minified line cannot hang a
  regex, and a clip that could hide a hit is reported as `old_tree_scan: "partial"` instead
  of claimed as proof.
- `PYPI_ENV_ENUM_ADDED` no longer fires on a single-key read (`os.environ["HOME"]`,
  `os.environ.get(...)`, `getenv` in any spelling). Sweeping the whole mapping is
  collection; reading one documented variable is configuration.
- `REPOSITORY_URL_CHANGED` compares the full sanitized value rather than the display copy
  bounded for evidence, so a change past the cap is not missed.
- An `UNCHANGED` or `MODE_ONLY` manifest now reads its text from the retained old-side view.
- The rule-failure guard bounds its own detail strings, so a rule id at the schema limit
  cannot crash the rule that already failed.

### Fixed — lockfile planning and baseline

- Two lockfile paths with the same `(name, version)` and disagreeing content kept the last
  one silently. The parser now keeps the first, records a `DUPLICATE_ENTRY` skip, and still
  dedupes identical hoisted and nested copies.
- A package whose new-side entries all failed to parse was reported as a removal, and one
  whose old-side entries failed as a clean brand-new package. Both are now `unanalysed` with
  the parser's reason: the update happened, only the reading failed.
- A tarball republished at the same version changes its `integrity` while the version set
  stays identical, which the plan called "no change". With both hashes present this is now
  `INTEGRITY_CHANGED` and unanalysed, because pkgwatch fetches by version and cannot
  retrieve the historical tarball to diff it.
- `write_baseline` replaces the target through a temporary file beside it after `fsync`, and
  removes that file if the rename fails, so an interrupted run cannot leave a truncated
  baseline behind.
- `load_baseline` checks nesting depth before parsing and catches `RecursionError`, so a
  hostile baseline exits `BASELINE_INVALID` instead of crashing the process.

### Fixed — CLI, config, store

- `action.yml` invokes `python -m pkgwatch`, which failed until `__main__.py` existed; the
  GitHub Action is now runnable as documented.
- `--plan` combined with `--markdown` or `--sarif` is `OUTPUT_OPTIONS_CONFLICT` instead of
  silently ignoring the requested renderer.
- `--output FILE` writes through a temporary file in the destination directory and removes
  it when the rename fails, so a failed run leaves no stray `.pkgwatch-out-*` file.
- The Markdown sanitizer escaped Markdown specials but not HTML. GitHub renders PR comments
  as HTML, so a package-controlled string could open a tag; `html.escape(quote=True)` now
  runs first. Manifest values in `--markdown` are consequently shown as `requires\_dist` and
  `requests&gt;=2.0`, which render identically.
- `config_version` accepts only `1`, so a config written for a future schema is refused
  rather than half-read.
- `store.db.migrate` rejects migrations that are unordered or share a version, and raises
  `SchemaTooNew` for a database ahead of this build even when no migrations are passed,
  instead of reporting a fresh database at the target version.

### Changed

- `rule_version` bumped to `2` for the six rules whose matching changed above
  (`NPM_INSTALL_SCRIPT_ADDED`, `JS_CHILD_PROCESS_ADDED`, `NET_ACCESS_ADDED`,
  `PYPI_INSTALL_HOOK_ADDED`, `PYPI_SHELL_EXEC_ADDED`, `PYPI_ENV_ENUM_ADDED`), so recorded
  findings can be told apart. Every other rule stays at `1`.
  [docs/rules.md](docs/rules.md) now lists the version of every rule, and a test checks
  that table against the registry.
- `compare` warns when a same-package diff produced no changed file, which used to be a
  silent no-op.
- Documentation: README gained a SARIF section, a `--config` row for `compare`, a case
  study, and honest coverage/limitation notes; `docs/ARCHITECTURE.md` describes what is actually
  built; SPEC §9 records the operator decisions behind this release (1–19).
- Default User-Agent is `pkgwatch/0.2.0`, and a test now pins `pyproject.toml`,
  `pkgwatch.__version__` and the default User-Agent to the same version.

### Removed

- Working drafts no longer ship with the repository: the planning and design documents and
  the per-milestone gate logs under `docs/` are local-only artifacts excluded through
  `.gitignore`, and `docs/pypi.md` and `docs/rules.md` are the user-facing pages that
  replace them.

## 0.1.0 — 2026-11-08

First public release. Static analysis only — pkgwatch never executes, installs or builds
package content.

- `compare npm:<name>@<old> npm:<name>@<new>`: registry document, tarball fetch with digest
  verification, hardened extraction sandbox, line diff, rule families 1–2 (install scripts,
  capability gains) and the 0–100 score, with text, `--json` and `--explain` output.
- `lock --old <lockfile> --new <lockfile>`: untrusted `package-lock.json` v2/v3 parsing with
  stable read/limit error codes, deterministic planning (changed pairs, new/removed packages,
  unanalysed and skipped entries with reasons), per-pair and brand-new-package analysis,
  `--plan`, `--config`, `--baseline`/`--update-baseline`/`--baseline-allow-lifecycle`,
  `--markdown`, `--fail-on`, `--max-pairs`, `--strict-skips`, `--no-new`, download cache and
  retries.
- `version`, `config-init`, `config-check`, `rules` commands; stable error codes and
  `measured: false` disclaimer in every output format; `action.yml` and an example workflow.
