# Changelog

All notable changes to pkgwatch are documented here. The format is kept close to
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer, and every entry
states whether its detection quality was measured — most is not, and nothing here is proof
of malicious behaviour.

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
  study, and honest coverage/limitation notes; `ARCHITECTURE.md` describes what is actually
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
