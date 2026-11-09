# pkgwatch

**PkgWatch: static supply-chain diff for npm and PyPI version updates. No code execution, offline, deterministic.**

```bash
pkgwatch compare npm:<name>@<old> npm:<name>@<new> [--json] [--fail-on LEVEL]
                             [--verbose] [--explain] [--ignore RULE_ID ...]
```

**Contents:** [What it does](#what-it-does) · [Install](#install) · [Usage](#usage) ·
[JSON schema](#json-schema) · [Lockfile parsing and planning](#lockfile-parsing-and-planning) ·
[`pkgwatch lock`](#pkgwatch-lock) · [How to use in a PR](#how-to-use-in-a-pr) ·
[Limitations](#limitations) · [Configuration](#configuration) · [Rules](#rules) ·
[Case study](#case-study) · [PyPI support](#pypi-support)

## What it does

- Reads the npm package document from the endpoint listed in [SPEC.md](SPEC.md) §3
  (`GET https://registry.npmjs.org/<name>`) and takes each version's tarball URL from
  `versions[v].dist.tarball`. No other endpoint is constructed.
- For PyPI, reads the JSON document at `GET https://pypi.org/pypi/<name>/json` and
  takes each release's file URL from `releases[v]`; artifacts come from
  `files.pythonhosted.org` only. An sdist (`.tar.gz`) is preferred, else a wheel
  (`.whl`); both are unpacked only through the sandbox and digests are verified
  (`sha256`, falling back to `blake2b_256`).
- Downloads both tarballs over HTTPS with a User-Agent, per-request timeouts, hard size
  caps on the document and each tarball, and redirects only to the registry's own host.
- Verifies `dist.integrity` (SRI, sha512) and falls back to `dist.shasum` only when
  integrity is absent. It reports which digest was used and stops on a mismatch.
- Unpacks both tarballs **only** through `pkgwatch.sandbox`, builds a file-level diff with
  the registry metadata, runs the versioned rule families 1–4, and scores with `w1`.
  Families 3 (obfuscation) and 4 (metadata) are **experimental**: off by default,
  enabled by `--experimental`.
- Reports, in text or JSON: both versions, file counts, every finding (grouped by
  severity), the score and boosts, changed files, `package.json` changes, registry
  metadata changes, ignored rules, and optional neutral `--explain` copy.
- v0.2 adds rule families 3 (obfuscation signals) and 4 (metadata changes) for npm. Their
  severities and thresholds are **operator decisions, initial untuned values, not
  measured** (SPEC §4.5.1 / §6.5.1), and both families are **experimental** (disabled
  by default; enable with `--experimental`).

## What it does not do

- **No code execution.** Package content is never executed, imported, installed or run —
  not in the pipeline and not in tests. No `npm`, `npx`, `node`, package scripts,
  package-code imports, or AST/eval-based execution. This is static analysis only.
- **npm and PyPI, exact versions only.** No ranges, tags, dist-tags, crates.io,
  watchlists, feeds, schedulers, store writes, model code or dataset code. The
  `lock` command covers npm lockfiles only; PyPI lock support is not implemented.
- **Detection quality has not been measured.** Findings are signals for human review, not
  proof of malicious behaviour. The score is an ordering, not a verdict. The v0.2
  severities and `[obfuscation]` thresholds are starting values, not tuned or measured.
- **It will miss obfuscated and runtime behaviour.** Rules read added lines and registry
  metadata; they cannot see code assembled at runtime, behaviour that appears only when
  installed, network traffic, or anything hidden behind encoding. Family 3 reports an
  obfuscation *signal* only, never intent.
- **No verdict, no quarantine, no reporting to a registry.** It informs a human.
- **Tests are offline.** They serve synthetic, defanged fixture tarballs through an
  injected HTTP client; the test suite never reaches the live registry.

Anyone running this against live registries should still do so in a constrained
environment: this is hardened in-process parsing, not an OS-level sandbox.

## Install

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync
uv run pkgwatch version
```

Configuration is optional; the built-in defaults match SPEC.md. To keep an editable copy:

```bash
uv run pkgwatch config-init --path pkgwatch.toml
uv run pkgwatch config-check --path pkgwatch.toml
```

The code itself also installs as a wheel (`pip install .` — hatchling, single runtime
dependency `pydantic`); version 0.1.0. Licensed under MIT (see `LICENSE`). Publishing to
a package index is not set up yet: install from the repository checkout until that
decided path exists.

## Usage

```bash
uv run pkgwatch compare npm:demo-pkg@1.0.0 npm:demo-pkg@1.1.0
uv run pkgwatch compare npm:demo-pkg@1.0.0 npm:demo-pkg@1.1.0 --json
uv run pkgwatch compare npm:demo-pkg@1.0.0 npm:demo-pkg@1.1.0 --fail-on high
uv run pkgwatch compare npm:demo-pkg@1.0.0 npm:demo-pkg@1.1.0 --verbose --explain
uv run pkgwatch compare npm:demo-pkg@1.0.0 npm:demo-pkg@1.1.0 --ignore NET_ACCESS_ADDED

uv run pkgwatch compare pypi:requests@2.31.0 pypi:requests@2.32.0
uv run pkgwatch compare pypi:requests@2.31.0 pypi:requests@2.32.0 --json --experimental

uv run pkgwatch lock --old package-lock.json --new updated-package-lock.json
uv run pkgwatch lock --old old.json --new new.json --json
uv run pkgwatch lock --old old.json --new new.json --fail-on high --max-pairs 40
uv run pkgwatch lock --old old.json --new new.json --strict-skips --no-cache
uv run pkgwatch lock --old old.json --new new.json --no-new
uv run pkgwatch lock --old old.json --new new.json --plan
uv run pkgwatch lock --old old.json --new new.json --config pkgwatch.toml
uv run pkgwatch lock --old old.json --new new.json --baseline baseline.json
uv run pkgwatch lock --old old.json --new new.json --update-baseline baseline.json --baseline-reason "reviewed in PR"
uv run pkgwatch lock --old old.json --new new.json --markdown
```

Scoped names are accepted and percent-encoded (`@scope/pkg` becomes `@scope%2Fpkg`).

| Flag | Meaning |
|---|---|
| `--json` | emit the JSON report documented below |
| `--sarif` | emit SARIF v2.1.0 JSON for GitHub/GitLab code scanning |
| `--fail-on LEVEL` | `info`, `low`, `medium` (default), `high`, `critical` |
| `--verbose` | show every changed file instead of the first 50 |
| `--explain` | add neutral "Why it matters" / "Common benign causes" lines per fired rule (experimental rules are marked) |
| `--ignore RULE_ID` | repeatable; removes that rule from findings, score and exit code, and prints `ignored: RULE_ID (n findings)`; an unknown ID exits 2 |
| `--experimental` | also run rule families 3 (obfuscation) and 4 (metadata); off by default |

### Recorded output

This is the only real run recorded so far. **2026-11-07**, exact command:

```text
$ pkgwatch compare npm:is-number@6.0.0 npm:is-number@7.0.0
package: is-number
old version: 6.0.0
new version: 7.0.0
files: added=0, removed=0, modified=4
findings: (none)
score: 0
boosts: (none)
digests: old=integrity, new=integrity
Detection quality has not been measured. Findings are signals for human
review, not proof of malicious behaviour.
```

That run was recorded under **v0.1**. Current versions keep every line above and append
the new sections (changed files, `package.json` changes, registry metadata, JSON schema,
toml config, `--config`/`--baseline` flows) after it; no post-v0.1 run has been recorded
yet, so no later output is shown here.

### Text sections

- `findings:` — sorted by severity (highest first), then `rule_id`, path, line. Each
  finding is one line, followed by an indented `details:` line when the rule records any
  (for family 3 this is where `likely_minified=True` appears).
- `changed files:` — `A`/`D`/`M`, path, `old -> new` size. Capped at 50 lines with
  `... N more`; `--verbose` shows all. Binary, mode-only and nested-archive changes are
  not listed here (they still count in `files:` only when they are added/removed/modified).
- `package.json changes:` — added/removed/changed entries in `scripts`, `dependencies`,
  `devDependencies`, `optionalDependencies`, `peerDependencies`, plus the `repository`
  field. A malformed root manifest is shown as `parse problem: <side> MANIFEST_INVALID_JSON`
  and makes the run exit 2 (never a crash).
- `registry metadata changes:` — only SPEC §3's `versions[v]` fields (`dependencies`,
  `devDependencies`, `scripts`, `engines`, `os`, `cpu`, `bin`, `dist.size`,
  `dist.fileCount`, `dist.unpackedSize`). An absent field prints `(not available)`; an
  explicitly null field prints `null`.
- `ignored:` — one line per `--ignore` rule, including rules with zero findings.
- `explanations:` — only with `--explain`, for rules that fired.

Text mode always ends with:

```text
Detection quality has not been measured. Findings are signals for human review, not proof of malicious behaviour.
```

JSON mode carries `"measured": false` instead.

## JSON schema

Compare JSON `schema_version` is `2` (the store schema remains `1`). Keys are stable; the
report is printed with sorted keys. Version 2 makes nested registry values real decoded
JSON rather than JSON-encoded strings.

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | int | `2` |
| `ecosystem` | str | `"npm"` |
| `package`, `old_version`, `new_version` | str | coordinates |
| `files` | object | `{added, removed, modified}` counts |
| `changed_files` | array | `{status, path, size_old, size_new}`; capped at 50 unless `--verbose` |
| `changed_files_omitted` | int | number of changed files not shown |
| `package_json_changes` | object | `sections` (`{added, removed, changed}` per section), `repository` (`{old, new}`), `parse_problems` (`{side, code}`) |
| `registry_metadata_changes` | object | `fields`: `{field: {old, new}}`; each side is a state object described below |
| `findings` | array | `{rule_id, severity, path, line, evidence, details}` in display order |
| `score` | int | 0–100 from the rule engine |
| `boosts` | array | `{name, points}` |
| `digests` | object | `{old, new}`: `integrity` or `shasum` |
| `explanations` | object | `{rule_id: {why_it_matters, common_benign_causes}}`; empty without `--explain` |
| `ignored_rules` | array | `{rule_id, findings}` |
| `rule_set_version` | str | 12 hex characters |
| `measured` | bool | always `false` |
| `disclaimer` | str | the fixed disclaimer text |

Each registry-metadata side is exactly one of `{"state": "absent"}` when the key is
missing along the dotted path, `{"state": "null"}` when it is explicitly JSON null, or
`{"state": "present", "value": <decoded JSON>}` otherwise. Present-but-empty objects
stay `{"state": "present", "value": {}}`; nested objects such as `devDependencies`,
`engines`, and `scripts` are not stringified.

On exit 2 in `--json` mode the object is `{"error": "<CODE>", "measured": false}`; an
`analysis_incomplete` error also carries `"parse_problems": ["manifest" | "budget" | …]`.
The stable code is also printed on stderr.

### Exit codes and stable error codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--fail-on` |
| `1` | one or more findings at or above `--fail-on` |
| `2` | any error — fetch, digest, sandbox rejection or `analysis_incomplete` |

Errors print a stable code, never an exception message (those can contain package text):

`INVALID_SPEC`, `INVALID_PACKAGE_NAME`, `INVALID_VERSION`, `PACKAGE_MISMATCH`,
`REGISTRY_DOC_INVALID`, `VERSION_NOT_FOUND`, `TARBALL_URL_INVALID`, `REDIRECT_REJECTED`,
`SIZE_LIMIT_EXCEEDED`, `HTTP_ERROR`, `FETCH_FAILED`, `DIGEST_MISMATCH`, `DIGEST_MISSING`,
`DIGEST_UNSUPPORTED`, `ARTIFACT_UNAVAILABLE`, every sandbox rejection code in SPEC §6.5,
`ANALYSIS_INCOMPLETE`, `UNKNOWN_RULE_ID`, `INTERNAL_ERROR`. A malformed manifest is recorded as the parse problem
`MANIFEST_INVALID_JSON`. `analysis_incomplete` never exits 0.

## Lockfile parsing and planning

`pkgwatch.lockfile` reads untrusted `package-lock.json` v2/v3 files without network access
and produces a deterministic plan: changed pairs, new packages, removed names, unanalysed
pairs and skipped entries. Parser errors carry stable codes: `LOCKFILE_NOT_FOUND`,
`LOCKFILE_PERMISSION_DENIED`, `LOCKFILE_NOT_UTF8`, `LOCKFILE_READ_FAILED` (fallback for
other OS errors), `LOCKFILE_TOO_LARGE`, `LOCKFILE_DEPTH_EXCEEDED`, `LOCKFILE_INVALID_JSON`,
`LOCKFILE_DUPLICATE_KEY`, `LOCKFILE_INVALID_FORMAT`, `LOCKFILE_UNSUPPORTED_VERSION` and
`TOO_MANY_PAIRS` (never truncates). A UTF-8 BOM is accepted silently. Read errors name the
failing file by its argument — `LOCKFILE_NOT_FOUND (--old)` — never by its path, and the
JSON error object carries `"argument": "--old"` / `"--new"`. A JSON object that repeats a
key is rejected rather than silently keeping the last value. Skipped entries are reported,
never dropped, with codes: `INVALID_ENTRY`, `INVALID_NAME`, `INVALID_VERSION`,
`INVALID_SOURCE`, `UNSUPPORTED_PATH`, `LINK_SOURCE`, `MISSING_RESOLVED`, `GIT_SOURCE`,
`FILE_SOURCE`, `HTTP_SOURCE`, `OTHER_HOST`, `MULTIPLE_VERSIONS` and
`PAIR_SOURCE_UNSUPPORTED`. Only HTTPS entries on `registry.npmjs.org` (the same allow-list
as `fetch/`) are analysable; names with several versions are not paired because no version
order exists yet.

## `pkgwatch lock`

One report for a dependency-update PR: for every package present in **both** lockfiles
whose version changed, what the update changes at install time and in code — plus a
separate no-baseline section for brand-new packages.

| Flag | Meaning |
|---|---|
| `--old OLD_LOCK` | required; the lockfile before the update |
| `--new NEW_LOCK` | required; the lockfile after the update |
| `--json` | emit the lock JSON report (its own `schema_version`, currently 4) |
| `--sarif` | emit SARIF v2.1.0 JSON for GitHub/GitLab code scanning |
| `--experimental` | also run rule families 3 (obfuscation) and 4 (metadata); off by default |
| `--markdown` | emit the report as Markdown (PR-comment sized, collapsible sections) instead of text |
| `--fail-on LEVEL` | `info`, `low`, `medium` (default), `high`, `critical`; falls back to the config's `fail_on`, CLI wins |
| `--max-pairs N` | override `[lock].max_pairs`; changed pairs plus analysed new packages count toward it; over the limit exits 2, never truncates |
| `--strict-skips` | exit 2 when a changed or brand-new package could not be analysed |
| `--no-new` | skip the no-baseline analysis; new packages are only listed and the header says they were NOT analysed |
| `--plan` | print the plan only (changed pairs, unanalysed, new, removed, skipped, with reason codes); no network, no analysis |
| `--config PATH` | read `fail_on`, `max_pairs` and ignored rules (with reasons) from this TOML file; CLI flags win |
| `--baseline FILE` | hide findings matching this baseline file (see below); hidden ones are counted, never silent |
| `--baseline-allow-lifecycle` | also honour baseline entries for lifecycle findings (not honoured by default) |
| `--update-baseline FILE` | write this run's findings to `FILE` as acknowledged; requires `--baseline-reason` |
| `--baseline-reason TEXT` | reason recorded in every entry `--update-baseline` writes |
| `--no-cache` | disable the verified download cache for this run |
| `--verbose` | show every finding of a pair or new-package analysis instead of the first 10 |
| `--ignore RULE_ID` | repeatable; removes that rule from findings, score and exit code |

Text sections, in order: `changed pairs:` (one line per analysed pair with its score and
finding count, then the findings), `failed pairs:` (pair plus its stable code),
`unanalysed packages:` (changed or brand-new packages that could not be analysed, with the
reason), `new packages (no baseline):` (see below), `removed packages:` (names only),
`skipped:` (side, name, version, reason code) and one `ignored:` line per ignored rule. The
disclaimer is printed last, in text mode and on a failed run. A finding without a path or
line prints `(package-level)` in place of one.

A package present only in the new lockfile is analysed against an **empty old tree**, by
the same `fetch/`, `sandbox/`, `diff/`, `rules/` and `score/` code as a changed pair. Its
findings live only in the `new packages (no baseline):` section, never mixed with changed
pairs, and a note says findings are expected to be noisier: with no old version to diff
against, everything the package contains looks added. **Only family 1 (lifecycle) findings
of a new package count toward `--fail-on`**; capability and other findings are shown but do
not change the exit code (operator decision 2026-11-07, SPEC §9.1). A new package with an
unsupported source is **unanalysed** and follows `--strict-skips`. New packages count
toward `--max-pairs` unless `--no-new` is given; with `--no-new` the header says
`new packages were NOT analysed (--no-new).` and each entry carries `"analysis": null` in
JSON. A new package whose analysis fails is shown with its stable code and makes the run
exit 2, like a failed pair. Family 4 findings of a new package (`DEPENDENCY_ADDED`,
`REPOSITORY_URL_CHANGED`) are not meaningful as "changes" against an empty tree, so in the
lock layer they are moved out of the findings list and out of the score into one
`metadata (informational)` line per package — never silent — and the counts ride in the
JSON `analysis` as `informational`. Family 1–3 findings of a new package are still listed
and scored normally. Changed pairs are unchanged: their family 4 findings stay in the list
and the score.

A changed pair whose source is unsupported (git, file, link, http, another host, missing
`resolved`) or whose name has several versions is **unanalysed**, not clean. The header
counts it, a `WARNING` line says the result is incomplete, and the JSON report carries
`unanalysed` plus `unanalysed_packages`. The default exit code is unchanged; opt into `2`
with `--strict-skips`.

Each pair is fetched and analysed by the same `fetch/`, `sandbox/`, `diff/`, `rules/` and
`score/` code as `compare`; nothing is installed, imported or run. Pairs are analysed
concurrently up to `[lock].concurrency` and reported in `name`, `old_version` order, so
output does not depend on which pair finishes first.

Tarballs are cached under the user cache directory (`%LOCALAPPDATA%\pkgwatch\cache` on
Windows, `~/Library/Caches/pkgwatch` on macOS, `$XDG_CACHE_HOME/pkgwatch` elsewhere), keyed
by the digest the registry advertised and the bytes were verified against. Every read
re-verifies that digest; a corrupt entry is deleted and fetched again. The cache is never
placed inside the repository unless `[lock].cache_dir` explicitly says so. Transient
failures (429, 5xx, timeouts) are retried with capped exponential backoff, `Retry-After`
is honoured, and each request waits `[lock].request_delay_seconds` to stay polite.

Exit codes follow SPEC §9.1(7): `2` for any error or incomplete analysis — a lockfile
error, `TOO_MANY_PAIRS`, or a fetch/digest/sandbox failure for **any** pair or new-package
analysis — and `2` wins over `1`. A pair or new package that failed is recorded with its
code and the rest of the run still completes, so a failed analysis never exits `0`.

Lock JSON `schema_version` is `4`: each `new_packages` entry gained an `analysis` object
(`score`, `findings`, `findings_omitted`, `boosts`, `digest`, `files`, `informational`,
`error`, `parse_problems`) or `null` when the package was not analysed, and the report carries
`new_packages_analysed`. `ignored_rules` sums pairs and new-package analyses; each entry now
also carries `reason` (the config ignore reason, or `null`), and the report carries a
`baselined` count.

`--plan` parses and plans only: it prints the changed pairs, unanalysed, new, removed and
skipped sections with their reason codes, and in `--json` mode the same sections as JSON
object keys (`changed_pairs`, `new_packages`, `removed_packages`, `skipped`,
`unanalysed_packages`, `lockfile_versions`). It never calls the network. Exit `0`, or `2`
on a lockfile error, `TOO_MANY_PAIRS`, or `--strict-skips` with unanalysed entries.

`--config PATH` reads `fail_on`, `max_pairs` and ignored rules from the file's `[lock]`
section; command-line flags win over it:

```toml
[lock]
fail_on = "high"            # default is "medium"
max_pairs = 50              # default is 300
ignored = [{ rule = "DEPENDENCY_ADDED", reason = "accepted risk" }]
```

Every ignore in the file requires a non-empty `reason` — an ignore without one exits `2`
with `CONFIG_INVALID`, a missing file with `CONFIG_NOT_FOUND`. Ignored findings are
counted and printed, never silent: `ignored: RULE (n findings) — reason`. An unknown rule
in CLI or config exits `2` with `UNKNOWN_RULE_ID`.

`--baseline FILE` hides a finding **only when** `(package name, rule_id, path, SHA-256 of
the evidence text)` matches an entry in the file — never by version. If the evidence
changes, the finding reappears. Hidden findings are counted and printed as
`baselined: N findings`, and `"baselined": N` in JSON. Entries carry a mandatory reason and
the date they were acknowledged. `--update-baseline FILE --baseline-reason TEXT` writes
every finding of the run (after `--ignore`, before `--baseline` hiding) into that file and
leaves the run's own exit code untouched. Baseline errors: `BASELINE_NOT_FOUND`,
`BASELINE_INVALID`, `BASELINE_REASON_REQUIRED` (update without a reason),
`BASELINE_WRITE_FAILED`, `BASELINE_WITH_PLAN` (`--baseline` flags with `--plan`).

`--markdown` renders the same report as Markdown: a `### pkgwatch lock report` heading, the
counts line, one `<details>` collapsible block per section, evidence capped at 200
characters, and every package-controlled string escaped for Markdown and HTML. The
disclaimer is printed last, exactly as in text mode. `--markdown` and `--json` conflict:
using both exits `2` with `OUTPUT_OPTIONS_CONFLICT`.

Lifecycle (family 1) baseline entries are **not honoured by default**: their evidence is
only the manifest line, so a baseline there could stay hidden while the script it points
at changes underneath. Pass `--baseline-allow-lifecycle` to honour them (operator
decision 2026-11-07, SPEC §9.1 decision 18). Writing a baseline is unaffected.

### How to use in a PR

Copy `examples/github-workflow.yml` to `.github/workflows/lock.yml`, pin every `uses:` by
full commit SHA, and point the action at the published pkgwatch action once publishing
exists. **The Action and the example workflow are untested on GitHub.** The trigger is
`pull_request` (never `pull_request_target`) with `permissions: contents: read`. The old
lockfile, `.pkgwatch.toml` and `baseline.json` are read from the base branch, so a PR
cannot silence its own findings; only the new lockfile comes from the PR. The report is
written to `$GITHUB_STEP_SUMMARY` by default, and PR comments are opt-in (`comment:
"true"`, which needs `pull-requests: write`). Full model, exit-code mapping and the
publishing TODO: [docs/ci.md](docs/ci.md).

### Limitations

- Static analysis only: no code is ever executed, imported, installed or built.
- npm and PyPI, exact versions only; `package-lock.json` v2/v3 only.
- A brand-new package is analysed without a baseline — everything it contains looks
  added, so its findings are noisier; only lifecycle findings count toward `--fail-on`.
- Lifecycle evidence is only the manifest line.
- Obfuscated or runtime behaviour is missed; the false-positive rate is unknown.
- Detection quality has not been measured; findings are signals for human review, not
  proof of malicious behaviour.

## Configuration

`[fetch]` and `[obfuscation]` in `pkgwatch.toml` (all values are defaults):

```toml
[fetch]
max_metadata_bytes = 8388608      # hard cap on the registry document
max_tarball_bytes = 67108864      # hard cap on each tarball
request_timeout_seconds = 15.0
max_redirects = 5                 # same-host redirects only
user_agent = "pkgwatch/0.1.0"

[obfuscation]
min_blob_length = 200             # base64-like run, characters
entropy_min_length = 64           # string-literal length to score
entropy_threshold_bits = 4.5      # Shannon entropy per character
min_escapes_per_line = 20         # \xHH / \uHHHH escapes on one ADDED line

[lock]
max_pairs = 300                   # over this exits 2 with TOO_MANY_PAIRS
fail_on = "medium"                # CLI --fail-on wins
# ignored = [{rule = "RULE_ID", reason = "why"}]  # reason is mandatory; see --config
concurrency = 4
max_lockfile_bytes = 20971520     # 20 MiB, checked before parsing
max_json_depth = 64               # nesting depth, checked before parsing
# cache_dir = "D:/cache/pkgwatch" # default: the user cache directory, never the repo
max_attempts = 3                  # retries for 429, 5xx and timeouts
retry_base_delay_seconds = 0.5    # doubles per attempt, capped by the next value
retry_max_delay_seconds = 8.0
request_delay_seconds = 0.1       # polite delay before each request
```

`likely_minified` is a reporting flag, not a suppression: a matching ADDED line of length
≥ 500 sets `details["likely_minified"] = True`. No file name (`*.min.js`, `dist/`, …)
suppresses a finding. Sandbox limits and score weights live in their existing sections;
v0.2 changes neither rule logic for families 1–2 nor any score weight.

## Rules

Families 1–2 are unchanged from M2. v0.2 adds, for npm only:

| Rule ID | Family | Severity | Weight | Reads |
|---|---|---|---|---|
| `BASE64_BLOB_PRESENT` | 3 obfuscation | low | 4 | ADDED lines, quoted strings |
| `HIGH_ENTROPY_STRINGS` | 3 obfuscation | low | 4 | ADDED lines, quoted strings |
| `HEX_ESCAPE_DENSITY` | 3 obfuscation | low | 4 | ADDED lines |
| `DEPENDENCY_ADDED` | 4 metadata | low | 4 | `versions[v].dependencies` |
| `REPOSITORY_URL_CHANGED` | 4 metadata | medium | 10 | root `package.json` `repository`, both trees |

`MAINTAINER_ADDED` is **deferred**: package-level maintainers is a current-state snapshot,
not a per-version value, so it cannot be diffed (SPEC §3 / §4.5.1). The synthetic installer
pair still produces exactly the same four findings and score 94; the benign pair scores 0.

Families 3 and 4 are **experimental**: they are disabled by default and their findings are
marked `(experimental)` in `--explain` output; pass `--experimental` to enable them.
Without the flag, neither family runs, so their findings are absent from reports and the
score.

## Case study

### node-ipc@9.2.1 → node-ipc@9.2.2 (CVE-2022-21680, December 2021)

On 2021-12-29, `node-ipc@9.2.2` was published with a malicious change: the package gained
a brand-new runtime dependency, `peacetrain`, whose code — shipped inside the
`peacetrain` tarball, not `node-ipc`'s — was a base64-encoded payload that overwrote
system files with itself and then deleted the parent package at install time across
Windows and Linux. It was pulled 6 hours after publishing; `9.2.2` was eventually
removed from the registry.

What PkgWatch would catch (from the public incident reports; this walkthrough is derived
from them, it is not a recorded run):

- With `--experimental`, `DEPENDENCY_ADDED` flags `peacetrain` as a newly declared
  dependency — the full list of `versions[v].dependencies` is part of the SPEC §3
  document the `compare` fetches, so this diff is visible even though the malicious
  code is not in the diffed tarball.
- The `package.json changes:` section lists removed/added `dependencies` in the new
  manifest, and the file counts show the package's own content shrinking towards the
  poisoned release.

What it would miss:

- The payload itself. It lived inside `peacetrain`, a package PkgWatch never downloads:
  static analysis of `node-ipc`'s own tarball cannot see code that ships in a dependency.
- The overwrite-and-self-destruct behaviour, which is runtime behaviour — no static
  line-matching rule sees it.

The lesson is already in this project's design: dependency metadata is family 4
(experimental), and nothing PkgWatch reports claims to be a verdict about malicious
behaviour — `measured: false` everywhere.

## PyPI support

`compare` supports PyPI exact versions through the JSON API at
`https://pypi.org/pypi/<name>/json` (PEP 503 name normalisation, so `Demo_Pkg`,
`demo-pkg` and `demo.pkg` are the same project). Each release's sdist (`.tar.gz`) is
preferred, else its wheel (`.whl`); both unpack only through the sandbox and digests
are verified before extraction. Build manifests (`setup.py`, `pyproject.toml`,
`setup.cfg`) and Python source (`.py`) are read as text only, never executed —
including `setup.py`, which is analysed statically like everything else.

Six PyPI-specific rules run (SPEC §4.5.2): `PYPI_INSTALL_HOOK_ADDED`
(lifecycle, high), `PYPI_SHELL_EXEC_ADDED`, `PYPI_EVAL_EXEC_ADDED` (both high),
`PYPI_NET_ACCESS_ADDED` (medium), `PYPI_ENV_ENUM_ADDED` (low), and
`PYPI_DEPENDENCY_ADDED` (metadata, low) — the last is experimental-gated, off by
default, exactly like npm's `DEPENDENCY_ADDED`. Dependency evidence comes from the
shipped `PKG-INFO`/`METADATA` document, never from registry metadata.

Not implemented yet: the `lock` command for PyPI, and wheel-binary analysis.


## Open assumptions (TODO)

- Live npm registry behaviour beyond SPEC §3's listed fields — response shape, tarball
  redirects, rate limits — was **not** verified offline.
- `versions[v].gpt` in SPEC §3 looks like a typo; it is ignored and no replacement is
  guessed.
- `maintainers`, `repository.url`, `_npmUser` and `deprecated` are package-document-level
  snapshots, not version fields; they are not diffed.
- `devDependencies`, `engines`, `os`, `cpu` and `bin` are not family-4 rules yet.
- The v0.2 severities and `[obfuscation]` thresholds are initial untuned values, not
  measured; `eval/` is where they get challenged.
- SPEC §6.4's version parser compares semver and PEP 440 versions; it is implemented
  and also drives version-ordered pairing for multi-version lockfile names.
- ARCHITECTURE §2's content-addressed caches are not implemented; v0.2 uses temp files and
  writes nothing to `data/` or the SQL store.

## Development

```bash
uv sync
uv run pytest -v
uv run mypy --strict src/
uv run ruff check .
uv run ruff format --check .
```

- Design: [ARCHITECTURE.md](ARCHITECTURE.md)
- Rules, score weights, record schema, endpoints, operator decisions: [SPEC.md](SPEC.md)
- Raw gate logs: [docs/](docs/)
- Licence: [MIT](LICENSE)

© 2026 Spacewolfx
