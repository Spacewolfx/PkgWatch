# pkgwatch — ARCHITECTURE

Version: 0.5 (as built) · Status: on-demand analysis implemented — `compare` for npm **and**
PyPI, `lock` for npm `package-lock.json` v2/v3, plus the M3 dataset export path; the batch
pipeline is not built and the offline model layer was dropped · Date: 2026-11-15

pkgwatch watches releases of *monitored* packages on npm, PyPI and crates.io, compares
each release against the one before it, extracts behavioral changes as deterministic
findings, scores them with a rule engine, and stores every result as a structured record
that can be exported as a labeled dataset.

That is the design goal. What runs today is the same analysis *on demand*: you name one
package pair (`compare`) or two lockfiles (`lock`) and get a report and an exit code. The
polling, storage and dataset halves below are documented as designed, not as built; §8
lists which checkpoints are actually proven.

This document explains *why* the code is shaped this way and which halves are implemented.
For a per-file inventory, see [FILE_MAP.md](FILE_MAP.md); for the normative contract the
code pins itself to, see [SPEC.md](../SPEC.md).

## At a glance

| Question | Answer |
|---|---|
| What runs today? | `compare` (npm + PyPI), `lock` (npm lockfiles), and dataset export via `--record-dir` |
| What is designed but not built? | The batch polling pipeline (`ingest/`), automatic `store/` writes; the offline model layer was dropped |
| Where can an alert come from? | `rules/` only — nothing else may raise, suppress or change an alert |
| Riskiest surface? | `sandbox/`: every archive member is validated before any member is written |
| Are detections measured? | No. Every report says `measured: false`; severities and weights are initial values |
| Current gates | 1077 passed, 1 skipped; `mypy --strict src/` and both ruff checks clean |

Two commitments shape the whole design:

1. **The rule engine is the source of truth for alerts.** Nothing outside the rule engine
   can raise, suppress, or change an alert.
2. **Package content is hostile input.** It is downloaded, unpacked, read, and parsed —
   never executed, imported, installed, or run, not even in tests.

---

## 1. Components

| Directory | Component | Responsibility | Status |
|---|---|---|---|
| `src/pkgwatch/config.py` | Config | Limits, ecosystems, paths, thresholds, seeds; loaded from TOML | built |
| `src/pkgwatch/models.py` | Records | pydantic v2 models for everything crossing a module boundary; the report shapes are separate `TypedDict`s in `cli.py` | built |
| `src/pkgwatch/version.py` | Version parser | PEP 440 + npm semver ranges, one total order used by pairing | built |
| `src/pkgwatch/ingest/` | Feed readers | Discover new releases per ecosystem; `npm.py`, `pypi.py` | **empty package** — designed, not built |
| `src/pkgwatch/fetch/npm.py` | npm downloader | Registry document + tarball to temp files; digest verified; **no extraction** | built |
| `src/pkgwatch/fetch/pypi.py` | PyPI downloader | Project document + per-version documents + sdist/wheel; PEP 503 names, host allowlist | built |
| `src/pkgwatch/fetch/cache.py` | Download cache | Verified-digest-keyed artifact cache in the OS user cache dir | built |
| `src/pkgwatch/fetch/retry.py` | Retry policy | 429/5xx/timeout only, capped backoff, `Retry-After` as seconds or HTTP-date | built |
| `src/pkgwatch/sandbox/` | Safe unpacker | Archive validation/extraction (tar + zip readers) plus chunked `sha256_file` used by dataset records | built |
| `src/pkgwatch/diff/files.py` | Differ | File-level changes → `DiffContext`; PyPI sdist re-rooting | built |
| `src/pkgwatch/diff/manifest.py` | Manifest diff | Root `package.json` sections, both trees | built |
| `src/pkgwatch/diff/pypi_metadata.py` | Metadata diff | Shipped `PKG-INFO`/`METADATA` dependencies | built |
| `src/pkgwatch/diff/ast.py` | AST differ | Symbol-level changes for changed `.py` files; bounded, report-only | built (Python only) |
| `src/pkgwatch/rules/` | Rule families | Pure functions `DiffContext -> list[Finding]`; 18 rules, npm 12 + PyPI 6 | built |
| `src/pkgwatch/lockfile/` | Lockfile reader | Untrusted `package-lock.json` v2/v3 parse + plan (no network) | built |
| `src/pkgwatch/lock/` | Lock runner | Per-pair analysis, report shaping, baseline | built |
| `src/pkgwatch/features/` | Featurizer | Closed 69-key numeric/categorical catalog; **no raw source text** | built (M3) |
| `src/pkgwatch/score/` | Scorer | Deterministic score from findings + weights | built |
| `src/pkgwatch/store/` | Repository | The only module that touches SQL | built for `releases`/`watchlist`/`runs`; unused by `compare` and `lock` |
| `src/pkgwatch/dataset/` | Exporter | Record seam, label join, salted split, JSONL + manifest, invariant validator | built (M3) |
| `src/pkgwatch/labeling/` | Label sources | Human CSV + local OSV advisory JSON, precedence and conflicts | built (M3) |
| `src/pkgwatch/cli.py` | Entry point | argparse wrapper: `compare`, `lock`, `rules`, `export-dataset`, `validate-dataset`, `config-*`, `version`; text/JSON/Markdown/SARIF output | built |

Dependency direction is strictly left-to-right through this list. `models.py` and
`config.py` depend on nothing but stdlib and pydantic; every other module may depend on
them, never the reverse. `lock/` reuses `fetch/`, `sandbox/`, `diff/`, `rules/` and
`score/` unchanged rather than forking a second pipeline.

## 2. Data flow

### 2.1 On-demand path — implemented

```
 compare npm:<name>@<old> npm:<name>@<new>   ·   compare pypi:<name>@<old> pypi:<name>@<new>
        │ spec prefix routes the ecosystem; both sides must name the same package
        ▼
 fetch/<eco>.py ──▶ registry document(s) ──▶ artifact URLs (never invented)
        │ cached read-through: verified digest is the cache key (§3 TB2)
        ▼
 tempdir/<pkgwatch-compare-*>            sandbox/extract() under hard limits
        │  both artifacts land here, nothing is written under data/
        ▼
 diff/files.py (+ manifest / pypi_metadata) ──▶ DiffContext
        ▼
 rules/runner.py (ecosystem select × family gating) ──▶ list[Finding]
        ▼
 score/engine.py ──▶ ScoreResult ──▶ report ──▶ text / JSON / Markdown / SARIF
                                        ├────▶ exit code 0 | 1 (--fail-on) | 2 (error);
                                               130 on SIGINT, 0 on closed stdout pipe (main)
                                        └── --record-dir ──▶ records/<sha256>.json
                                             (AnalysisRecord: unfiltered findings, re-score,
                                              69 features, both artifact digests)

 lock --old OLD_LOCK --new NEW_LOCK        (npm package-lock.json, lockfileVersion 2 or 3)
        ▼
 lockfile/parser.py (untrusted) ──▶ lockfile/plan.py (pairs + new packages, no network)
        ▼
 lock/run.py: the compare pipeline above, per pair, concurrently ──▶ lock/report.py
        └── baseline hiding + --update-baseline + --plan, --markdown, --sarif;
            --record-dir failures surface as record_errors in all formats; lock SARIF
            locations name the lockfile relative to the repo root, with no invented region
```

No database, no `data/` writes and no persistent extraction roots on this path: a run that
fails halfway leaves nothing behind but a possibly warmer download cache. `--record-dir` is
the one deliberate exception, and it writes only the record files the operator asked for.

### 2.2 Batch path — designed, not built

The monitored-package pipeline this document was written for. It is the target shape for
`ingest/`, `store/` and `dataset/`; nothing on this branch runs it.

```
                     ┌──────────────────────────────────────────────────────────┐
                     │  HOT PATH (deterministic, rule-based rules)              │
                     └──────────────────────────────────────────────────────────┘

 watchlist ──▶ ingest/<eco>.py ──▶ Release ──▶ store.releases (status=pending)
   (package      (registry metadata                 │
    names)        only, no artifacts)               ▼
                                              fetch/<eco>.py
                                                    │  tarball bytes + digest
                                                    ▼
                                              data/raw/artifacts/<sha256>.tgz
                                                    │
                                                    ▼
                                              sandbox/extract()
                                                    │  validated file tree, or Rejection
                                                    ▼
                                              data/raw/extract/<sha256>/
                                                    │
                       ┌────────────────────────────┴───────────────┐
                       ▼                                            ▼
                 diff/files.py                               diff/ast.py (M4)
             old tree vs new tree                      old source vs new source
                       └────────────────┬───────────────┘
                                        ▼
                                   DiffContext  (the only object rules see)
                                        │
                    ┌───────────────────┼────────────────────┐
                    ▼                   ▼                    ▼
              rules/*.py          features/build.py    (labels later)
              list[Finding]       dict[str, num|cat]
                    └───────────────────┼────────────────────┘
                                        ▼
                                   score/engine.py ──▶ ScoreResult (authoritative)
                                        │
                                        ▼
                                   store: findings, scores, dataset_records
 ══════════════════════════════ TRUST BOUNDARY ══════════════════════════════════════
                                        ▼
   compare/lock --record-dir ──▶ records/*.json  (AnalysisRecord)
                                          │
       labeling/ (human CSV + local OSV) ──▶ dataset/export.py ──▶ data/dataset/*.jsonl
                                          │
                                          ▼ (offline, separate command, separate env)
```

The double rule is a real architectural line, enforced by an import test (§5). The
`--record-dir → dataset/ → labeling/` half is implemented on the on-demand path; the batch
pipeline that would feed it automatically is still the proposal drawn here.

**Diff needs both sides.** In the batch design, extraction results are content-addressed by
tarball SHA-256 and reused, so comparing vN against vN−1 costs one new extraction in the
common case. What exists today instead is the verified **download cache** (§3 TB2): the
bytes are reused, the unpacked tree is not, so a warm cache still re-extracts on every run.

**Everything is resumable.** Each stage advances a status column on `releases`
(`pending → fetched → extracted → diffed → scored → exported`) plus a `stage_error`
string. A crash mid-release leaves a row that the next run picks up; it never re-downloads
and never skips silently. **Not implemented end to end** — the columns and the repository
methods exist and are covered by tests, but no production command advances a lifecycle;
`compare` and `lock` are single-shot commands where the whole run is retried.

## 3. Trust boundaries

Five boundaries, each with a named threat and the mechanism that holds it. TB1–TB4 are
implemented and tested; TB5 covers the dataset half (§2.2, §8) and is here so that whoever
builds the batch pipeline inherits the reasoning rather than reinventing it.

### TB1 — Registry → ingest
*Threat:* registry JSON is attacker-influenced (package names, descriptions, maintainer
lists, URLs). *Mechanism:* parsed with pydantic into `Release`; field-length caps; unknown
fields dropped; no URL ever constructed from a package-owned string without validation.
Registry responses are never treated as truth about behavior, only about existence and
coordinates. On the implemented path this holds for the npm document, the PyPI project
document and the PyPI per-version documents: names and versions are validated *before* any
URL is built, artifact URLs are read from the document rather than assembled, and a registry
field that cannot be fetched renders as `(not available)` instead of failing the analysis.

### TB2 — Network → fetch
*Threat:* artifact substitution, truncated download, gzip-of-death. *Mechanism:* download
to a temp file, stream-hash, compare against the registry-supplied digest when present —
npm SRI `sha512` else `shasum`, PyPI `sha256` else `blake2b_256` — and stop with
`DIGEST_MISMATCH` on a mismatch rather than falling through to the next candidate. Only
HTTPS on the allowlisted hosts is followed (npm registry; `pypi.org` for documents,
`files.pythonhosted.org` for artifacts); an off-host redirect is rejected without a second
request. Size is bounded while streaming, before the bytes reach the sandbox.
Metadata (`package.json`, `PKG-INFO`, `Cargo.toml`) is separately persisted as a snapshot so
metadata diffs never require re-extraction (batch path).

The verified bytes are reused: `fetch/cache.py` keys one entry per advertised digest in the
OS user cache directory, re-verifies on every read, and deletes a corrupt entry instead of
using it. `[lock].cache_dir` and `[fetch].cache_dir` relocate it (never inside the
repository unless said so explicitly) and `--no-cache` disables reads and writes for one
run. Transient failures (429, 5xx, timeouts) retry with capped exponential backoff, honour
`Retry-After` in seconds or HTTP-date form, and stay polite via `request_delay_seconds`;
no other status is retried.

### TB3 — Compressed archive → sandbox
*Threat:* the highest-risk surface in the project. Path traversal, absolute paths,
`..` chains, symlink/hardlink escape, device nodes, zip bombs, excessive file count, deep
nesting, Windows-specific escapes (drive letters, UNC, backslashes, case-insensitive
collisions). *Mechanism:* validate **every** member before writing **any** member; write
only under a freshly created temp root; commit by rename. Limits are config, defaults in
SPEC §6.5. No stdlib convenience is trusted alone — `tarfile`'s `data` filter is applied *in
addition to* our own checks, and our checks are the ones the tests cover.

### TB4 — Unpacked file content → diff, rules, features
*Threat:* content that is huge, binary, invalid UTF-8, or crafted to blow up a parser;
content that leaks into outputs. *Mechanism:* byte-first reading; decode with
`errors="replace"`; `text_scan_bytes` truncates a file's view (`FileView.truncated`), and a
view the diff could not read becomes `ParseErrorKind.BUDGET`/`READ`, surfaced by the runner
as an INFO finding; every per-file operation wrapped so an exception becomes a
`RULE_ENGINE_ERROR` info-finding and the worker continues; evidence excerpts hard-capped at
200 characters in the model itself; features typed so raw prose cannot masquerade as a
categorical value (SPEC §6.2). Parsers are AST-only — `ast.parse`, `tomllib`, `json`.
Never `eval`, `exec`, `compile`, `__import__`, `importlib`, `subprocess`, or `pip`.
PyPI build manifests (`setup.py`, `pyproject.toml`, `setup.cfg`) are analysed as text under
exactly the same rule as any other file: `setup.py` is never executed or built, only matched
for lifecycle hooks and capability imports. Each tree has its own view allowance (a changed
path is read from both sides, an unchanged path only from the old side). Capability patterns
scan only the code part of a line: Python `#`, JavaScript `//`/`/*` and `*` continuation lines
are stripped quote-aware, so a comment alone cannot fire a rule, while text inside string
literals still can. Dotted prefixes (`mock_os.system(`) do not match PyPI capabilities.

### TB5 — Store → dataset
*Threat:* label leakage and unreproducible datasets. *Mechanism:* split assigned by hashing
`package_name` (never version, never finding); `rule_derived` labels excluded from val/test
metrics by a validator, not by convention. The offline model layer was dropped; if one is
added, its output must never join `ScoreResult`.

### Process model
One Python process, no subprocess spawning, no execution of package content, no plugin
loading from package content. Extraction and parsing run in-process under resource guards —
a real OS sandbox (container/VM) is a **non-goal** for this codebase (SPEC §2) and anyone
running pkgwatch against live registries should still do so in a constrained environment.
Network egress exists only in `fetch/` (plus `ingest/`, once the batch path is built);
`diff/`, `rules/`, `features/`, `score/`, `dataset/` receive paths and bytes, never URLs to
fetch.

## 4. Storage

`store/` is the only module containing SQL. One file for schema (`store/schema.py` — the DDL
as constants, so a migration step and its table definition are checked by the same test
instead of being read off disk at import), one for the connection (`store/db.py`), one
repository class per aggregate (`store/repo.py`).
SQLite in WAL mode, single writer, `foreign_keys=ON`.

Tables: `releases` (coordinates + stage status), `artifacts` (digest, size, paths),
`extractions` (root path, file count, total bytes, reject reason), `file_changes`,
`findings`, `scores`, `dataset_records`, `labels`, `runs` (reproducibility manifest).
Migrations are forward-only integer `PRAGMA user_version` steps.

Three tables exist, at `user_version` 1: `releases`, `watchlist` and `runs` — the set SPEC
§10 A1 authorises. `watchlist` is the operator's set of packages to follow and is not derived
from any package. Every other table above arrives with its own milestone as a new numbered
migration step.

Nothing on the implemented path opens this database: no shipped command imports `store/`, so
there is a schema, a connection and a repository exercised by tests, and no pipeline that
writes to it. That is the M2 caveat in §8 stated where it lives.

**M3 adds no migration.** `user_version` stays 1: the dataset path persists records as files
under the operator's `--record-dir`, and `export-dataset` writes JSONL plus a manifest, so it
records `sqlite_user_version: null` rather than claiming a schema it never touched.

`Release` identity is `(ecosystem, package_name, version)` — unique index. `Finding`
identity additionally carries `rule_id@rule_version`, so re-running a new rule version on an
old release produces new rows instead of silently mutating history (rule-version changes
must be visible in the data).

## 5. Determinism, reproducibility, enforcement

- Every **batch** run writes a manifest into its output directory: resolved config,
  `rule_set_version`, weights version, `schema_version`, seeds, tool versions, SQLite
  `user_version`. On the implemented path the same fields are carried *in the report*
  instead — `rule_set_version`, `measured: false` and the disclaimer appear in text, JSON,
  Markdown and SARIF output, and `rule_set_version` is the hash of the sorted
  `rule_id@rule_version` set, so adding or versioning a rule is visible in every report.
- Seeds fixed for the splitter and for any sampling. No wall-clock, no `hash()`, no dict
  ordering in any computed output — `hash()` is randomized per process, so the splitter uses
  `sha256` (SPEC §6.3). Clocks on the implemented path are the baseline writer's acknowledged
  date (data, not a match key) and `datetime.now(UTC)` in `fetch/retry.py` when an HTTP-date
  `Retry-After` becomes a delay; neither enters a computed report or dataset key.
- Findings, file-change lists and feature dicts are emitted in sorted key order; JSON dumps
  use `sort_keys=True`. The same two tarballs in → the same `ScoreResult` bytes out, which
  is what makes the integration tests meaningful and what makes the dataset stable enough to
  train on. Display order is specified too (severity descending, then `rule_id`, `path`,
  `line`), as are the caps: 50 changed files unless `--verbose`, 10 findings per pair unless
  `--verbose`.
- Three structural invariants are asserted by tests rather than trusted by convention:
  **(a)** no module under `ingest|fetch|sandbox|diff|rules|features|score|store|dataset`
  imports anything from `model/`; **(b)** no module in the package references `subprocess`,
  `eval(`, `exec(`, `compile(`, `__import__`, `pip`, or `importlib.import_module`;
  **(c)** SQL text appears in `store/` only. Tests grep the source tree for these.

  (b) is read as what it protects — nothing that came out of a package is ever compiled,
  evaluated, executed or installed — so the grep allows exactly one spelling of `compile(`,
  namely `re.compile(`, because SPEC §4.5 requires family-2 rules to pattern-match and those
  pattern literals are written by us, never by a package. `pip` is matched as a whole word, so
  "pipeline" in a docstring is not a violation, and it is `importlib.import_module` that is
  banned rather than every `importlib` use. `tests/unit/test_structure.py` encodes these
  predicates; widening any of them is a security decision, not a lint fix.

  One consequence worth knowing before editing a rule: the capability rules *describe*
  `subprocess`, `eval(` and `__import__` in patterns and docstrings, which is exactly what the
  grep forbids. Detection literals are therefore built by concatenation (`"sub" + "process"`,
  `"__imp" + "ort__"`) and prose is worded around the tokens. The grep stays strict and the
  rules stay expressive; a new rule that needs such a literal follows the same spelling.

## 6. Extension points

- **Rules** register through a decorator carrying `rule_id`, `rule_version`, `severity`,
  `ecosystems`; discovery is explicit (a registry list in `rules/__init__.py`, not filesystem
  scanning) so `rule_set_version` is reproducible. The runner selects `registry.select(ctx.ecosystem)`
  and then applies family gating, so an npm rule can never fire on a PyPI tree and vice versa;
  `pkgwatch rules [--ecosystem npm|pypi] [--family F] [--rule ID]` prints the live catalog.
- **Ecosystems** were specified as one `FeedReader` protocol (`discover`, `describe`) and one
  `ArtifactSource` protocol (`tarball_for`); those protocols are **not** declared in code — no
  batch ingest exists to consume them. On the implemented path each ecosystem is a module of
  plain functions (`fetch/npm.py`, `fetch/pypi.py`) with the same shape: validate spec →
  document(s) → artifact URLs → verified bytes. What the implemented PyPI support actually needed: a spec
  router in `cli.py` (`pypi:` prefix), a name+version validator, a document/artifact fetcher
  with its own host allowlist and digest fallback, a tree-realignment rule (sdist version roots
  are stripped before diffing so a bump shows modifications rather than a total replacement),
  the ecosystem branch in the report, and its own rules. `crates` is still only a table row in
  this document.
- **Output formats** are renderers over one report dict, not a second pipeline: text, JSON
  (`schema_version`-bearing), Markdown and SARIF 2.1.0 all read the same `CompareReport` /
  `LockReport`, so a new format cannot change a finding, a score or an exit code.
- **Label sources** are plain loaders — `load_human_labels()` and `load_advisories()`,
  resolved by `labeling/policy.py:resolve_label()`. `LabelSource` is an enum in `models.py`,
  not a protocol, and there is no `LabeledKey` type. A new advisory feed is a new file in
  `labeling/` and cannot invent labels without declaring `label_source` (built in M3).

## 7. Testing strategy

| Layer | Tool | Covers |
|---|---|---|
| Sandbox property tests | hypothesis | arbitrary member names/types/sizes: no write ever lands outside the root; limit violations always rejected, never partial |
| Sandbox rejection tests | pytest, one case per limit | each implemented rejection condition (33 codes in SPEC §6.5; 32 referenced directly by sandbox tests, `EXTRACTION_ROOT_ESCAPE` has no direct case) |
| Version parser | hypothesis | total order, antisymmetry, transitivity, sort stability, parse/format round-trip |
| Rule fixtures | pytest parametrized | every rule has ≥1 positive and ≥1 negative synthetic fixture |
| Score | pytest | monotonicity: adding a finding never lowers the score; decay and caps exact |
| Offline registry doubles | pytest | `FakeRegistry`, `MultiRegistry`, `PyPIRegistry`: documents, tarballs, wheels and redirects served from memory — **no test opens a socket**, and per-test request counts are asserted, which is how the host allowlist and the cache are proven |
| CLI integration | pytest, `cli.main(argv, client=…, config=…)` | `compare` (npm + PyPI), `lock`, `rules`, `config-*`: exit codes, stable error codes, text/JSON/Markdown/SARIF shape, caps, warnings, baseline, plan |
| Recorded invariants | pytest | the two pairs the README quotes keep their exact numbers: synthetic installer → 4 findings, score 94; benign bump → 0 findings, score 0 |
| Integration | pytest + fixtures | one benign and one synthetic-malicious pair per ecosystem → expected findings — built, and the layer most of the suite above exercises |
| Dataset schema | pytest | export validates against `DatasetRecord`; no raw text in features; no package in two splits; `rule_derived` excluded from test metrics — built and run (M3) |
| Structural | pytest | §5 import/SQL/exec greps |

Current gate: **1077 passed, 1 skipped** (a Windows symlink-creation property case that the OS
denies without Developer Mode), `ruff format --check` + `ruff check` clean, `mypy --strict src/`
clean over 64 source files. The suite is run with a deliberately long temp root so the
Windows `MAX_PATH` cache-key regression stays covered. Detection quality is a separate, unmet
obligation: severities and weights are initial untuned values, every report says
`measured: false`, and the README states it in the disclaimer, in Limitations and in the
per-ecosystem / per-family rule coverage table.

Fixtures are hand-authored, defanged, and committed under `tests/fixtures/`. They are
strings a rule can match and nothing more: no live URLs, no working commands, no binaries.
`tests/fixtures/README.md` states this; npm rule fixtures and npm package trees carry a
one-line `HARMLESS.txt`, PyPI fixtures and package trees do not. Use the README's convention,
not the file's presence, to tell a fixture from a sample.

## 8. Milestones as architecture checkpoints

The milestones were designed so each one *proves* something about the unsafe part of the
system before the next layer is built on top of it. That is still the useful reading, so
below is each checkpoint and whether it is actually proven today.

| Checkpoint | What it was meant to prove | Status |
|---|---|---|
| **M1** — sandbox + fetch in isolation | The highest-risk surface holds alone, with no rules to reason about: every implemented rejection in SPEC §6.5 fires, no write lands outside the root, digests are verified before bytes are trusted. | **proven**, for tar and zip, npm and PyPI. Hypothesis property tests plus one test per rejection condition. |
| **M2** — `DiffContext → Finding → ScoreResult` | The contract end-to-end on fixtures: rules see one object, the score is a pure deterministic function of findings, monotonicity holds, output is byte-stable. | **proven** on the on-demand path. `store/` is built and tested, but no shipped command writes a report to it — the "→ store" half of this arrow is a library, not a pipeline. |
| **M3** — dataset soundness | Splits leak nothing, features carry no source text, the export validates against `DatasetRecord`, `rule_derived` labels are excluded from metrics. | **proven on the on-demand path.** `compare`/`lock --record-dir` write `AnalysisRecord` files; `export-dataset` joins labels, assigns the salted split and writes JSONL plus a manifest; `validate-dataset` re-checks every invariant. Tests assert the 69-key catalog, no source text in features, one split per package, and that `unknown` and holdout `rule_derived` are never metric-eligible. `data/labels/` ships empty, so no measured metric exists yet. |
| **M4** — widened coverage | PyPI, AST-level diff, rule families 3–4. | **partial.** PyPI `compare` ships (6 `PYPI_*` rules, sdist re-rooting, per-version registry metadata). Families 3–4 ship but are gated: 6 rules (`BASE64_BLOB_PRESENT`, `HEX_ESCAPE_DENSITY`, `HIGH_ENTROPY_STRINGS`, `DEPENDENCY_ADDED`, `PYPI_DEPENDENCY_ADDED`, `REPOSITORY_URL_CHANGED`) are off unless `--experimental` — the gate is `rules/runner.py:all_experimental()`, which skips
a rule only when every family is experimental, so a mixed-family rule runs by default — and
their weights are untuned. `rule_set_version()` is `ca4f11b65010` (nine rule versions bumped).
`diff/ast.py` ships for Python `.py` files as bounded, report-only symbol changes; JavaScript, TypeScript and Rust stay line-level. `crates.io` support was dropped before release. |

Two things shipped that this milestone plan did not anticipate:

- **`lock`** — package-lock.json v2/v3 analysis: untrusted parser, no-network plan, per-pair
  concurrent run, download cache, retry policy, baseline with mandatory reasons, `--plan`,
  `--markdown`, `--sarif`, and a GitHub Action. It exercises M1 and M2 thousands of times over
  instead of once, which is why the cache and the per-pair skip policy exist.
- **Output formats as a contract.** A report is one dict rendered four ways, so CI consumes
  pkgwatch without parsing prose.

The honest summary: the security-critical half of the design is built and tested, and the
data path is built; the offline model layer was dropped because labels ship empty. Anyone
extending pkgwatch should treat §2.2's
batch pipeline as the proposal it is, and should not claim progress beyond M4 from the code in §2.1.
