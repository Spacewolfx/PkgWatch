# pkgwatch — ARCHITECTURE

Version: 0.1 (design, milestone M1) · Status: awaiting approval · Date: 2026-11-05

pkgwatch watches releases of *monitored* packages on npm, PyPI and crates.io, compares
each release against the one before it, extracts behavioral changes as deterministic
findings, scores them with a rule engine, and stores every result as a structured record
that can be exported as a labeled dataset.

Two commitments shape the whole design:

1. **The rule engine is the source of truth for alerts.** Nothing a model produces can
   raise, suppress, or change an alert.
2. **Package content is hostile input.** It is downloaded, unpacked, read, and parsed —
   never executed, imported, installed, or run, not even in tests.

---

## 1. Components

| Directory | Component | Responsibility | Milestone |
|---|---|---|---|
| `src/pkgwatch/config.py` | Config | Limits, ecosystems, paths, thresholds, seeds; loaded from TOML | M1 |
| `src/pkgwatch/models.py` | Records | pydantic v2 models for everything crossing a module boundary | M1 |
| `src/pkgwatch/ingest/` | Feed readers | Discover new releases per ecosystem; `npm.py`, `pypi.py`, `crates.py` | M1 (npm), M4 |
| `src/pkgwatch/fetch/` | Downloader | Fetch tarball + metadata to `data/raw/`; verify digest; **no extraction** | M1 |
| `src/pkgwatch/sandbox/` | Safe unpacker | Archive validation and extraction under hard limits | M1 |
| `src/pkgwatch/diff/` | Differ | File-level changes (M2), then AST-level changes (M4) | M2, M4 |
| `src/pkgwatch/rules/` | Rule families | Pure functions `DiffContext -> list[Finding]` | M2 (families 1–2), M4 (3–4) |
| `src/pkgwatch/features/` | Featurizer | Numeric/categorical features; **no raw source text** | M3 |
| `src/pkgwatch/score/` | Scorer | Deterministic score from findings + weights | M2 |
| `src/pkgwatch/store/` | Repository | The only module that touches SQL | M2 |
| `src/pkgwatch/dataset/` | Exporter | JSONL export, split assignment, schema validation | M3 |
| `src/pkgwatch/labeling/` | Label sources | Human files + OSV advisory DB, label policy | M3 |
| `src/pkgwatch/model/` | Offline layer | Train / eval / explain; never imported by ingestion | M5 |
| `src/pkgwatch/cli.py` | Entry point | Thin argparse wrapper over the above | M1 |

Dependency direction is strictly left-to-right through this list. `models.py` and
`config.py` depend on nothing but stdlib and pydantic; every other module may depend on
them, never the reverse.

## 2. Data flow

```
                     ┌──────────────────────────────────────────────────────────┐
                     │  HOT PATH (deterministic, no model, no LLM)              │
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
              dataset/export.py ──▶ data/dataset/*.jsonl ──▶ labeling/ (M3)
                                          │
                                          ▼ (offline, separate command, separate env)
                                    model/ train · eval · explain   (M5)
```

The double rule is a real architectural line, enforced by an import test (§5).

**Diff needs both sides.** Extraction results are content-addressed by tarball SHA-256 and
reused, so comparing vN against vN−1 costs one new extraction in the common case. The
previous release is fetched lazily if its tree is not in the cache.

**Everything is resumable.** Each stage advances a status column on `releases`
(`pending → fetched → extracted → diffed → scored → exported`) plus a `stage_error`
string. A crash mid-release leaves a row that the next run picks up; it never re-downloads
and never skips silently.

## 3. Trust boundaries

Five boundaries, each with a named threat and the mechanism that holds it.

### TB1 — Registry → ingest
*Threat:* registry JSON is attacker-influenced (package names, descriptions, maintainer
lists, URLs). *Mechanism:* parsed with pydantic into `Release`; field-length caps; unknown
fields dropped; no URL ever constructed from a package-owned string without validation.
Registry responses are never treated as truth about behavior, only about existence and
coordinates.

### TB2 — Network → fetch
*Threat:* artifact substitution, truncated download, gzip-of-death. *Mechanism:* download
to a temp file, stream-hash, compare against the registry-supplied `shasum`/`integrity`
when present; store under `artifacts/<observed-sha256>`; reject if the observed size
exceeds `max_artifact_bytes`. Metadata (`package.json`, `PKG-INFO`, `Cargo.toml`) is
separately persisted as a snapshot so metadata diffs never require re-extraction.

### TB3 — Compressed archive → sandbox
*Threat:* the highest-risk surface in the project. Path traversal, absolute paths,
`..` chains, symlink/hardlink escape, device nodes, zip bombs, excessive file count, deep
nesting, Windows-specific escapes (drive letters, UNC, backslashes, case-insensitive
collisions). *Mechanism:* validate **every** member before writing **any** member; write
only under a freshly created temp root; commit by rename. Limits are config, defaults in
SPEC §4. No stdlib convenience is trusted alone — `tarfile`'s `data` filter is applied *in
addition to* our own checks, and our checks are the ones the tests cover.

### TB4 — Unpacked file content → diff, rules, features
*Threat:* content that is huge, binary, invalid UTF-8, or crafted to blow up a parser;
content that leaks into outputs. *Mechanism:* byte-first reading; decode with
`errors="replace"`; per-file size cap for text analysis with `oversized_file` recorded as a
finding rather than a crash; every per-file operation wrapped so an exception becomes a
`RULE_ENGINE_ERROR` info-finding and the worker continues; evidence excerpts hard-capped at
200 characters in the model itself; features typed so raw prose cannot masquerade as a
categorical value (SPEC §6.2). Parsers are AST-only — `ast.parse`, `tomllib`, `json`.
Never `eval`, `exec`, `compile`, `__import__`, `importlib`, `subprocess`, or `pip`.

### TB5 — Store → dataset → model
*Threat:* label leakage, model output re-entering the scoring path, unreproducible
datasets. *Mechanism:* split assigned by hashing `package_name` (never version, never
finding); `rule_derived` labels excluded from val/test metrics by a validator, not by
convention; model outputs live in their own tables and are never joined into `ScoreResult`.

### Process model
One Python process, no subprocess spawning, no execution of package content, no plugin
loading from package content. Extraction and parsing run in-process under resource guards —
a real OS sandbox (container/VM) is a **non-goal** for this codebase (SPEC §2) and anyone
running pkgwatch against live registries should still do so in a constrained environment.
Network egress exists only in `ingest/` and `fetch/`; `diff/`, `rules/`, `features/`,
`score/`, `dataset/` receive paths and bytes, never URLs to fetch.

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

As of M2 only `releases`, `watchlist` and `runs` exist — the three tables SPEC §10 A1
authorises for this milestone, at `user_version` 1. `watchlist` is the operator's set of
packages to follow and is not derived from any package. Every other table above arrives
with its own milestone as a new numbered migration step.

`Release` identity is `(ecosystem, package_name, version)` — unique index. `Finding`
identity additionally carries `rule_id@rule_version`, so re-running a new rule version on an
old release produces new rows instead of silently mutating history (rule-version changes
must be visible in the data).

## 5. Determinism, reproducibility, enforcement

- Every run writes a manifest into its output directory: resolved config, `rule_set_version`,
  weights version, `schema_version`, seeds, tool versions, SQLite `user_version`.
- Seeds fixed for the splitter and for any sampling. No wall-clock, no `hash()`, no dict
  ordering in any computed output — `hash()` is randomized per process, so the splitter uses
  `sha256` (§ SPEC §6.3).
- Findings, file-change lists and feature dicts are emitted in sorted key order; JSON dumps
  use `sort_keys=True`. The same two tarballs in → the same `ScoreResult` bytes out, which
  is what makes the integration tests meaningful and what makes the dataset stable enough to
  train on.
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

## 6. Extension points

- **Rules** register through a decorator carrying `rule_id`, `rule_version`, `severity`,
  `ecosystems`; discovery is explicit (a registry list in `rules/__init__.py`, not filesystem
  scanning) so `rule_set_version` is reproducible.
- **Ecosystems** implement one `FeedReader` protocol (`discover`, `describe`) and one
  `ArtifactSource` protocol (`tarball_for`); adding an ecosystem touches nothing downstream
  except a rule-eligibility filter.
- **Label sources** implement `LabelSource.load() -> list[LabeledKey]`; a new advisory feed
  is a new file in `labeling/`, and cannot invent labels without declaring `label_source`.

## 7. Testing strategy

| Layer | Tool | Covers |
|---|---|---|
| Sandbox property tests | hypothesis | arbitrary member names/types/sizes: no write ever lands outside the root; limit violations always rejected, never partial |
| Sandbox rejection tests | pytest, one case per limit | each of the ~20 rejection conditions in SPEC §4.3 individually |
| Version parser | hypothesis | total order, antisymmetry, transitivity, sort stability, parse/format round-trip |
| Rule fixtures | pytest parametrized | every rule has ≥1 positive and ≥1 negative synthetic fixture |
| Score | pytest | monotonicity: adding a finding never lowers the score; decay and caps exact |
| Integration | pytest + fixtures | one benign and one synthetic-malicious pair per ecosystem → expected findings (M2+) |
| Dataset schema | pytest | export validates against `DatasetRecord`; no raw text in features; no package in two splits; `rule_derived` excluded from test metrics |
| Structural | pytest | §5 import/SQL/exec greps |

Fixtures are hand-authored, defanged, and committed under `tests/fixtures/`. They are
strings a rule can match and nothing more: no live URLs, no working commands, no binaries.
`tests/fixtures/README.md` states this and each fixture dir carries a one-line
`HARMLESS.txt` so a future contributor does not mistake a fixture for a sample.

## 8. Milestones as architecture checkpoints

M1 proves the unsafe part (sandbox + fetch) in isolation, with no rules to reason about.
M2 proves the contract end-to-end on fixtures: `DiffContext → Finding → ScoreResult → store`.
M3 proves the dataset is sound: splits leak nothing, features carry no source text, schema
validates. M4 widens coverage (PyPI, crates, AST diff, families 3–4). M5 is the only place a
model appears, and it consumes the M3 export rather than the pipeline.
