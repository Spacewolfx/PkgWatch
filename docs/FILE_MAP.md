# pkgwatch file map

A map of the repository's tracked files and what each one is for: 353 files, of which
64 Python modules (~11,300 lines) live under `src/pkgwatch/`.

For usage start at [README.md](../README.md), for design and trust boundaries at
[ARCHITECTURE.md](ARCHITECTURE.md), and for the normative contract at
[SPEC.md](../SPEC.md). This file answers only "where does X live and why".

## Find it fast

| I want to... | Go to |
|---|---|
| Change CLI flags, output formats or exit codes | `src/pkgwatch/cli.py` |
| Add or edit a detection rule | `src/pkgwatch/rules/` + `tests/fixtures/rules/` |
| Change how archives are unpacked | `src/pkgwatch/sandbox/` |
| Change registry URLs, retries or the download cache | `src/pkgwatch/fetch/` |
| Change scoring or weights | `src/pkgwatch/score/engine.py` |
| Work on records, features, labels or splits | `dataset/`, `features/`, `labeling/` |
| Work on SQLite state | `src/pkgwatch/store/` |
| Debug npm lockfile analysis | `lockfile/`, `lock/` |
| Add a contributor guide or doc | `docs/` (start at `docs/README.md`) |

## Repository root

```
pkgwatch/
├─ README.md                 usage, live examples, limitations
├─ SPEC.md                   normative contract (schemas, rules, split)
├─ CHANGELOG.md              0.3.1 release notes
├─ LICENSE                   MIT, "pkgwatch contributors"
├─ pyproject.toml            packaging, dependencies, pytest/ruff/mypy
├─ uv.lock                   locked dependencies
├─ action.yml                GitHub composite action definition
├─ .python-version           Python version
└─ .gitignore
```

## `src/pkgwatch/` — runtime

```
src/pkgwatch/
├─ __main__.py               python -m pkgwatch entry point
├─ cli.py                    compare / lock / export-dataset / validate-dataset
├─ config.py                 TOML configuration and defaults
├─ models.py                 shared data models (Diff, Finding, AstLimits, ...)
├─ version.py                version parsing and comparison
├─ py.typed                  PEP 561 marker: type hints ship with the package
│
├─ fetch/                    registry access
│  ├─ npm.py                 npm metadata + tarball
│  ├─ pypi.py                PyPI JSON + sdist/wheel
│  ├─ cache.py               content-addressed download cache
│  └─ retry.py               retries and backoff
│
├─ sandbox/                  safe extraction (no package code is executed)
│  ├─ plan.py                extraction plan per archive type
│  ├─ extract.py             executor
│  ├─ tar_reader.py          tar/.tar.gz reader
│  ├─ zip_reader.py          zip reader
│  ├─ write.py               bounded writes to disk
│  ├─ names.py               path and glob safety
│  └─ errors.py
│
├─ diff/                     version-pair comparison
│  ├─ files.py               additions/removals/changes + AST attachment
│  ├─ manifest.py            package.json / pyproject changes
│  ├─ pypi_metadata.py       PyPI metadata changes
│  └─ ast.py                 Python symbol diff (functions/classes/imports)
│
├─ rules/                    18 rules in six families
│  ├─ runner.py              rule executor
│  ├─ registry.py            rule registry
│  ├─ scan.py                source scanning helpers
│  ├─ guard.py               safe access and limits
│  ├─ family1_lifecycle.py   lifecycle (npm)
│  ├─ family1_pypi.py        lifecycle (PyPI)
│  ├─ family2_capability.py  capability (npm)
│  ├─ family2_pypi.py        capability (PyPI)
│  ├─ family3_obfuscation.py obfuscation/concealment (experimental)
│  ├─ family4_metadata.py    metadata (npm)
│  └─ family4_pypi.py        metadata (PyPI)
│
├─ score/engine.py           weighted score from findings
│
├─ lockfile/                 npm package-lock handling
│  ├─ parser.py              lockfile parsing
│  └─ plan.py                split into version pairs
│
├─ lock/                     lock execution
│  ├─ run.py                 batch analysis
│  ├─ baseline.py            baseline comparison
│  └─ report.py              Markdown/JSON report
│
├─ store/                    SQLite state
│  ├─ schema.py              schema (user_version 1)
│  ├─ db.py                  connection and migrations
│  └─ repo.py                queries
│
├─ features/build.py         closed catalog of 69 features
│
├─ labeling/                 label sources
│  ├─ human.py               reviewer CSV
│  ├─ advisory.py            OSV malicious-packages
│  ├─ policy.py              precedence: human > advisory > rule
│  └─ errors.py
│
├─ dataset/                  M3 data pipeline
│  ├─ record.py              AnalysisRecord construction
│  ├─ canonical.py           canonical JSON
│  ├─ split.py               permanent salted split
│  ├─ export.py              dataset.jsonl + manifest
│  ├─ validate.py            re-check every invariant
│  └─ errors.py
│
└─ ingest/                   currently only __init__.py (planned feed layer)
```

## `tests/` — 259 files

```
tests/
├─ conftest.py
├─ unit/                     one test module per unit
│  ├─ dataset/               4 files
│  ├─ diff/                  3 files (ast, files, pypi_metadata)
│  ├─ features/              1
│  ├─ fetch/                 4 (npm, pypi, cache, retry)
│  ├─ labeling/              3 (human, advisory, policy)
│  ├─ lock/                  4 (run, run_records, baseline, report)
│  ├─ lockfile/              2 (parser, plan)
│  ├─ rules/                 8 (families + registry/runner/scan)
│  ├─ sandbox/               9 + helpers (tar/zip rejection, links, size)
│  ├─ score/                 1
│  ├─ store/                 2 (migrations, repo)
│  ├─ version/               3 (parse, compare, properties)
│  └─ root tests             config, models, structure, docs, release metadata, ...
├─ integration/              7 end-to-end CLI tests
│  ├─ test_compare_cli.py
│  ├─ test_pypi_compare_cli.py
│  ├─ test_ast_compare_cli.py
│  ├─ test_lock_cli.py
│  ├─ test_rules_cli.py
│  ├─ test_dataset_cli.py
│  └─ test_npm_release_pair.py
├─ support/                  fake registries, archives, lockfiles, record helpers
└─ fixtures/
   ├─ rules/                 143 small rule fixtures
   ├─ packages/              16 npm package trees
   └─ pypi-packages/         13 PyPI package trees
```

## Docs, examples, and data

```
docs/
├─ README.md                 index of all documentation
├─ BUILD.md                  build wheel/sdist, verify artifacts, version bumps
├─ CONTRIBUTING.md           safety rules, setup, gates, how to add a rule or ecosystem
├─ ARCHITECTURE.md           module boundaries, trust boundaries, data flow, M1–M4 status
├─ FILE_MAP.md               this file — repository layout, file by file
├─ ci.md                     GitHub Action / CI usage
├─ dataset.md                record → label → export pipeline
├─ pypi.md                   PyPI behaviour and limits
└─ rules.md                  rule catalog and families

examples/
├─ github-workflow.yml       ready-made CI workflow
├─ pkgwatch.toml             example configuration
├─ lock-old.json / lock-new.json / lock-git.json

eval/measure_m2/
├─ measure.py                harness measuring M2 rules on a benign list
├─ benign_list.example.txt
├─ measure.example.toml
└─ out/.gitkeep

data/
├─ labels/.gitkeep           human labels (empty)
├─ raw/.gitignore            raw records (untracked)
└─ splits/.gitkeep           split outputs
```

## Request flow

`cli.py` → `fetch/` (registry) → `sandbox/` (extract) → `diff/` + `rules/` → `score/` → report.
With `--record-dir`: `dataset/record.py` → `features/` → `labeling/` → `dataset/split.py`
→ `export.py` → `validate.py`.
