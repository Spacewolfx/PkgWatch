# Dataset path — record → label → split → export → validate

M3 turns pairs that `compare` and `lock` already analyse into a sound, reproducible,
label-joined dataset. It trains nothing and it adds **no** store migration:
the persisted unit is a JSON record file, not a database row.

Everything here is static analysis. No package content is executed, imported, installed or
built, and no command in this path opens a network connection.

## 1. Record — `compare` and `lock`

```bash
pkgwatch compare npm:left-pad@1.2.0 npm:left-pad@1.3.0 --record-dir records/
pkgwatch lock --old old-lock.json --new new-lock.json --record-dir records/
```

One `AnalysisRecord` JSON file per analysed changed pair. The filename is the full SHA-256 of
`"<ecosystem>|<package>|<old>|<new>"` plus `.json`, so scoped npm names and `+`/`~` in
versions never reach the filesystem. The identity is inside the file; the filename is never
parsed.

A record is a pure function of the two artifacts, the rule set and the resolved config:
there is no timestamp, so re-recording the same pair is byte-identical. Findings are the
**unfiltered** set — `--ignore` and baseline suppression never become dataset content — and
the chain is re-scored from scratch.

Exclusions, always counted, never silent:

| Case | Behaviour |
|---|---|
| Brand-new package (no old artifact) | not recorded; `reason="new_package"`. An old-side digest is never invented. |
| `analysis_incomplete` | recorded for audit value, **never exported**; counted as `skipped_incomplete`. |
| Fetch / archive failure | no record; the existing stable error code is unchanged. |

`lock` treats a failed record write as a per-pair skip (`record_errors` in its JSON report)
and never aborts the run. `--plan --record-dir` is refused with
`RECORD_OPTIONS_CONFLICT`; plan mode analyses nothing, so there would be nothing to record.

## 2. Label

Labels are the only non-deterministic input, so they follow SPEC §7. The labels directory
is laid out as `<labels>/human/*.csv` and `<labels>/advisories/*.json`; a missing
subdirectory means "no claims from that source".

**Human** rows use exactly these nine columns:

```
ecosystem,package_name,old_version,new_version,label,reviewer,reviewed_at,confidence,note
```

`note` is parsed for shape and dropped: reviewer prose never reaches a shipped dataset. A
malformed row rejects the whole file (`LABEL_CSV_INVALID` or `LABEL_VALUE_INVALID`, with the
1-based CSV record number). The same identity twice is `HUMAN_LABEL_DUPLICATE`.

**Advisory** data is operator-supplied OSV JSON (OpenSSF `malicious-packages`, Apache-2.0).
A record is `malicious` only when the package name matches **and** the new version is inside
an `affected[].ranges[].events` interval or listed in `affected[].versions[]`. A name match
with the version outside every interval is an explicit `unknown` claim at confidence 0.9 —
"the advisory database knows this package and does not accuse this version". Malformed JSON
is `ADVISORY_JSON_INVALID`.

Precedence is `human` > `advisory_db` > `rule_derived` > `none`. `rule_derived` is
`suspicious` when the score is at least 40, else `benign`, at confidence exactly 0.3, and it
is only a candidate when the score is above 0. Every losing claim is written to
`label_conflicts.jsonl` with reason `precedence` or `advisory_duplicate`.

Every file under `data/labels/` needs a row in `data/labels/PROVENANCE.md` (source URL,
retrieval date, license, SHA-256 of the file). Advisory provenance is
`osv:<id>:<file_sha256[:12]>`: an OSV document carries no commit SHA, so the upstream commit
belongs in `PROVENANCE.md`, not in a fabricated identifier.

## 3. Split

```
bucket = int(sha256(f"pkgwatch-split-v1|{ecosystem}|{package_name}").hexdigest()[:8], 16) % 1000
train if bucket < 700 else (val if bucket < 850 else test)
```

Salted, fixed, no `hash()`, no version component. A package is in exactly one split forever,
so the same package's old version cannot appear in train while its new version appears in
test. `npm` `foo` and PyPI `foo` are independent scopes.

## 4. Export — `export-dataset`

```bash
pkgwatch export-dataset --records records/ [--labels data/labels] [--out data/dataset] [--json]
```

Writes `data/dataset/<run_id>/`:

- `dataset.jsonl` — one `DatasetRecord` per line, sorted by
  `(ecosystem, package_name, old_version, new_version)`, never by filename.
- `manifest.json` — schema and rule-set versions, `config_sha256`, `experimental`, split salt
  and thresholds, `seeds` (empty; M3 samples nothing), toolchain versions, `sqlite_user_version:
  null` (no database was touched), `git_sha`, record/skip counts, label and split counts,
  `feature_catalog_sha256` and `records_sha256`.
- `label_conflicts.jsonl` — always present, empty when there are none.

`run_id` is `UTC-compact-timestamp + "-" + sha256(canonical manifest)[:8]`; the manifest never
contains `run_id`. Two identical exports in the same second collide by design, and a colliding
run directory is refused with `EXPORT_RUN_EXISTS`, never overwritten.

Records that disagree on `(schema_version, rule_set_version, weights_version, config_sha256,
experimental)` are refused with `DATASET_RECORD_INHOMOGENEOUS`: two analyses under different
rules or limits are not comparable. An empty record directory is `EXPORT_NO_RECORDS`.
Brand-new packages are dropped at record time, so the exporter cannot count them; the
manifest records `skipped.new_package: null` rather than a false zero.

## 5. Validate — `validate-dataset`

```bash
pkgwatch validate-dataset --path data/dataset/<run_id>/dataset.jsonl [--json]
```

Re-checks every invariant from the file: schema version and rule identities, the exact
69-key feature catalog and categorical allow-lists, split equality with the recomputed split,
one split per package, no duplicate pair, no eligible `unknown`/holdout `rule_derived`, and no
incomplete record. With `--json` the payload is
`{ok, record_count, errors: [{code, line, detail}]}`, sorted by `(line, code)`.

Exit codes: `2` for any tool error, `1` for invalid content, `0` when valid. That `1` is the
single deliberate exception to the tool's "any error is 2" rule (SPEC §6.4): an invalid
dataset is a verdict about the data, not a crashed tool.

## 6. Features

Every record always carries the same closed catalog of 69 keys, in sorted order: 6 `size_*`,
34 `file_*`, 4 `dep_*`, 6 `capability_*`, 6 `obfus_*`, 4 `manifest_*`, 8 `score_*`, and the
categorical `ecosystem`. A missing feature is a schema error, not a silent zero. Two
categorical vocabularies exist (`ecosystem`, `file_dominant_role`); **`file_extension` is
deliberately never emitted**, because an extension is attacker-controlled and unbounded.

No feature carries a path, evidence, file content, package name, version string, dependency
name or any raw source text. `DatasetFinding` keeps only `rule_id`, `rule_version` and
`severity`.

## 7. What an export is not

`data/labels/` ships empty. Every export today is therefore `unknown` (no claim) or
`rule_derived` (weak, score-derived). `unknown` is never metric-eligible in any split, and
`rule_derived` is never metric-eligible on `val`/`test`, so **no classification metric may be
reported on an export made from this repository as it stands**. The export is the honest
denominator and the future training input; it is not a measured detection result.
