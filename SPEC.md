# pkgwatch — SPEC

Version 0.1 · schema_version 1 · weights_version `w1` · rule_set_version (unassigned until M2)

Normative for milestones M1–M5. Where this document says *verified*, it means probed from
this machine on 2026-11-05; where it says *TODO*, the behavior is specified but the
coordinate is not yet confirmed and must not be assumed by a later implementer.

---

## 1. Scope

pkgwatch answers one question per release: **what behavioral capability did this package
gain between the previous release and this one, and what does the rule engine make of it?**

In scope:
- Monitor a user-maintained watchlist of packages on npm, PyPI, crates.io.
- Detect new releases from registry metadata; fetch the sdist/tarball for the new release
  and the one it replaces.
- Extract both safely, diff them at file level (M2) and at AST level (M4).
- Run versioned, pure-function rules over the diff to produce `Finding` records.
- Score findings deterministically; alert thresholds are a function of the score alone.
- Persist everything; export a JSONL dataset whose records are labeled, split, and
  schema-versioned for optional post-training of a small model.

## 2. Non-goals

- **Not a runtime sandbox.** Nothing is executed, installed, imported, or run — not in the
  pipeline, not in tests. pkgwatch is static-only by construction.
- **Not a malware classifier with verdicts.** Rules report signals; the score is an ordering,
  not a claim about intent. Obfuscation rules report the signal and stop.
- **Not a network detector.** No C2 hunting, no live traffic analysis, no domain reputation.
- **Not a full registry crawler.** Watchlist-driven, not firehose-driven (§3 npm feed).
- **Not an auto-quarantine tool.** It informs a human; it does not report to a registry.
- **No container/VM isolation of the parser.** Hardened in-process limits only (TB3).
- **No model in the alert path.** Ever. (ARCHITECTURE §5a.)
- **Not a license/SCA tool**, no vulnerability CVE matching (OSV is consumed only for
  *malicious package* labels).

## 3. Trust boundaries and data flow

See ARCHITECTURE.md §2–§3 for the diagram and the five boundaries. This section pins the
external coordinates each boundary touches.

**Verified endpoints** (probed 2026-11-05, status in parentheses):

| Ecosystem | Purpose | Endpoint | Status |
|---|---|---|---|
| npm | full package doc (dist-tags, `time`, per-version `dist.tarball`) | `GET https://registry.npmjs.org/<name>` | 200 ✅ |
| npm | dist-tags only | `GET https://registry.npmjs.org/-/package/<name>/dist-tags` | 200 ✅ |
| npm | per-package "recent updates" RSS | `GET https://registry.npmjs.org/-/rss?<name>` | 200 ⚠️ title is `npm recent updates`; whether the query scopes to the package is **unverified** — not used in M1 |
| PyPI | package JSON (`urls[]`, `info.requires_dist`, `uploads`) | `GET https://pypi.org/pypi/<name>/json` | 200 ✅ |
| PyPI | per-version JSON | `GET https://pypi.org/pypi/<name>/<version>/json` | TODO (not probed) |
| PyPI | release RSS | `GET https://pypi.org/rss/project/<name>/releases.xml` | 200 ✅ |
| crates | version list | `GET https://crates.io/api/v1/crates/<name>/versions` | 200 ✅ **only with a `User-Agent`**; 403 without |
| crates | tarball | `GET https://crates.io/api/v1/crates/<name>/<version>/download` → 303 | TODO (redirect target not probed) |

Consequences already designed in: crates.io requests always send
`User-Agent: pkgwatch/<version> (<contact>)`; registry-hosted names are percent-encoded and
scoped names (`@scope/pkg`) use the `%2F` form; npm `dist` carries `fileCount` and
`unpackedSize`, which TB3 uses as a *pre-flight* cross-check against observed extraction.

**Dead endpoint, do not build on it:** `https://registry.npmjs.org/-/feed/recent` → 404 and
`/-/feed/updated` → 404. Global npm firehose ingestion is therefore **out of scope for M1**;
npm ingest polls the watchlist doc endpoint and uses `time[version]` for discovery.
TODO (M4+): confirm a supported change-stream before writing a firehose reader.

**Fields consumed, per ecosystem** (only these; everything else is dropped):

- npm: `name`, `dist-tags.latest`, `time` (map: version → ISO8601, plus `created`/`modified`),
  `versions[v].dist.{tarball,shasum,integrity,size,fileCount,unpackedSize}`,
  `versions[v].{dependencies,devDependencies,scripts,engines,os,cpu,bin,gpt}` — note
  `scripts` is read from the doc snapshot for lifecycle detection, and re-read from the
  extracted `package.json` as the authoritative copy;
  `maintainers[{name,email}]`, `repository.url`, `_npmUser`, `deprecated`.

  **`dist.size` is not always present.** In the live `is-number` smoke run (2026-11-07) it was
  `null` on both sides. It stays in this list and the code that tolerates its absence stays;
  consumers must treat it as optional, never as guaranteed. The same applies to any other
  per-version field: absent and explicitly `null` are reported as such, not as empty.
- PyPI: `info.name`, `info.version`, `info.requires_dist`, `info.maintainer(_email)`,
  `info.project_urls`, `urls[].{filename,packagetype,url,sha256,size,upload_time,
  python_version}`. **Preference order for the artifact: `sdist` first** (behavior lives in
  `setup.py` / `pyproject.toml`), then `bdist_wheel`, then `other`.
- crates: `versions[].{crate, num, created, downloads, yanked}`, `dependencies[].{crate_id,
  req, kind, optional}`; tarball from the download route.

**TODO(v0.2) — operator decision, initial untuned values, not measured (2026-11-07):**
`versions[v].gpt` looks like a typo. No replacement is guessed; that token is ignored and
must not appear in a rule, a metadata section, or a field name until it is confirmed against
a live document. TODO: verify the real field. Likewise `maintainers[{name,email}]`,
`repository.url`, `_npmUser` and `deprecated` are listed here as *package-document-level*
snapshots, not as `versions[v]` fields: a snapshot of the current state cannot be diffed
between two versions. TODO: confirm their placement in a live document. `MAINTAINER_ADDED`
is therefore DEFERRED (§4.5.1). The "registry metadata changes" section may print only
`versions[v]` fields, and prints `(not available)` for any field the document omits — it
must never assume `maintainers` exists.

## 4. Rule contract

### 4.1 Signature and registry

Every rule is a pure function of one object:

```python
RuleFn = Callable[[DiffContext], list[Finding]]   # no I/O, no clock, no env, no globals

@registry.register(
    rule_id="NPM_INSTALL_SCRIPT_ADDED",
    rule_version=1,
    severity="high",
    ecosystems=("npm",),
    families=(RuleFamily.LIFECYCLE_SCRIPTS,),
)
def npm_install_script_added(ctx: DiffContext) -> list[Finding]: ...
```

Rules must be: deterministic (same `DiffContext` → same list, same order); total (never
raise — see §4.4); side-effect free; and unaware of any model, label, or stored history
beyond what `DiffContext` carries. `rules/__init__.py` holds the registry as an explicit
list. Registration order fixes emission order.

**Mandatory per rule** (enforced by a parametrized test over the registry):
1. ≥1 positive fixture and ≥1 negative fixture under
   `tests/fixtures/rules/<rule_id>/{positive,negative}/`;
2. a docstring stating **what it detects** and **what it deliberately ignores** — the
   ignore-list is what stops a later contributor from "fixing" a deliberate blind spot;
3. `rule_id` stable across versions — a rename is a new rule, the old one is retired in
   place with its final `rule_version`;
4. `rule_version` bumped on **any** change to detection semantics (not to formatting).

### 4.2 `DiffContext` — what a rule may see

`ecosystem`, `package_name`, `old_version`, `new_version`, `published_at`,
`changes: list[FileChange]`, `files_new`/`files_old` (virtual-path → `FileView` index),
`metadata_before`/`metadata_after` (parsed registry manifest),
`parse_errors: list[ParseError]`, `limits` (the active config, so rules can respect caps).

`FileView` gives `path`, `content` (`str`, decoded with `errors="replace"`, truncated at
`max_text_scan_bytes`), `is_text`, `size`, `sha256`, `truncated: bool`, and
`diff_lines: list[DiffLine]` where `DiffLine.op ∈ {add, del, ctx}`. A rule that needs a
line range reads `diff_lines`, not the whole file, so evidence ranges are always inside the
changed region.

Rules see the union of the two trees: a file present only in `new` is `ADDED`, only in `old`
is `REMOVED`, and both is `MODIFIED` (equal SHA-256 → `UNCHANGED`, excluded from rule input
but retained in features as a ratio).

### 4.3 `Finding` — required fields

| Field | Type | Rule |
|---|---|---|
| `rule_id` | `str` | stable, uppercase, ecosystem-prefixed where scoped |
| `rule_version` | `int` | ≥1 |
| `severity` | enum | `info` `low` `medium` `high` `critical` |
| `path` | `str \| None` | virtual path **relative to the extraction root**, POSIX separators; `None` only for package-level findings |
| `evidence` | `str` | **hard-capped at 200 chars by the model**, truncated with `…` marker; never contains a decoded secret or a URL that came from outside the package |
| `line_start`, `line_end` | `int \| None` | 1-based, inclusive; `None` for package-level |
| `ecosystem`, `package_name`, `old_version`, `new_version` | `str` | denormalised so a finding row is self-describing |
| `details` | `dict[str, int\|float\|bool\|str]` | small, string values ≤64 chars |

`finding_uid` = `sha256(rule_id|rule_version|path|line_start|line_end|evidence)[:16]` —
stable across runs, so re-scoring is idempotent.

### 4.4 Failure policy

Per file, per rule, `try/except Exception` around the analysis body. An exception becomes
`Finding(rule_id="RULE_ENGINE_ERROR", severity="info", path=<file>,
details={"exception": <class name>, "rule_id": <origin>})` and the worker continues with the
next file. The exception class name and the path are recorded; the traceback text and the
file content are **not**, because a parser error message can echo hostile source. A release
whose analysis produced `RULE_ENGINE_ERROR` findings is marked `analysis_incomplete=True` and
is excluded from dataset export — partial coverage in a labeled dataset is a silent lie.

The same record shape carries the two engine-level cases that are not a rule's fault: a rule
returning a finding under a foreign `rule_id` (details `exception="RuleContractViolation"`) and
a file whose view the diff stage could not read (details `stage="diff"`, `kind` = the
`ParseErrorKind`, `reason` = the first 64 characters of its detail). Both mean "this release was
not fully analysed", so both flip `analysis_incomplete`.

### 4.5 Families

| # | Family | M1 | Examples (rule_id) |
|---|---|---|---|
| 1 | Lifecycle scripts | — (M2) | `NPM_INSTALL_SCRIPT_ADDED`, `NPM_SCRIPT_INJECTION_FROM_METADATA`, `PY_SETUP_CMDCLASS_HOOK_ADDED`, `RUST_BUILD_RS_ADDED_OR_CHANGED` |
| 2 | New dangerous capability (present in `new`, absent in `old`) | — (M2) | `JS_CHILD_PROCESS_ADDED`, `PY_SUBPROCESS_ADDED`, `NET_ACCESS_ADDED`, `DYNAMIC_EVAL_ADDED`, `FS_WRITE_OUTSIDE_PACKAGE_ADDED`, `ENV_ENUMERATION_ADDED`, `RUST_UNSAFE_OR_FFI_ADDED` |
| 3 | Obfuscation signals (report the signal, not the intent) | — (M4) | `BASE64_BLOB_PRESENT`, `HIGH_ENTROPY_STRINGS`, `HEX_ESCAPE_DENSITY` |
| 4 | Metadata changes | — (M4) | `MAINTAINER_ADDED`, `DEPENDENCY_ADDED`, `REPOSITORY_URL_CHANGED` |

Family 2's "absent before" is evaluated against the *whole old tree*, not the changed file —
a capability that already existed elsewhere in the package is not new. Family 3 thresholds
(entropy, blob length, escape density) are config, and the rule text names them.

### 4.5.1 v0.2 npm rules — operator decision, initial untuned values, not measured

**Operator decision, initial untuned values, not measured (2026-11-07).** The IDs in the
§4.5 table are normative for these five rules. `rule_version = 1` for all of them. They are
npm-only, pure `DiffContext -> list[Finding]` functions, and follow §4.1/§4.4 unchanged.
Both families are **experimental**: they are disabled by default and run only with
`--experimental` (v0.3); experimental findings are marked `(experimental)` in `--explain`
output. Their severities and thresholds stay untuned operator decisions, not measured.

| `rule_id` | family | severity | base (§5) | reads |
|---|---|---|---|---|
| `BASE64_BLOB_PRESENT` | 3 obfuscation | `low` | 4 | ADDED lines of new text views |
| `HIGH_ENTROPY_STRINGS` | 3 obfuscation | `low` | 4 | ADDED lines of new text views |
| `HEX_ESCAPE_DENSITY` | 3 obfuscation | `low` | 4 | ADDED lines of new text views |
| `DEPENDENCY_ADDED` | 4 metadata | `low` | 4 | `metadata_before/after` → `versions[v].dependencies` |
| `REPOSITORY_URL_CHANGED` | 4 metadata | `medium` | 10 | `repository` field of the root `package/package.json` in **both** trees, via the same defensive parser as the "package.json changes" section |

Family 3 reports the signal only, never intent, on ADDED lines only. `details` carries a
`likely_minified` boolean (a matching line of length ≥ 500) so a reader can discount it; it
is never a suppression, and no file name (`*.min.js`, `dist/`, …) may suppress a finding —
that would be an evasion path. Evidence never prints a whole blob. Thresholds are the
`[obfuscation]` config in §6.5.1, and each rule's text names the threshold it uses.

**DEFERRED (TODO):** `MAINTAINER_ADDED`. Package-level `maintainers` is a snapshot of the
current state, not a per-version value, so it cannot be diffed between two versions. It is
not registered and has no fixture. Family 4 in v0.2 ships `DEPENDENCY_ADDED` and
`REPOSITORY_URL_CHANGED` only. TODO: `devDependencies`, `engines`, `os`, `cpu`, `bin`,
`_npmUser`, `deprecated` and doc-level `repository.url` are not yet rules; none may be
invented as a rule without an operator decision.

**Malformed root manifest — operator decision, initial untuned values, not measured
(2026-11-07):** `ParseErrorKind` gains `manifest`; its `detail` is the stable token
`MANIFEST_INVALID_JSON`. A malformed or non-object root `package/package.json` is recorded
as a parse problem, never raised, and flips `analysis_incomplete` (CLI exit 2). The same
defensive parser is used by the "package.json changes" section and by
`REPOSITORY_URL_CHANGED`.

## 5. Score — weights and computation

`score()` is a pure function of `(findings, weights)`. No model output, no clock, no
registry state. Monotone: adding a finding never lowers the score. **weights_version `w1`.**

Severity base weights:

| Severity | Base | Rationale |
|---|---|---|
| `info` | 0 | reported, never alerts |
| `low` | 4 | housekeeping signal (new dep, maintainer change) |
| `medium` | 10 | capability present, benign explanations common |
| `high` | 20 | capability newly gained, or a script that runs at install time |
| `critical` | 35 | install-time execution combined with a gained capability |

**Step 1 — per-rule aggregation.** Findings are grouped by `rule_id` (not by file, so a
package that adds 400 files does not add 400 points). Within a group, findings are sorted by
`(path, line_start)` and weighted by count decay:

```
count_weight = 1.0 + 0.5 + 0.25          # instances 1, 2, 3; instances ≥4 add 0
rule_score(rule_id) = base(severity_max_in_group) * min(count_weight, 1.75)
```

`severity_max_in_group` takes the highest severity present in the group, so a group is
scored at its worst finding.

**Step 2 — corroboration.** Co-occurrence, not volume:

| Condition | Boost | Applied once |
|---|---|---|
| ≥2 distinct rules with base ≥20 fire | +10 | yes |
| A family-1 rule **and** a family-2 rule both fire | +20 | yes |
| A family-1 rule and ≥3 family-3 (obfuscation) rules fire | +15 | yes |

**Step 3 — total.** `score = clamp(round(Σ rule_scores + Σ boosts), 0, 100)`.

**Thresholds:** `alert = score >= 40`; `escalate = score >= 70`. Substantive signal starts
around 25 (one high, or several mediums) and 40 requires either one critical or a corroborated
pair — that is deliberate: a single `low` never alerts, and no single `high` alone escalates.

`ScoreResult` carries `score`, `rule_set_version`, `weights_version`, the contributing
findings, `breakdown: list[{rule_id, rule_version, base, count_weight, subtotal}]` and
`boosts: list[{name, points}]` — the boost list is what makes a 94 explainable without
re-deriving it — so a human can see exactly why. `rule_set_version` = `sha256` over the sorted
`rule_id@rule_version` list, first 12 hex chars — it changes the moment any rule semantics
change, which is the point.

**Operator decision, initial untuned values, not measured (2026-11-07):** v0.2 introduces
**no new weights**. The five new rules use the existing `w1` severity bases from the table
above: `low` → 4 for `BASE64_BLOB_PRESENT`, `HIGH_ENTROPY_STRINGS`, `HEX_ESCAPE_DENSITY`
and `DEPENDENCY_ADDED`; `medium` → 10 for `REPOSITORY_URL_CHANGED`. No existing base,
decay, cap, boost or threshold changes; `weights_version` stays `w1`. The §5 Step-2 boost
"A family-1 rule and ≥3 family-3 rules fire" needs exactly the three family-3 IDs above.

## 6. Record schema

All records are pydantic v2, `model_config = ConfigDict(extra="forbid", frozen=True)`, so a
new field is a deliberate edit here and not an accident upstream.

### 6.1 Pipeline records

- **`Release`** — `ecosystem`, `package_name`, `version`, `published_at`, `previous_version`,
  `previous_published_at`, `tarball_url`, `sha256`, `size`, `registry_snapshot: dict`,
  `source_endpoint`. `previous_version` is chosen by `published_at` from the registry `time`
  map, **not** by version-string order, because registries yank, retract and backfill; the
  tie-break, when timestamps collide, is the ecosystem version order (§6.4). `retracted`
  (npm `deprecated`, crates `yanked`) is recorded but never used to *exclude* a release —
  retracted releases are prime suspects.
- **`FileChange`** — `path_old`, `path_new`, `change_type ∈ {added, removed, modified,
  renamed, unchanged, binary, mode_only, nested_archive}`, `size_old`, `size_new`,
  `sha256_old`, `sha256_new`, `lines_added`, `lines_removed`, `mode_new`, `is_text`,
  `role ∈ {source, manifest, lockfile, test, doc, vendor, binary, other}` (path+extension
  heuristic, recorded so features can normalise over it).
- **`SandboxRejection`** — `reason_code` (from §6.5), `detail ≤200 chars`, `offending_path`
  (sanitised), `limit_name`, `limit_value`, `observed_value`. This is a *record*, not an
  exception message, so a rejection is queryable and dataset-visible.
- **`Finding`** — §4.3. **`ScoreResult`** — §5. **`DatasetRecord`** — §6.2.

### 6.2 `DatasetRecord` — the post-training unit

One record per `(ecosystem, package_name, old_version, new_version)`. `schema_version = 1`.

```python
class DatasetRecord(BaseModel):
    ecosystem: Eco                       # "npm" | "pypi" | "crates"
    package_name: str
    old_version: str
    new_version: str
    published_at: AwareDatetime          # tz-aware UTC, serialised ISO-8601
    features: dict[str, FeatureValue]    # numeric or categorical; NO raw source text
    findings: list[DatasetFinding]       # {rule_id, rule_version, severity} only
    rule_score: int                      # 0..100, from score()
    label: Label                         # benign | suspicious | malicious | unknown
    label_source: LabelSource            # human | advisory_db | rule_derived
    label_confidence: float              # 0.0..1.0
    split: Split                         # train | val | test
    schema_version: int                  # 1
    # provenance, not predictions:
    rule_set_version: str
    weights_version: str
    artifact_sha256_old: str
    artifact_sha256_new: str
    analysis_incomplete: bool = False
    metric_eligible: bool                # False for rule_derived on val/test
    label_provenance: str | None         # URL or human reviewer id + date
```

`DatasetFinding` deliberately drops `path`, `evidence`, `details` and `line_*` — the dataset
carries rule *identity*, not package text. Features are the same rule: `FeatureValue` is
`int | float | bool | str`, and a `str` is validated against
`^[A-Za-z0-9_.:/*@+-]{1,48}$` with an allow-list of known categorical vocabularies
(`role`, `ecosystem`, `file_extension`, `change_type`, …). This makes "raw code smuggled
into a feature" a schema error rather than a policy violation — it is the boundary that keeps
the dataset safe to ship and safe to train on.

Feature families (namespaced, non-overlapping): `size_*`, `file_*` (counts by role, added /
removed / modified), `dep_*` (count and ratio of new dependencies), `capability_*` (one
count per capability type), `obfus_*` (max/mean entropy, blob count, escape density),
`manifest_*` (bool flags for hook presence), `score_*` (the rule score and per-severity
finding counts). Derived from diff and findings only.

### 6.3 Split assignment

```
bucket = int(sha256(f"pkgwatch-split-v1|{ecosystem}|{package_name}").hexdigest()[:8], 16) % 1000
train if bucket < 700 else (val if bucket < 850 else test)
```

Salted, fixed, no `hash()` (process-randomised), no version component. A package is in
exactly one split **forever**; `dataset/split.py` exposes the function, and a test asserts
that for every record in a file, all records sharing `(ecosystem, package_name)` share a
`split`, and that no `old_version`/`new_version` pair appears in two splits.
The scope is `(ecosystem, package_name)` rather than bare name so that a package called
`foo` on PyPI and a crate called `foo` are independent — they genuinely are.

### 6.4 Version parsing

Own parser, no third-party semver dependency (fewer unpinned transitive deps, and the
comparator must be property-tested in isolation). Three orderings, one per ecosystem:
npm/crates semver (`major.minor.patch[-prerelease][+build]`, prerelease ordering per semver
§11, **build metadata ignored for precedence** so `1.0.0+a` and `1.0.0+b` are equal — the
comparator is a partial order and the code says so); PyPI PEP 440 (epoch, release,
pre/post/dev, local version ignored for precedence). `version.parse(ecosystem, text)`
raises `UnsupportedVersion` on garbage instead of coercing; hypothesis tests check
reflexivity/antisymmetry/transitivity, sort stability, round-trip `parse → canonical → parse`,
and that `compare(v, v) == 0` for every generated string.

### 6.5 Sandbox limit set and rejection codes

Config-loaded, defaults below; every code has at least one test.

| `limits.` setting | default | rejection code |
|---|---|---|
| `max_artifact_bytes` | 64 MiB | `ARTIFACT_TOO_LARGE` |
| `max_total_uncompressed_bytes` | 80 MiB | `TOTAL_UNCOMPRESSED_EXCEEDED` |
| `max_single_file_bytes` | 16 MiB | `FILE_TOO_LARGE` |
| `max_file_count` | 5000 | `FILE_COUNT_EXCEEDED` |
| `max_entry_depth` | 32 components | `DEPTH_EXCEEDED` |
| `max_entry_path_len` | 512 chars | `PATH_TOO_LONG` |
| `max_compression_ratio` | 200 | `COMPRESSION_RATIO_EXCEEDED` |
| `extract_deadline_seconds` | 60 | `DEADLINE_EXCEEDED` |
| `max_nesting_archives` | 0 (never recurse) | `NESTED_ARCHIVE_NOT_EXTRACTED` (recorded as `FileChange`, not fatal) |

Plus structural rejections: `ABSOLUTE_PATH`, `PATH_TRAVERSAL`, `DRIVE_OR_UNC_PATH`
(Windows), `BACKSLASH_IN_NAME`, `SYMLINK_OUTSIDE_TARGET`, `SYMLINK_ABSOLUTE_TARGET`,
`HARDLINK_OUTSIDE_TARGET`, `PARENT_IS_SYMLINK`, `DEVICE_OR_FIFO`, `UNSUPPORTED_MEMBER_TYPE`,
`CASE_COLLISION` (win32 case-insensitive filesystem — two members differing only by case are
rejected, since an overwrite would silently corrupt the tree we then analyze),
`NAME_HAS_CONTROL_CHARS`, `WINDOWS_ILLEGAL_NAME` (trailing space/dot, reserved `CON`/`NUL`),
`EXTRACTION_ROOT_ESCAPE`, `ARCHIVE_TRUNCATED`, `ARCHIVE_FORMAT_UNSUPPORTED`,
`DIGEST_MISMATCH`, `LIMITS_DISAGREE_WITH_REGISTRY` (observed bytes vs npm
`dist.unpackedSize`, tolerance 5%).

Extraction protocol: **validate-all-then-write-none**; `tarfile` opened with
`filter=` our own function plus `tarfile.data_filter` composed after it (belt and braces);
hardlinks never created (in-target link → independent copy, out-of-target link → reject);
modes recorded but never applied as executable; symlinks materialised as **nothing** (recorded
in a manifest, not created on disk, so a later reader cannot be tricked into following one);
extraction goes to `data/raw/extract/.tmp-<uuid>/` then renames into `extract/<sha256>/`;
`data/raw/` is gitignored.

### 6.5.1 `[obfuscation]` — operator decision, initial untuned values, not measured

**Operator decision, initial untuned values, not measured (2026-11-07).** A new config
section `[obfuscation]` carries the family-3 thresholds. These are starting values, not
tuned against a corpus; `eval/` is where they get challenged.

| `obfuscation.` setting | default | meaning |
|---|---|---|
| `min_blob_length` | 200 | minimum base64-like run, in characters |
| `entropy_min_length` | 64 | minimum string-literal length to score, in characters |
| `entropy_threshold_bits` | 4.5 | minimum Shannon entropy per character (bits/char) |
| `min_escapes_per_line` | 20 | minimum `\xHH` / `\uHHHH` escapes on one ADDED line |

`likely_minified` is a reporting flag, never a suppression: a *matching* ADDED line of
length ≥ 500 characters sets `details["likely_minified"] = True`. The 500 is the constant
`LIKELY_MINIFIED_LINE_LENGTH` next to the family-3 rules, not a fifth config key. Every
family-3 rule text names the threshold(s) it reads. The active `[obfuscation]` limits are
carried on `DiffContext` (§4.2) so rules stay pure functions of their context.

## 7. Label policy

Labels are the only non-deterministic input to the dataset, so they get the strictest rules.

1. **No LLM may create a label.** A model may draft a *rationale* for a human reviewer; that
   rationale is stored separately as `rationale_draft`, never in `label`, and it is not a
   label even if the reviewer agrees with it — the reviewer's own judgement is the label.
   Enforced: `label_source` has no `model` value.
2. **Precedence when sources conflict:** `human` > `advisory_db` > `rule_derived`. The
   winner's `label_source`/`label_confidence` are recorded, and the losing claims are kept in
   a `label_conflicts` table (not in `DatasetRecord`) so disputes stay auditable.
3. **`human`** — CSV in `data/labels/human/`, columns
   `ecosystem,package_name,old_version,new_version,label,reviewer,reviewed_at,confidence,note`.
   Committed, with provenance. Default confidence 1.0; a reviewer may lower it.
4. **`advisory_db`** — OpenSSF `malicious-packages`
   (`https://github.com/ossf/malicious-packages`), OSV-format JSON under `advisories/`.
   **License: Apache-2.0** (verified 2026-11-05 from the repository `LICENSE`); redistribution
   requires preserving copyright and license notices. Recorded in
   `data/labels/PROVENANCE.md` before any advisory-sourced export ships. Label is `malicious`
   only when the record's `package_name` matches **and** the version falls inside an
   `affected[].ranges[].events` interval; anything else is `unknown`, never a guess. Default
   confidence 0.9. `label_provenance` = the advisory ID and its commit SHA.
5. **`rule_derived`** — weak, and treated as such: confidence **fixed at 0.3**, `label =
   suspicious` if `rule_score >= 40` else `benign`. `metric_eligible = False` for any
   `rule_derived` record in `val` or `test`. Training on them is allowed (they are a useful
   prior); reporting metrics computed over them is **not** — that would score the model
   against the rules it was trained to imitate. Enforced by a validator in
   `dataset/validate.py` *and* asserted in `eval/`.
6. **`unknown`** — the default. Never silently dropped from the export (it is the honest
   denominator), but excluded from supervised training.
7. Label files are committed data; every file in `data/labels/` needs a matching row in
   `PROVENANCE.md` with source URL, retrieval date, license, and SHA-256 of the file.

## 8. Reproducibility

Every run writes `runs/<run_id>/manifest.json` containing: resolved config (post-defaults,
not the file), `rule_set_version`, `weights_version`, `schema_version`, split salt, all
seeds, toolchain versions (`sys.version`, mypy, ruff), SQLite `user_version`, and the git
SHA of the pkgwatch source when present. `run_id` is `UTC-timestamp + sha256(manifest)[:8]`,
so two identical runs collide — duplicate manifests are a signal that nothing changed, which
is the desired property. Ecosystem version comparisons, split hashing, and any sampling in
`model/` read their seeds from this manifest; nothing reads the clock except `published_at`
capture and `run_id`.

## 9. CLI

`pkgwatch init` (config + db) · `watch add|list|remove` · `ingest <eco> [--package]` ·
`fetch --release eco/name/version` · `check <eco> <name> <v_old> <v_new> [--offline-dir]`
(the offline pair-analysis used by integration tests) · `score --release …` ·
`export-dataset [--split]` · `validate-dataset` · `train|eval|explain` (M5, own entry) ·
`compare npm:<name>@<old> npm:<name>@<new>` (v0.2) · `lock --old OLD_LOCK --new NEW_LOCK`
(§9.1, implemented in `lock/` + `lockfile/`).

### 9.1 `pkgwatch lock` — operator decision, initial untuned values, not measured (2026-11-07)

Goal: a dependency-update PR changed `package-lock.json`; for every package whose version
changed, show what the update changes at install time and in code, in one short report.
`pkgwatch lock --old OLD_LOCK --new NEW_LOCK [options]`, reusing `fetch/`, `sandbox/`,
`diff/`, `rules/` and `score/` unchanged. Static analysis only.

1. New CLI error codes are accepted for this command and are listed in README.
2. Compared pairs: only packages present in **both** lockfiles whose version changed. The old
   version is the one in the old lockfile, **not** chosen by publish date. No version ordering
   is claimed (the §6.4 parser does not exist), so upgrade vs downgrade is not labelled.
3. Packages present only in the new lockfile are analysed against an **empty old tree**
   ("no baseline"), reusing `fetch/`, `sandbox/`, `diff/`, `rules/` and `score/` unchanged
   (L2c, 2026-11-08). They appear in a separate "new packages (no baseline)" section, never
   mixed with changed pairs, with a note that findings are expected to be noisier. **Only
   family 1 (lifecycle) findings count toward `--fail-on` for new packages** — with no
   predecessor, every capability looks added, so other findings are shown but never change
   the exit code (operator decision 2026-11-07, untuned, not measured). A new package with
   an unsupported source is unanalysed and follows `--strict-skips` (decision 11). New
   packages count toward `max_pairs`; `--no-new` skips the analysis entirely, removes them
   from the limit, and the header then says new packages were NOT analysed. Removed packages
   are listed by name only. Family 4 findings of a new package (`DEPENDENCY_ADDED`,
   `REPOSITORY_URL_CHANGED`) are not meaningful as "changes" against an empty tree, so
   (L2d) they are moved out of the findings list and out of the score into one
   informational line per package (`metadata (informational)`) plus counts in JSON — never
   silent. They never counted toward `--fail-on` here anyway (only family 1 does). Family
   1–3 findings of new packages stay listed and scored; changed pairs keep family 4 in
   findings and score, unchanged.
4. Lockfile support: `lockfileVersion` 2 and 3 (the `packages` map). Version 1 and anything
   else fails with `LOCKFILE_UNSUPPORTED_VERSION`. The same name at several `node_modules`
   paths is keyed by `(name, version)` sets, not by path.
5. Only entries whose `resolved` is https on the registry host used by `fetch/npm.py` are
   analysed. Entries with git, file, link, http or other-host sources are listed under
   "skipped (unsupported source)" with a reason code. Never silently dropped.
6. Defaults (`config.py`, `[lock]` section): `max_pairs=300`, `concurrency=4`,
   `max_lockfile_bytes=20 MiB`, `max_json_depth=64`. Over `max_pairs`: exit 2 with
   `TOO_MANY_PAIRS`, never silently truncate; the user can raise `--max-pairs`.
7. Exit codes: 0 = no unignored finding at or above `--fail-on` (default medium); 1 = at least
   one such finding; 2 = any error or incomplete analysis (`analysis_incomplete`,
   fetch/digest/sandbox failure for ANY pair, unsupported lockfile, limits). Exit 2 wins over
   1. A failed pair never exits 0.
8. The lockfile is untrusted input (it can come from a fork PR). Every name, version and URL is
   validated with the existing validators before use. A lockfile string is never used as a
   filesystem path. Size and depth limits are enforced before parsing.
9. Download cache (L2b, 2026-11-08): tarballs are cached keyed by the registry digest the bytes
   were verified against (SRI sha512, else shasum sha1), in the OS user cache directory by
   default — never inside the repository. Every read re-verifies the digest; a corrupt entry is
   deleted and fetched again. `--no-cache` disables reads and writes for one run; an explicit
   `[lock].cache_dir` overrides the location.
10. Retry (L2b): only 429, 5xx and timeouts are retried, with capped exponential backoff
    (`[lock].max_attempts`, `retry_base_delay_seconds`, `retry_max_delay_seconds`). A
    `Retry-After` delay is honoured, bounded by `retry_max_delay_seconds`. Every request is
    preceded by the polite `[lock].request_delay_seconds`. Other failures and other statuses are
    never retried.
11. Unanalysed policy (L2b, extended by L2c): a changed pair or brand-new package that cannot
    be analysed is NOT clean. This covers an unsupported source on either side (git, file,
    link, http, other host, missing resolved), `MULTIPLE_VERSIONS`, and — for new packages —
    an unsupported source in the new lockfile. The text header counts them, a warning line
    states that the result is incomplete, and JSON adds `unanalysed` and `unanalysed_packages`.
    The default exit code is unchanged; `--strict-skips` makes any unanalysed package exit 2.
12. Duplicate JSON keys (L2b): an object that repeats a key is rejected with
    `LOCKFILE_DUPLICATE_KEY` instead of silently keeping the last value.
13. Distinct lockfile read errors (L2c, 2026-11-08): `LOCKFILE_NOT_FOUND`,
    `LOCKFILE_PERMISSION_DENIED`, `LOCKFILE_NOT_UTF8` (a UTF-8 BOM is accepted silently),
    `LOCKFILE_INVALID_JSON`, with `LOCKFILE_READ_FAILED` kept only as the fallback for other
    OS errors. The same codes apply to `--old` and `--new`; the error names the failing file
    by its argument (`LOCKFILE_NOT_FOUND (--old)`), never by path or exception message, and
    JSON adds `"argument": "--old"` / `"--new"`. All codes are listed in README.
14. `--plan` (L2d): print the plan only — changed pairs, unanalysed, new packages, removed
    packages and skipped entries, with reason codes, in text or as JSON section keys — with
    no network access and no analysis. Exit `0`, or `2` on a lockfile error, on
    `TOO_MANY_PAIRS`, or on `--strict-skips` with unanalysed entries.
15. `--config` (L3): the `[lock]` section may carry `fail_on`, `max_pairs` and ignored
    rules. Every config ignore is an object `{rule, reason}` with a **mandatory non-empty
    reason**; an ignore without one fails `CONFIG_INVALID`, a missing file fails
    `CONFIG_NOT_FOUND`. CLI flags win over the file. CLI `--ignore` and config ignores are
    merged; ignored findings are counted and printed, never silent
    (`ignored: RULE (n findings) — reason`; JSON carries `reason` or `null`). An unknown
    rule in either list exits `2` with `UNKNOWN_RULE_ID`.
16. Baseline (L3): `--update-baseline FILE --baseline-reason TEXT` writes the run's
    findings (after `--ignore`, before `--baseline` hiding) as entries
    `{package, rule_id, path, evidence_sha256, reason, date}` in a versioned JSON file,
    and does not change the run's exit code. `--update-baseline` without a reason exits
    `2` with `BASELINE_REASON_REQUIRED`. `--baseline FILE` hides a finding **only when**
    the tuple `(package name, rule_id, path, SHA-256 of the evidence text in UTF-8)`
    equals an entry's `(package, rule_id, path, evidence_sha256)` — the version is
    never part of the match, `path` compares as null for package-level findings, and
    changed evidence therefore reappears. Hidden findings are removed from the report,
    the score and `--fail-on`, and are counted and printed (`baselined: N findings`
    in text, `"baselined": N` in JSON). Load errors give `BASELINE_NOT_FOUND` /
    `BASELINE_INVALID`, a failed write gives `BASELINE_WRITE_FAILED`, and baseline flags
    with `--plan` give `BASELINE_WITH_PLAN`.
17. `--markdown` (L3): render the lock report as Markdown — one `<details>` collapsible
    block per section, evidence capped at 200 characters, the same disclaimer, and every
    package-controlled string escaped for Markdown and HTML. `--markdown` and `--json`
    together exit `2` with `OUTPUT_OPTIONS_CONFLICT`.
18. Baseline entries for lifecycle findings (L4, operator decision 2026-11-07, untuned,
    not measured): family 1 (`NPM_INSTALL_SCRIPT_ADDED`,
    `NPM_SCRIPT_INJECTION_FROM_METADATA`) entries are **not honoured by default**.
    The evidence of a lifecycle finding is only the manifest line, so a baseline
    there could stay hidden while the script that line points at changes underneath.
    `--baseline-allow-lifecycle` opts in to honouring them. Writing a baseline
    (`--update-baseline`) is unaffected.

Implementation status (2026-11-08): decisions 1–18 are implemented. `lockfile/parser.py` reads
and validates one lockfile, `lockfile/plan.py` produces the deterministic plan including
unanalysed packages, `lock/run.py` analyses each changed pair and each brand-new package
(against an empty tree) through the unchanged `fetch/`, `sandbox/`, `diff/`, `rules/` and
`score/`, `fetch/cache.py` and `fetch/retry.py` provide the cache and backoff, `lock/baseline.py`
owns the baseline format and match rule, `lock/report.py` shapes the report (its own JSON
`schema_version` 4, with per-new-package `analysis`, `new_packages_analysed`, family-4
`informational` counts, `baselined` count, ignore reasons, and the `--plan` and `--markdown`
documents), `cli.py` exposes `lock` including `--no-new`, `--plan`, `--config`,
`--baseline`/`--update-baseline`/`--baseline-allow-lifecycle` and `--markdown`, and
`action.yml` plus `examples/github-workflow.yml` describe the GitHub Action (untested
on GitHub; config, baseline and the old lockfile are read from the base branch).
Still TODO: any version ordering (§6.4), so multi-version names stay unpaired.

## 10. Open assumptions (not silently guessed)

| # | Assumption | Status | Action |
|---|---|---|---|
| A1 | M1 needs persistence for the watchlist and the ingest cursor, but `store/` is scheduled for M2 | Decision requested | Recommendation: pull forward a **minimal** `store/` (tables `releases`, `watchlist`, `runs` only) in M1; M2 adds `findings`/`scores`/`file_changes`. The alternative — JSON files in M1 — becomes throwaway work. |
| A2 | npm change-stream endpoint for global ingestion | 404 today | Out of scope for M1; TODO confirm a supported feed in M4 |
| A3 | crates.io download 303 target, PyPI per-version JSON | Not probed | TODO verify before M4 fetch implementation |
| A4 | PyPI packages without an sdist (wheel-only) | Certain to exist | sdist preferred, wheel fallback; a release with no analyzable artifact gets `analysis_incomplete=True` and is excluded from export — no invented findings |
| A5 | npm `/-/rss?<name>` scoping | Response does not prove scoping | Unused; watchlist polling instead |
| A6 | Severity→base-weight numbers in §5 | Design judgement, not empirically tuned | `w1`; weights live in `config.py`, versioned, and `eval/` is where they get challenged |
| A7 | `max_*` default limits in §6.5 | Chosen for typical packages | Revisit with real registry corpus stats in M4; all are config, none are literals |
| A8 | `versions[v].gpt` in §3 | Looks like a typo | TODO(v0.2): ignored; confirm the real field against a live document before naming it |
| A9 | `maintainers` as a per-version diff | Not supportable | TODO(v0.2): `MAINTAINER_ADDED` deferred; package-level maintainers is a current-state snapshot |
| A10 | `[obfuscation]` defaults in §6.5.1 and v0.2 severities in §4.5.1 | Operator decision, initial untuned values, not measured | TODO: challenge in `eval/`; never present them as measured detection quality |
| A11 | Doc-level `repository.url`, `_npmUser`, `deprecated`, `devDependencies` as family-4 rules | Not implemented | TODO(v0.2): no rule may be invented for them without an operator decision |
