# PyPI support — implementation plan (2026-11-09)

**Spec:** `docs/superpowers/specs/2026-11-08-pypi-design.md` (approved, commit 2630f6f)

**Goal:** `pkgwatch compare pypi:<name>@<old> pypi:<name>@<new>` end-to-end offline:
fetch via the PyPI JSON API, extract sdist/wheel, diff, run 6 PyPI-specific rules,
score with the unchanged `w1` table, emit text/JSON/Markdown/SARIF. Plus the SPEC
§6.4 version parser (M1) and its first consumer: ordered multi-version lockfile
pairing (M2).

**Architecture:** new modules `src/pkgwatch/version.py`, `src/pkgwatch/fetch/pypi.py`,
`src/pkgwatch/diff/pypi_metadata.py`, `src/pkgwatch/rules/family1_pypi.py`,
`src/pkgwatch/rules/family2_pypi.py`, `src/pkgwatch/rules/family4_pypi.py`;
extended: `fetch/cache.py` (sha256 + blake2b_256), `fetch/npm.py` (validate_version
delegation + ARTIFACT_UNAVAILABLE code), `lockfile/plan.py` (zip pairing),
`rules/scan.py` (suffix-parameterised capability scan), `cli.py` (`pypi:` route),
`tests/support/pypi_registry.py` (offline double). The npm compare path and all 12
npm rules stay byte-identical in behaviour.

**Tech stack:** Python 3.12, uv, pydantic v2, hypothesis (property tests), pytest,
mypy --strict, ruff (line-length 100). TDD throughout: write the failing test,
watch it fail, implement, watch it pass.

## Global constraints (verbatim from spec §1 / MASTER_PROMPT)

- Static analysis only. Package content is never executed, imported, installed or
  built — including `setup.py`, which is read as text only. Never run npm, npx,
  node, pip or package scripts, including in tests.
- No live registry calls in tests; everything is served from an offline double.
- Errors print stable codes, never exception messages; package-controlled strings
  are untrusted in every output format.
- Rule logic, severities and weights of the existing 12 npm rules do not change;
  the `compare` npm path and score semantics do not change either.
- No third-party dependencies (the version parser is own code — SPEC §6.4).
- Do not touch `eval/measure_m2/` or `data/`.
- Hard invariants to keep green every phase: npm installer pair = 4 findings,
  score 94; benign pair = 0; full suite 542+ passed, 1 skipped (Windows symlink).
- Do not push to GitHub unless the user explicitly asks.

## Resolved spec ambiguities

1. **§7 vs §6 gating:** §7 says "no PyPI finding is experimental in v1" while §6
   registers `PYPI_DEPENDENCY_ADDED` in the metadata family. Resolution: the
   runner's family gating (`EXPERIMENTAL_FAMILIES = {OBFUSCATION, METADATA}`)
   stays ecosystem-agnostic and unchanged — `PYPI_DEPENDENCY_ADDED` is off by
   default and surfaces under `--experimental`, exactly like npm's
   `DEPENDENCY_ADDED`. §7's sentence is read as "no *new* gating concept".
2. **compare JSON for PyPI:** `schema_version` stays 2; `ecosystem` reads `"pypi"`;
   `package_json_changes` renders the empty skeleton (spec §5, polish deferred).
3. **Artifact candidate failure:** first sdist by filename, else first wheel by
   filename; if none exists → `ARTIFACT_UNAVAILABLE`; if the chosen entry's URL or
   digest is bad → `TARBALL_URL_INVALID` / `DIGEST_MISSING` / `DIGEST_UNSUPPORTED`
   (no silent fall-through to the next candidate; determinism).
4. **Name mismatch check:** old/new specs must agree on the PEP 503 normalized
   name and the ecosystem; otherwise `PACKAGE_MISMATCH`.

## File structure map

| File | Action |
|---|---|
| `src/pkgwatch/version.py` | new — parse/compare, semver + PEP 440 |
| `tests/unit/version/test_parse.py`, `test_compare.py`, `test_properties.py` | new |
| `src/pkgwatch/lockfile/plan.py` | edit — multi-version zip pairing |
| `tests/unit/lockfile/test_plan.py` | edit — pairing tests |
| `src/pkgwatch/fetch/npm.py` | edit — `ARTIFACT_UNAVAILABLE` code, `validate_version` delegation |
| `src/pkgwatch/fetch/cache.py` | edit — sha256 + blake2b_256 in `digest_matches` |
| `src/pkgwatch/fetch/pypi.py` | new — doc URL, host allowlist, artifact selection, fetch_pair_pypi |
| `tests/support/pypi_registry.py` | new — `PyPIRegistry` offline double |
| `tests/unit/fetch/test_pypi.py` | new |
| `src/pkgwatch/diff/pypi_metadata.py` | new — PKG-INFO/METADATA path resolution + parse |
| `src/pkgwatch/rules/scan.py` | edit — `suffixes` parameter on capability scan |
| `src/pkgwatch/rules/family1_pypi.py` | new — `PYPI_INSTALL_HOOK_ADDED` |
| `src/pkgwatch/rules/family2_pypi.py` | new — 4 capability rules |
| `src/pkgwatch/rules/family4_pypi.py` | new — `PYPI_DEPENDENCY_ADDED` |
| `src/pkgwatch/rules/__init__.py` | edit — import the three new modules |
| `tests/fixtures/pypi-packages/<case>/{old,new}/` | new — committed synthetic trees |
| `tests/unit/rules/test_pypi_rules.py` | new — positive/negative per rule |
| `src/pkgwatch/cli.py` | edit — `pypi:` route in `_compare` |
| `tests/integration/test_pypi_compare_cli.py` | new — end-to-end offline |
| `README.md`, `SPEC.md` | edit — M5 |
| `docs/GATES-pypi.txt` | new — M5 raw gate log |

---

## M1 — version parser (`src/pkgwatch/version.py`)

### Task 1.1 — RED: parse/compare unit tests
`tests/unit/version/test_parse.py` + `test_compare.py` (create `tests/unit/version/__init__.py`):
- npm: `parse(Ecosystem.NPM, "1.2.3")` ok; `"1.2.3-alpha.1"` ok; `"1.2.3+build.5"`
  ok (build accepted, ignored for precedence); garbage (`"1.2"`, `"v1.2.3"`, `"1.2.3-"`,
  `"latest"`, `""`) → `UnsupportedVersion`.
- pypi: `"1.0"`, `"1.0.post1"`, `"1.0a1"`, `"1.0.dev3"`, `"2!1.0"`, `"1.0+local.1"` ok;
  `"1.0+"`, `"foo"`, `""` → `UnsupportedVersion`.
- compare npm: `1.0.0 < 1.0.1 < 1.1.0 < 2.0.0`; `1.0.0-alpha < 1.0.0-alpha.1 <
  1.0.0-beta < 1.0.0`; `1.0.0+build == 1.0.0` (precedence 0); numeric identifiers
  compare numerically (`1.0.0-alpha.2 < 1.0.0-alpha.10`).
- compare pypi: `1.0.dev1 < 1.0a1 < 1.0b2 < 1.0rc1 < 1.0 < 1.0.post1`;
  `1.0a1 < 1.0a2`; epochs dominate (`2!1.0 > 1.9`); release zero-normalization
  (`1.0.0` precedence-equals `1.0`); local sorts after no-local (`1.0 < 1.0+local`).
- cross-ecosystem `compare` → `UnsupportedVersion`.

### Task 1.2 — RED: hypothesis property tests
`tests/unit/version/test_properties.py`: strategies generating valid versions per
ecosystem (build from components, not from text fuzzing); properties:
reflexivity `compare(v, v) == 0`; antisymmetry `compare(a, b) == -compare(b, a)`;
transitivity over triples; sort stability (sorting twice gives the same result);
round-trip `parse(eco, parse(eco, text).canonical).canonical == canonical`;
precedence-equal tie-break by text is deterministic.

### Task 1.3 — GREEN: implement
`src/pkgwatch/version.py`:
```python
class UnsupportedVersion(Exception): ...

@dataclass(frozen=True)
class ParsedVersion:
    ecosystem: Ecosystem
    text: str
    canonical: str
    key: tuple[Any, ...]   # total-order sort key within the ecosystem

def parse(ecosystem: Ecosystem, text: str) -> ParsedVersion: ...
def compare(a: ParsedVersion, b: ParsedVersion) -> int: ...
```
- npm key: `(major, minor, patch, prerelease_key)`; prerelease_key `()` sorts after
  any prerelease; identifiers: int < str, ints compare numerically, fewer identifiers
  sorts first when all-equal prefix (semver §11).
- PEP 440 key: `(epoch, release_tuple_zeros_stripped, pre_key, post_key, dev_key,
  local_key)` following PEP 440's ordering rules (dev before pre before release
  before post; `-inf`/`inf` sentinels as in the reference `_cmpkey`).
- canonical: for npm, canonical keeps the text verbatim (round-trip trivial, no
  information loss — build metadata stays visible but is ignored by `compare`);
  for PEP 440, canonical is the normalized form (lowercase, zeros stripped,
  `alpha`→`a`, `-alpha`→`a` etc. per PEP 440 normalization rules).
- `CRATES` → `UnsupportedVersion` (not this milestone).

### Task 1.4 — verify
`uv run pytest tests/unit/version -q` green; full suite green; ruff/mypy clean.

## M2 — lockfile multi-version zip pairing

### Task 2.1 — RED
`tests/unit/lockfile/test_plan.py` additions:
- Balanced: old `{a@1.0.0, a@2.0.0}` → new `{a@1.1.0, a@2.1.0}`: changed sets
  `{1.0.0, 2.0.0}` / `{1.1.0, 2.1.0}` pair index-wise after version sort →
  pairs `(1.0.0→1.1.0)`, `(2.0.0→2.1.0)`; no `MULTIPLE_VERSIONS` skip.
- Balanced with unordered input: old `{2.0.0, 1.0.0}` still pairs lowest→lowest.
- Unbalanced: old `{1.0.0}` → new `{1.1.0, 2.0.0}` keeps `MULTIPLE_VERSIONS`
  unanalysed + skips (existing behaviour).
- Unparseable version in a multi-version name → keep `MULTIPLE_VERSIONS` (safe fallback).
- Single-version names: existing tests unchanged (byte-identical behaviour).

### Task 2.2 — GREEN
`src/pkgwatch/lockfile/plan.py`: replace the `len(old_versions) > 1 or
len(new_versions) > 1` block: when both changed sets are non-empty and equal in
size, try `version.parse(Ecosystem.NPM, ...)` on every member; on success sort both
and emit `ChangedPair`s index-wise (each still passes the `_source_reason` checks —
reuse the single-pair reason logic per pair); on `UnsupportedVersion` or unequal
sizes keep the current `MULTIPLE_VERSIONS` path. Update the module docstring
(SPEC §6.4 order now exists).

### Task 2.3 — verify
Full suite green (lock invariants unchanged), gates.

## M3 — fetch layer + CLI route

### Task 3.1 — RED: cache digest tests
`tests/unit/fetch/test_cache.py` additions: `digest_matches` true/false for
`sha256` and `blake2b_256` algorithms; `DownloadCache.put/get` round-trip with a
sha256 `ExpectedDigest`; corrupt-entry deletion still works.

### Task 3.2 — GREEN: cache.py
`digest_matches`: add `sha256` → `hashlib.sha256`, `blake2b_256` →
`hashlib.blake2b(data, digest_size=32)`, keep sha512 branch, sha1 as the legacy
fallback. `path_for` unchanged (extension is cosmetic; extraction sniffs magic bytes).

### Task 3.3 — RED: pypi fetch unit tests
`tests/support/pypi_registry.py` first (double, no test yet): `PyPIRegistry`
dataclass mirroring `FakeRegistry` semantics — serves
`https://pypi.org/pypi/{normalized}/json` document
(`{"info": {"name": ...}, "releases": {v: [file entries]}}`), artifact bytes at
`https://files.pythonhosted.org/packages/aa/bb/{filename}`, `digests` with real
sha256 (+ blake2b_256 helper), request logging, `doc_override`, `redirects`,
`set_new`. Helpers: `sdist_bytes(tmp_path, name, version, files)` (tar.gz rooted at
`<norm>-<version>/`), `wheel_bytes(...)` (zip with `<norm>-<version>.dist-info/METADATA`
+ module files), reusing `tests/support/archives.make_tar/make_zip`.

`tests/unit/fetch/test_pypi.py`:
- `build_doc_url("Foo_Bar")` → `https://pypi.org/pypi/foo-bar/json` (PEP 503).
- `validate_name_pypi`: accepts `foo.bar`, `Foo_Bar`, `f1`; rejects `""`, `..`,
  `foo/bar`, `-foo`, `foo-`, control chars, over-length.
- `parse_spec("pypi:foo@1.0")` → `("foo", "1.0")`; `"npm:foo@1.0"` → INVALID_SPEC;
  `"pypi:foo"` → INVALID_SPEC; `"pypi:foo@bogus"` → INVALID_VERSION (via version.parse).
- `is_pypi_url`: https on `pypi.org`/`files.pythonhosted.org` ok; `http://`, other
  host, port 8443, userinfo → False.
- artifact selection: sdist preferred over wheel; wheel-only ok; neither →
  `ARTIFACT_UNAVAILABLE`; unknown version → `VERSION_NOT_FOUND`; bad URL →
  `TARBALL_URL_INVALID`; missing digests → `DIGEST_MISSING`; wrong sha256 →
  `DIGEST_MISMATCH`; blake2b_256 fallback works.
- `fetch_pair_pypi` writes artifacts whose filenames keep the original suffix
  (`.tar.gz` / `.whl`), returns `FetchPair` with `published_at` from
  `upload_time_iso_8601`, redirect off-host → `REDIRECT_REJECTED`.

### Task 3.4 — GREEN: fetch/npm.py + fetch/pypi.py
- `fetch/npm.py`: add `ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"` to
  `FetchErrorCode`; rewrite `validate_version` to delegate:
  `version.parse(Ecosystem.NPM, text)` → `UnsupportedVersion` maps to
  `FetchError(INVALID_VERSION)`; keep the length cap check; drop the §6.4 TODO.
- `fetch/pypi.py` (new): constants `PYPI_DOC_URL_TEMPLATE`,
  `ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})`;
  `normalize_name`, `validate_name_pypi`, `validate_version_pypi`, `parse_spec`,
  `build_doc_url`, `is_pypi_url`, `expected_digest_pypi(entry)`,
  `_select_artifact(files)` (sdist-by-filename first, else wheel-by-filename, else
  ARTIFACT_UNAVAILABLE), `_document_releases`, `_fetch_bytes_pypi` (same loop shape
  as npm's, PyPI allowlist), `fetch_release_pypi`, `fetch_pair_pypi` returning the
  npm `FetchPair`/`VersionArtifact` types (metadata = `{}` — PyPI per-version
  metadata comes from the tree, M4).
- `cli.py`: `_compare` routes by prefix — new helper
  `_route(text) -> tuple[Ecosystem, str, str]`: `"pypi:"` → pypi.parse_spec +
  `Ecosystem.PYPI`, else npm.parse_spec + `Ecosystem.NPM`; mismatch check compares
  `(ecosystem, normalized name)`; `fetch_pair` call branches on ecosystem;
  `build_diff_context(ecosystem=eco, ...)`. npm behaviour byte-identical.

### Task 3.5 — RED→GREEN: CLI integration (compare pypi end-to-end)
`tests/integration/test_pypi_compare_cli.py`: sdist-only pair with one added
`os.system(` line → findings + nonzero score, exit 1 under default fail-on;
wheel-only pair; JSON has `"ecosystem": "pypi"`, `"schema_version": 2`;
`--markdown`/`--sarif` render ecosystem pypi; digest mismatch → `DIGEST_MISMATCH`
exit 2; unknown version → `VERSION_NOT_FOUND`; off-host redirect →
`REDIRECT_REJECTED`; no network beyond the double (all served by `PyPIRegistry`).
Rules don't exist yet in this task — score may be 0 with no findings; the assertions
here are transport/shape/error-code only. Rule firing lands in M4.

### Task 3.6 — verify
Full suite green; npm invariants (installer 94, benign 0) untouched; gates.

## M4 — ecosystem-aware metadata + PyPI rules

### Task 4.1 — RED: pypi_metadata unit tests
`tests/unit/diff/test_pypi_metadata.py`: build a `DiffContext` via
`tests/support/context.py` helpers (or `build_diff_context` over synthetic
`ExtractionResult`s): sdist side resolves `<name>-<version>/PKG-INFO`; wheel side
resolves `<name>-<version>.dist-info/METADATA`; deterministic pick when several
candidates (sorted paths, `PKG-INFO` before `METADATA` at equal sort position);
`parse_metadata` extracts `Name`, `Version`, and `Requires-Dist` lines into
`{"name": "specifier-or-empty"}` (PEP 508 name = leading
`[A-Za-z0-9][A-Za-z0-9._-]*`, extras/markers ignored); absent file → `None`,
never raises; hostile content (huge line, control chars) bounded.

### Task 4.2 — GREEN: diff/pypi_metadata.py
`root_metadata_path(ctx, side) -> str | None`, `metadata_text(ctx, side) -> str | None`
(mirrors `manifest._text`'s UNCHANGED-view fallback), `parse_metadata(text) ->
PypiMetadata` frozen dataclass `(name, version, dependencies)`.

### Task 4.3 — RED: scan suffixes + rule tests
- `tests/unit/rules/test_pypi_rules.py`: committed fixture trees under
  `tests/fixtures/pypi-packages/` (synthetic only): `benign` (module text change),
  `installer` (setup.py added `setup(` cmdclass hook), `shell` (added
  `os.system(...)`), `eval` (added `eval(`), `net` (added `import requests`),
  `env` (added `os.environ`), `deps` (PKG-INFO/METADATA gains `Requires-Dist: evil`),
  each with `old/`+`new/`; positive test per rule + negative (old tree already had
  the capability → silent; comment-only mention behaviour per pattern).
- Runner gating test: `PYPI_DEPENDENCY_ADDED` silent without `experimental=True`,
  fires with it (families unchanged).

### Task 4.4 — GREEN: rules
- `rules/scan.py`: add `suffixes: Sequence[str] = JS_SUFFIXES` parameter to
  `text_views` callers — `capability_findings(ctx, *, ..., suffixes=JS_SUFFIXES)`
  and `old_tree_has_capability(ctx, item, suffixes=JS_SUFFIXES)`; npm call sites
  unchanged (default).
- `PYPI_SUFFIXES = (".py",)`; `PYPI_BUILD_FILES = ("setup.py", "pyproject.toml",
  "setup.cfg")` at depth ≤ 2.
- `rules/family1_pypi.py`: `PYPI_INSTALL_HOOK_ADDED` (lifecycle, high) — added lines
  in build files matching `setup\s*\(`, `setuptools\.setup\s*\(`,
  `^\s*\[project\.scripts\]`, `^\s*\[project\.entry-points`; one finding per line,
  old-tree check across both sides' build-file views.
- `rules/family2_pypi.py`: four `scan.capability_findings` rules with `.py` suffixes:
  `PYPI_SHELL_EXEC_ADDED` (high: `os.system\s*\(`, `os.popen`, `subprocess\.`),
  `PYPI_EVAL_EXEC_ADDED` (high: `(?<![A-Za-z0-9_.$])eval\s*\(`,
  `(?<![A-Za-z0-9_.])exec\s*\(`, `__import__\s*\(`),
  `PYPI_NET_ACCESS_ADDED` (medium: `import socket|urllib|requests|http.client`,
  `from (socket|urllib|requests|http\.client|http)`, `urllib.request`),
  `PYPI_ENV_ENUM_ADDED` (low: `os\.environ`, `os\.getenv\s*\(`, `(?<![\w.])getenv\s*\(`).
  Docstrings state exact patterns + blind spots (family-2 style).
- `rules/family4_pypi.py`: `PYPI_DEPENDENCY_ADDED` (metadata, low) — reads
  `pypi_metadata` for both sides; one package-level finding (path=None) per added
  dependency name; registry-document metadata never consulted.
- `rules/__init__.py`: import the three modules after the npm families
  (registration order = npm 12 then PyPI 6).

### Task 4.5 — verify: invariants + integration
- npm `rule_set_version` changes (expected — new rules registered); no npm rule
  changes; installer pair still 4 findings / 94 (PyPI rules select out by ecosystem).
- Extend `tests/integration/test_pypi_compare_cli.py`: installer sdist pair fires
  `PYPI_INSTALL_HOOK_ADDED` + capability rules; `--experimental` adds
  `PYPI_DEPENDENCY_ADDED`; `--ignore` works; explain shows `(experimental)` marker
  on the metadata rule; `--json` findings carry `"ecosystem": "pypi"`.
- Full suite, gates.

## M5 — docs, SPEC, gates, smoke

### Task 5.1 — README
Replace "PyPI support (roadmap)" with actual status: compare supported (sdist +
wheel), 6 rules (one experimental-gated), lock not supported yet; update "What it
does not do" ("npm only" → "npm and PyPI, exact versions only"); usage example
`pkgwatch compare pypi:requests@2.31.0 pypi:requests@2.32.0`; flag tables unchanged.

### Task 5.2 — SPEC.md
§3: PyPI endpoint table (document endpoint, allowed hosts, digest preference
sha256 → blake2b_256). §4.5.2: PyPI rule table (6 rules, patterns, severities).
§6.4: status "implemented" (version.py + plan pairing). §9.1 decision log: entry
for the PyPI JSON API endpoint decision + the §7-gating resolution noted in this
plan. Error code table gains `ARTIFACT_UNAVAILABLE`.

### Task 5.3 — gates + smoke + report
`uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy --strict src/`,
`uv run pytest -v` (record every skip reason) → `docs/GATES-pypi.txt` with
`C:\Users\<user>` masked. cmd.exe smoke (no live network): the npm installer/benign
example pairs as today, plus `pypi:` spec-parse error paths that never reach the
network (`pkgwatch compare pypi:bad pypi:bad@1.0.0` → INVALID_SPEC;
`pkgwatch compare npm:x@1.0.0 pypi:x@1.0.0` → PACKAGE_MISMATCH).
Commit per phase (M1..M5 separately). Push only when the user asks.

## Phase exit criteria (spec §11)

| Phase | Exit |
|---|---|
| M1 | hypothesis suite green both ecosystems; garbage rejected |
| M2 | balanced multi-version names pair ordered; singles unchanged; unbalanced keeps MULTIPLE_VERSIONS |
| M3 | `compare pypi:` end-to-end offline; stable codes; validate_version delegated |
| M4 | 6 PyPI rules fire; gating/ignore paths respected; npm invariants unchanged |
| M5 | docs + SPEC + gatelog + smoke + report |
