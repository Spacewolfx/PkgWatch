# PyPI support — design (2026-11-08)

Status: **approved design**. Scope per operator decisions recorded in the milestone
request: **compare-first**, **PyPI JSON API** document endpoint, **sdist + wheel
together**, and **PyPI-specific new rules** (npm rules are never registered for
the `pypi` ecosystem; the two ecosystems' rule sets are disjoint).

## 1. Goal and boundary

Add `pkgwatch compare pypi:<name>@<old> pypi:<name>@<new>` so a dependency-update
diff across two PyPI releases produces the same report families the npm path produces:
findings, score, boosts, changed files, JSON/Markdown/SARIF output, `--fail-on`
gating and the same exit-code contract. No other ecosystem enters this work.

Hard constraints carried over from all milestone work so far:

- Static analysis only. Package content is never executed, imported, installed or
  built — including `setup.py`, which is read as text only.
- Lockfiles are untrusted input; size and depth limits enforced before parsing.
- No live registry calls in tests; everything is served from an offline double.
- Errors print stable codes, never exception messages; package-controlled strings
  are untrusted in every output format.
- Rule logic, severities and weights of the existing 12 npm rules do not change; the
  `compare` npm path and score semantics do not change either.

Explicitly out of scope for this design:

- The **lock** command for PyPI (`requirements.txt`, `uv.lock`, Poetry lockfiles,
  `pip freeze`; no single standard exists, so it comes as a later milestone).
- Wheel/egg binary analysis beyond static reading (binary payloads stay invisible).
- PyPI obfuscation and metadata rule families 3/4 analogs (the npm versions stay
  experimental and off by default; PyPI gains its own experimental decisions later).

## 2. Architecture

```
                ┌──────────────────── compare CLI (npm: / pypi:)
                │                            │
                │                ┌ pip route ──► maybe empty path
                ▼                ▼
   ┌─────────────────fetch────────────────────────────┐
   │  fetch/npm.py (existing, unchanged)              │
   │  fetch/pypi.py (new: document + artifact fetch)  │
   │  fetch/cache.py (sha256 + blake2b_256 added)     │
   │  fetch/retry.py, UrllibClient (unchanged)        │
   └──────────────┬─────────────────────────┬─────────┘
                  ▼                         ▼
   ┌───────────────────diff───────────────────────────\
   │  build_diff_context accepts Ecosystem;          │
   │  root manifest readers become ecosystem-aware     │
   │  (npm: package/package.json; pypi: PKG-INFO or    │
   │   *.dist-info/METADATA at depth ≤ 1 tree root)    │
   └──────────────┬────────────────────────────────────┘
                  ▼
   ┌────rules─────────────────────────────────────────┐
   │  registry DEFAULT gains pypi registrations      │
   │  PYPI_* rules: lifecycle + capability families   │
   └──────────────┬────────────────────────────────────┘
                  ▼
        score (w1, unchanged) → format_text / JSON / SARIF / markdown
```

The lock pipeline (`lock/`, `lockfile/`) is untouched — PyPI tools enter through
`compare` only.

## 3. The version parser (PEC §6.4 first half, new module)

The `§6.4 version parser for multi-version pairing of npm lockfiles` is still
**unimplemented** and is a dependency of this milestone because PyPI's
ordering is part of §6.4's three-ecosystem design (npm/crates semver + PyPI
PEP 440). Delivered as its own phase (M1) and consumed by both M3 (PyPI) and
a later lock pairing milestone.

Write `src/pkgwatch/version.py`:

```python
class UnsupportedVersion(Exception): ...
@dataclass(frozen=True)
class ParsedVersion:  # ecosystem, text, parsed fields, canonical
    ...
def parse(ecosystem: Ecosystem, text: str) -> ParsedVersion:
    """Total order over one ecosystem's versions.

    Accepts npm/crates semver (2.0.0; build metadata accepted and ignored — a
    partial order) and PyPI PEP 440 (epochs, pre/post/dev, local versions kept
    in ordering; release normalization per PEP 440).
    Raises UnsupportedVersion on garbage or an unknown ecosystem.
    """
def compare(a: ParsedVersion, b: ParsedVersion) -> int:
    """Precedence comparison. Dataclass ``==`` is structural; precedence equality
    through ``compare`` is what sorting ties on."""
```

Hypothesis property tests per SPEC §6.4: reflexivity/antisymmetry/transitivity
of `compare`, sort stability, `parse → canonical → parse` round-trip (canonical
text), `compare(v, v) == 0`, plus deterministic tie-break by text for equal
precedence.

Consumers in this milestone:
- `validate_version` (npm.py) delegates to `parse(Ecosystem.NPM, ...)` and maps
  `UnsupportedVersion → FetchError(INVALID_VERSION)`; same acceptance set, one
  source of truth.
- `lockfile/plan.py` multi-version pairing (M2; planned here to honor the
  §6.4 purpose): for each name with several versions per side, sort both changed
  sets by parsed version and pair index-wise; unbalanced sets keep
  `MULTIPLE_VERSIONS` unanalysed + skipped per version. Single-version names
  behave exactly as before.
- PyPI document keying (`releases[v]` names come from raw version strings;
  the parser orders them for display but keys stay exact strings).

## 4. Fetch layer (M3)

`src/pkgwatch/fetch/pypi.py` mirrors `fetch/npm.py` in shape, not by copy-paste of
the generic machinery:

- `build_doc_url(name) -> "https://pypi.org/pypi/{name}/json"` — the ONLY URL
  constructed. The name goes through PEP 503 normalization
  (`re.sub(r"[-_.]+", "-", name).lower()`) before URL building, so `Foo_Bar`,
  `foo-bar` and `foo.bar` name the same project; the original spelling is
  reported everywhere else.
- `parse_spec(text)` accepts only the `pypi:` prefix; anything else stays an
  `INVALID_SPEC`.
- `validate_name_pypi(name)` — PEP 503 shape; reject `..`, path separators,
  leading/trailing hyphens, control characters; cap length. Rejects anything
  that an unquoted URL interpolation could bend.
- `_document_versions` fetch loop identical in shape to npm's (User-Agent,
  timeout, `max_metadata_bytes`, redirects) but with a **PyPI host allowlist**:
  `pypi.org` and `files.pythonhosted.org`, HTTPS only, no userinfo, no
  arbitrary ports → `REDIRECT_REJECTED` otherwise.
- Artifact selection (`_artifact_pypi`):
  - From `releases[v]` choose `sdist` first, then `bdist_wheel` (first by
    filename order otherwise). If neither usable entry exists →
    `ARTIFACT_UNAVAILABLE` (new stable code, added to `FetchErrorCode`).
  - `url` must validate as a PyPI host URL → `TARBALL_URL_INVALID`.
  - Digest: `digests.sha256`, fallback `digests.blake2b_256`, none →
    `DIGEST_MISSING`. The `digest_method` string in the report is the
    algorithm name (`sha256`, `blake2b_256`).
  - Download via the existing `UrllibClient` + `RetryingClient`; size caps are
    `[fetch]`-driven as today. The artifact file keeps its original filename
    so `extract_archive`'s format sniffing sees `.tar.gz` / `.whl`.
- `ExpectedDigest`/`digest_matches` (cache.py) — add `sha256` and
  `blake2b_256` branches (small, targeted extension, no behavior change for
  existing sha512/sha1 paths).
- `fetch_release_pypi(name, version, ...)` and `fetch_pair_pypi(...)` with the
  same return shape as the npm pair.

What `fetch/pypi.py` deliberately does NOT do: index/time-travel queries, no
`files` guessing, no fallback to mirrors, no "latest" resolution.

## 5. Diff layer changes (M3)

- `build_diff_context` already takes `ecosystem`. The npm-specific coupling is
  in the root metadata readers: `diff/manifest.py` and `rules/scan.py` hardcode
  `ROOT_MANIFEST = "package/package.json"`. Introduce one ecosystem-aware
  resolver used by both. Per-version dependency metadata CANNOT come from the
  PyPI registry document (no per-version `dependencies` field exists there, only
  the latest version's `info.requires_dist`), so PyPI's read path is the
  unpacked tree itself (`PKG-INFO`/`METADATA`), via ecosystem-aware root
  metadata resolution:
  - npm → `package/package.json` (unchanged).
  - PyPI sdist → `<name>-<version>/PKG-INFO` at depth 1.
  - PyPI wheel → `*.dist-info/METADATA` at depth 1.
  Read both trees' root metadata; expose `dependencies` (parsed `Requires-Dist`
  lines), `name`, `version` to family-4 PyPI rules. `read_root_manifest` gains
  an ecosystem switch; behavior for npm byte-identical (existing tests).
- The npm-shaped `package_json_changes` / `registry_metadata_changes` report
  sections stay exactly as they are for npm. On a PyPI pair they render as
  absent/empty skeleton; ecosystem-specific manifest-section polish is
  deferred to a later phase (documented in §11).
- Sandbox unchanged: `extract_archive` already sniffs tar.gz and zip and
  applies traversal limits.

## 6. Rules (M4)

Registry gains PyPI registrations; the same `RuleFamily` enum and `rules_for`
select by ecosystem. PyPI rule set for M4 (v1, bounded):

| Rule ID | Family | Severity | Reads |
|---|---|---|---|
| `PYPI_INSTALL_HOOK_ADDED` | lifecycle | high | `setup.py` / `pyproject.toml` at depth ≤ root; detects added `setup(` / `setuptools.setup(` invocation or new `[project.scripts]`/`[project.entry-points]` tables |
| `PYPI_SHELL_EXEC_ADDED` | capability | high | added lines into any `.py` text view: `os.system(`, `os.popen`, `subprocess.` |
| `PYPI_EVAL_EXEC_ADDED` | capability | high | added lines: `eval(`, `exec(`, `__import__(` |
| `PYPI_NET_ACCESS_ADDED` | capability | medium | added lines: `import socket`, `import urllib`, `import requests`, `import http.client` and their usage forms |
| `PYPI_ENV_ENUM_ADDED` | capability | low | added lines: `os.environ`, `os.getenv`, `getenv(` |
| `PYPI_DEPENDENCY_ADDED` | metadata | low | root metadata (`Requires-Dist`) added names, one package-level finding per new dependency |

Severities mirror the npm counterparts' precedents (`NET_ACCESS_ADDED` is medium;
`ENV_ENUMERATION_ADDED` is low) so scores stay within the existing `w1` table;
no new weights are introduced, no npm rule logic changes. The rules' docstrings
state the exact patterns and scope limits (text-only evidence), matching the
style of families 1/2.

Behavior note: the family corroboration engine works unchanged — with
obfuscation family 3 not implemented for PyPI, `lifecycle_plus_obfuscation`
cannot fire on PyPI; that is documented as a v1 limitation, not a scoring
defect.

**Out of P1 scope:** PyPI obfuscation, wheel-binary rules, metadata-difference
rules reading registry JSON `info.requires_dist` (wrong level), anything
requiring semantic AST analysis.

## 7. CLI and report

```
pkgwatch compare pypi:<name>@<old> pypi:<name>@<new> [--json|--markdown|--sarif]
                 [--fail-on] [--explain] [--ignore] [--experimental]
                 [--fail-on-score] [--min-severity] [--verbose] [--output] [--quiet]
```

- `parse_spec` learns the `pypi:` prefix; `npm:` is untouched. A bare name
  (no prefix) is rejected as before.
- `--fail-on-score` and `--min-severity` behave identically: score is the same
  `w1` number; `--min-severity` filters PyPI display the same way.
- `submitted ecosystem` is on the wire in all report outputs (`"ecosystem": "pypi"`).
  The compare JSON `schema_version` stays `2`: the JSON shape is unchanged; only
  the `ecosystem` field's domain grows (`"npm" | "pypi"`), and report
  `disclaimer` remains unconditional.
- `--sarif`/`--output`/`--quiet`/`--explain`/`--ignore` flow through the same
  patterns as npm already established. `(experimental)` explain marking applies
  wherever the explanations block is rendered; P1 ships no PyPI family 3/4
  rules, so no PyPI finding is experimental in v1.
- `--experimental` extends the same gating concept to the PyPI path in the same
  way: experimental families, if any were added for PyPI, stay off unless the
  flag is given. By default nothing in the PyPI core set is gated today.

## 8. Error codes (all old codes are reused; one new)

- `ARTIFACT_UNAVAILABLE` (new, `FetchErrorCode`) — the version exists but has
  no sdist/wheel (or neither passes host/hash validation).
- Others map: unknown project/version → `VERSION_NOT_FOUND`; document malformed →
  `REGISTRY_DOC_INVALID`; host or scheme violation → `TARBALL_URL_INVALID` /
  `REDIRECT_REJECTED`; hash absent → `DIGEST_MISSING`; mismatch → `DIGEST_MISMATCH`;
  non-sha256/blake2b-only main digests → `DIGEST_UNSUPPORTED`; HTTP/transport errors →
  `HTTP_ERROR` / `FETCH_FAILED`; name/version garbage at parse → `INVALID_PACKAGE_NAME` /
  `INVALID_VERSION` / `INVALID_SPEC`; `package` mismatch between old/new →
  `PACKAGE_MISMATCH`.

`compare pypi` error output shape is the same as npm's (`_error`).

## 9. Tests (offline-first)

- `tests/support/pypi_registry.py`: `PyPIRegistry` fake mirroring `FakeRegistry`
  semantics (document + sdist tarball + wheel zip bytes, digest consistent,
  request logging, 404/429 for retry tests).
- `tests/unit/version/` property tests (hypothesis, per §6.4) — also covers
  lock pairing tie-breaks.
- `tests/unit/lockfile/test_plan.py` + `test_run.py`: balanced multi-version
  zip pairings after ordering lands; unbalanced keeps `MULTIPLE_VERSIONS`.
- New rule fixtures: committed synthetic trees mimicking an sdist root layout
  (`PYPI_ALLOWED` trees) — never real packages (per hard constraint).
- Integration: compare success paths for sdist-only, wheel-only, mixed; digest
  mismatch / unsupported host / version not found never touch the network beyond
  the fixture; SARIF/Markdown assert ecosystem "pypi".
- Hard invariants to keep green: npm installer pair (4 findings, score 94),
  benign pair (0), lock invariants unchanged.

## 10. Documentation updates

- `README.md`: replace the "PyPI support (roadmap)" section with the actual
  support status and the PyPI design milestones; update "What it does not do"
  ("npm only, exact versions only" → "npm and PyPI, exact versions only").
- `SPEC.md`: §3 PyPI endpoint table (document endpoint + allowed hosts +
  hash preference); §4.5 gets a PyPI rule section (§4.5.2); §6.4 status lines to
  "implemented"; decision log entry for the PyPI JSON API endpoint.
- `pyproject.toml` description stays accurate ("Package behavior diff monitor
  for npm, PyPI and crates.io") — now true for two of three.
- `action.yml`/workflow docs state PyPI `compare` is not wired into CI yet.

## 11. Phases in this milestone

| Phase | Ships source of truth | Exit criteria |
|---|---|---|
| **M1** | `src/pkgwatch/version.py` + property tests | hypothesis suite green for both ecosystems; non-. version rejected |
| **M2** | `version.py` wired into plan zip pairing | balanced multi-version names get ordered pairs; npm singles unchanged; `MULTIPLE_VERSIONS` retained for unbalanced |
| **M3** | `fetch/pypi.py` + cache sha256 + CLI route | `compare pypi:` end-to-end offline; stable codes on doc/artifact errors; `validate_version` delegation |
| **M4** | ecosystem-aware root metadata + 5–6 `PYPI_*` rules + fixtures | PyPI rules fire and respect `--experimental`/ignore paths; installer invariants unchanged for npm; new-PyPI snapshot fixtures green under pytest |
| **M5** | docs + SPEC + gates + smoke | README status reset, SPEC decisions closed, gatelog, cmd.exe smoke, git push |

**Estimate label:** these are relative slices, not timing promises; M1 is the
dependency-free slice and lands first. Each phase lands with its own tests;
no phase changes behavior for the existing numpy code paths.

## 12. Open items for the implementation phase (no spec blockers)

- Exact path of wheel's `<name>-<version>.dist-info/` root detection — resolve
  by reading the sandbox's ZIP reader conventions at implementation time.
- CLI `--ecosystem` flag remains a no-op string; spec prefix is the route.
- The action will inherit `compare pypi` support automatically once CLI lands;
  workflow wiring is a later phase.
