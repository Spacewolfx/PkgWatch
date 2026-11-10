# PyPI support

`pkgwatch compare` supports PyPI exact versions. This is the user-facing companion to
the PyPI sections of [SPEC.md](../SPEC.md) (§3, §4.5.2, §9.2) and [rules.md](rules.md).

## Usage

```bash
uv run pkgwatch compare pypi:requests@2.31.0 pypi:requests@2.32.0
uv run pkgwatch compare pypi:requests@2.31.0 pypi:requests@2.32.0 --json --experimental
```

Names go through PEP 503 normalisation, so `Demo_Pkg`, `demo-pkg` and `demo.pkg` are
the same project; the report shows the spelling you typed. The two specs must name the
same ecosystem and project, else the command exits 2 with `PACKAGE_MISMATCH`. Only
exact versions are accepted — ranges, tags and wildcards are rejected
(`INVALID_VERSION`).

## What is fetched

One document, `GET https://pypi.org/pypi/<name>/json`, is fetched and the release
artifact URL is read from its `releases[v]` file entries — never invented. Only
HTTPS on `pypi.org` and `files.pythonhosted.org` is followed. Artifacts are verified
against `digests.sha256` (falling back to `digests.blake2b_256`) before extraction;
a mismatch stops the run with `DIGEST_MISMATCH`. An sdist (`.tar.gz`) is preferred;
if a release has only a wheel (`.whl`), the wheel is used; if it has neither,
`ARTIFACT_UNAVAILABLE`. Artifacts are cached keyed by the verified digest (the same
cache as npm); `[fetch].cache_dir` overrides the location and `--no-cache` disables it
for one run.

Per-version registry metadata is fetched from `GET /pypi/<name>/<version>/json` for
both versions and diffed into `pypi metadata changes` (`requires_dist`,
`requires_python`, `classifiers`, `project_urls`, `entry_points`, `yanked`,
`summary`). If that document cannot be fetched, every field reads `(not available)`
and the artifact analysis still runs.

## What is analysed

Both artifacts are unpacked only through `pkgwatch.sandbox` and read as text. Nothing
is ever executed, imported, installed or built — including `setup.py`, which is
analysed statically. An sdist's `{name}-{version}/` root is stripped before diffing,
so the same file across versions compares to itself and a version bump reports
`modified > 0` rather than all-added/all-removed. The six PyPI rules in
[rules.md](rules.md) run; dependency evidence comes from the shipped
`PKG-INFO`/`METADATA`, never from registry metadata.

## Limitations

- The `lock` command covers npm lockfiles only; there is no PyPI lock support.
- Wheel *binary* content is not analysed — only the text files inside the archive
  (modules, `METADATA`). Distribution binaries are skipped.
- Family 3 obfuscation signals are npm-only; the PyPI rule set is families 1, 2 and 4.
