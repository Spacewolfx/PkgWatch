# Building pkgwatch

pkgwatch is a pure-Python package: there are no native extensions, so no compiler is needed.
The build backend is hatchling (declared in `pyproject.toml`) and the supported interpreter is
**Python 3.12 only** (`>=3.12,<3.13`; see `.python-version`).

## Prerequisites

```bash
uv --version
```

If uv is not installed, see <https://docs.astral.sh/uv/getting-started/installation/>.
uv fetches Python 3.12 and the hatchling build backend on first use.

## Development install — no build step

For everyday work, let uv install the project from `src/` with its dev dependencies:

```bash
uv sync
uv run pkgwatch --help
uv run pkgwatch version
```

Run the gates from here; see [CONTRIBUTING.md](CONTRIBUTING.md#gates--run-all-four-before-opening-a-pr).

## Build the distributions

```bash
uv build
```

Success creates two files in `dist/`:

```
dist/pkgwatch-<version>.tar.gz
dist/pkgwatch-<version>-py3-none-any.whl
```

For the current tree these are `pkgwatch-0.3.2.tar.gz` and
`pkgwatch-0.3.2-py3-none-any.whl`. The version comes from `pyproject.toml`.

`dist/` is gitignored by the root `.gitignore`; any `dist/.gitignore` is local-only, not
tracked. Old wheels are left in place, so remove stale artifacts before comparing builds:

```bash
# bash
find dist -type f -delete
# PowerShell
Get-ChildItem dist -File | Remove-Item
```

## Verify the built wheel

Install the wheel into a fresh environment rather than trusting the source tree:

```bash
uv venv .build-check
uv pip install --python .build-check/bin/python dist/pkgwatch-0.3.2-py3-none-any.whl
.build-check/bin/pkgwatch version
.build-check/bin/python -m pkgwatch version
```

On Windows use `.build-check\Scripts\python.exe` and `.build-check\Scripts\pkgwatch.exe`.
The release-metadata test also checks that the version in `pyproject.toml` matches the code:

```bash
uv run pytest -q tests/unit/test_release_metadata.py
```

## pip-only path

The composite action installs from a checkout with pip, which performs a PEP 517 build using
hatchling. The same commands work locally:

```bash
python -m pip install .                       # regular PEP 517 install from source (-e . for editable)
python -m pip wheel . --no-deps --wheel-dir dist
python -m pip install dist/pkgwatch-0.3.2-py3-none-any.whl
```

## When bumping the version

Four places must agree — three test functions enforce the first three and the README string:

| Place | What to change |
|---|---|
| `pyproject.toml` | `[project].version` |
| `src/pkgwatch/__init__.py` | `__version__` |
| `src/pkgwatch/config.py` | default `user_agent = "pkgwatch/<version>"` |
| `README.md` | prose that names `version <version>` |

Then rebuild and run the full gate set.

## Publishing status

Nothing is published to PyPI yet. `action.yml` installs pkgwatch from the action's own
checkout and is explicitly untested on a GitHub runner. Do not invent package URLs, hashes
or commit SHAs; follow the TODOs in `action.yml` and [ci.md](ci.md) before publishing.
