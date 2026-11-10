# Rule catalog

`pkgwatch rules [--json | --markdown] [--family FAMILY] [--rule RULE_ID] [--ecosystem npm|pypi]`
prints this catalog from the live registry; every entry lists its families and ecosystems.

Every rule is a pure `DiffContext -> list[Finding]` function; the full contract is in
[SPEC.md](../SPEC.md) §4. Findings are produced for **added lines only** (family 2) or
the shipped metadata document (family 4), and a capability already present anywhere in
the old tree is never reported as new. Families 3 (obfuscation) and 4 (metadata) are
**experimental**: disabled by default, enabled with `--experimental`. Severities are
operator decisions, initial untuned values, not measured.

## npm

| Rule ID | Family | Severity | Detects |
|---|---|---|---|
| `NPM_INSTALL_SCRIPT_ADDED` | lifecycle | high | an added `preinstall`/`install`/`postinstall` key in the root `package.json` |
| `NPM_SCRIPT_INJECTION_FROM_METADATA` | lifecycle | high | an install script the registry `scripts` copy gained or changed |
| `JS_CHILD_PROCESS_ADDED` | capability | high | an added `require("child_process")` (with or without `node:`) |
| `DYNAMIC_EVAL_ADDED` | capability | high | an added `eval(` call or `new Function(` constructor |
| `NET_ACCESS_ADDED` | capability | medium | an added `require` of `https`, `http`, `net`, `tls`, `dgram` or `dns` |
| `FS_WRITE_OUTSIDE_PACKAGE_ADDED` | capability | medium | an added write call whose path escapes the package via a `..` segment |
| `ENV_ENUMERATION_ADDED` | capability | low | an added `Object.keys(process.env)` or `JSON.stringify(process.env)` |
| `BASE64_BLOB_PRESENT` | obfuscation | low | a long base64-like run on an added line |
| `HIGH_ENTROPY_STRINGS` | obfuscation | low | a high-entropy string literal on an added line |
| `HEX_ESCAPE_DENSITY` | obfuscation | low | many `\xHH` / `\uHHHH` escapes on one added line |
| `DEPENDENCY_ADDED` | metadata | low | a dependency name added in `versions[v].dependencies` |
| `REPOSITORY_URL_CHANGED` | metadata | medium | a changed `repository` field in the root `package.json` (normalized) |

## PyPI

| Rule ID | Family | Severity | Detects |
|---|---|---|---|
| `PYPI_INSTALL_HOOK_ADDED` | lifecycle | high | an added `setup(`, `setuptools.setup(`, `[project.scripts]` or `[project.entry-points` line in a build manifest (`setup.py`, `pyproject.toml`, `setup.cfg`, depth ≤ 2), unless the old tree already declared it |
| `PYPI_SHELL_EXEC_ADDED` | capability | high | an added `os.system(`, `os.popen(` or `subprocess.` use in a `.py` file |
| `PYPI_EVAL_EXEC_ADDED` | capability | high | an added `eval(`, `exec(` or `__import__(` call in a `.py` file |
| `PYPI_NET_ACCESS_ADDED` | capability | medium | an added `import`/`from` of `socket`, `urllib`, `requests`, `http.client` or `http`, or a `urllib.request` call |
| `PYPI_ENV_ENUM_ADDED` | capability | low | an added `os.environ`, `os.getenv(` or `getenv(` read |
| `PYPI_DEPENDENCY_ADDED` | metadata | low | a `Requires-Dist` name added in the shipped `PKG-INFO`/`METADATA` (never registry data) |

All six PyPI rules are disjoint from the npm rules by ecosystem: a rule only runs for
its own ecosystem. `PYPI_DEPENDENCY_ADDED` is experimental-gated, exactly like npm's
`DEPENDENCY_ADDED`.
