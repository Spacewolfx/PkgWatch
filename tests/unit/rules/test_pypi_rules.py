"""PyPI rules (SPEC §4.5.2): lifecycle hooks, capability additions, declared dependencies.

Matching is on ADDED lines only, exactly like the npm families; every rule states the
blind spots that line matching cannot see. Dependency evidence comes from the shipped
``PKG-INFO``/``METADATA`` document, never from registry metadata.
"""

from __future__ import annotations

from pathlib import Path

from pkgwatch.models import Ecosystem, RuleFamily, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.family1_pypi import PYPI_INSTALL_HOOK_ADDED, pypi_install_hook_added
from pkgwatch.rules.family2_pypi import (
    PYPI_ENV_ENUM_ADDED,
    PYPI_EVAL_EXEC_ADDED,
    PYPI_NET_ACCESS_ADDED,
    PYPI_SHELL_EXEC_ADDED,
    pypi_env_enum_added,
    pypi_eval_exec_added,
    pypi_net_access_added,
    pypi_shell_exec_added,
)
from pkgwatch.rules.family4_pypi import PYPI_DEPENDENCY_ADDED, pypi_dependency_added
from pkgwatch.rules.runner import run_rules
from tests.support.context import ctx_from_files
from tests.support.fixtures import pypi_package_context

BASE = {"demo/__init__.py": b"VERSION = '1.0.0'\n"}

# (rule_id, fn, severity, line, pattern, families)
DETECTIONS = [
    (
        PYPI_SHELL_EXEC_ADDED,
        pypi_shell_exec_added,
        Severity.HIGH,
        "import os\nos.system('echo hi')\n",
        "os_system",
        RuleFamily.DANGEROUS_CAPABILITY,
    ),
    (
        PYPI_EVAL_EXEC_ADDED,
        pypi_eval_exec_added,
        Severity.HIGH,
        "value = eval('1 + 1')\n",
        "eval_call",
        RuleFamily.DANGEROUS_CAPABILITY,
    ),
    (
        PYPI_NET_ACCESS_ADDED,
        pypi_net_access_added,
        Severity.MEDIUM,
        "import requests\n",
        "import_requests",
        RuleFamily.DANGEROUS_CAPABILITY,
    ),
    (
        PYPI_ENV_ENUM_ADDED,
        pypi_env_enum_added,
        Severity.LOW,
        "keys = list(os.environ)\n",
        "os_environ",
        RuleFamily.DANGEROUS_CAPABILITY,
    ),
    (
        PYPI_INSTALL_HOOK_ADDED,
        pypi_install_hook_added,
        Severity.HIGH,
        "from setuptools import setup\nsetup(name='demo')\n",
        "setup_call",
        RuleFamily.LIFECYCLE_SCRIPTS,
    ),
    (
        PYPI_DEPENDENCY_ADDED,
        pypi_dependency_added,
        Severity.LOW,
        None,
        None,
        RuleFamily.METADATA,
    ),
]


def test_rule_metadata_matches_spec() -> None:
    registered = {rule.rule_id: rule for rule in RULES}
    for rule_id, fn, severity, _line, _pattern, family in DETECTIONS:
        rule = registered[rule_id]
        assert rule.severity is severity
        assert rule.rule_version == 1
        assert rule.families == (family,)
        assert rule.ecosystems == (Ecosystem.PYPI,)
        assert callable(fn)


def test_capability_rules_fire_on_the_obvious_added_line(tmp_path: Path) -> None:
    for rule_id, fn, severity, line, pattern, family in DETECTIONS:
        if line is None or family is not RuleFamily.DANGEROUS_CAPABILITY:
            continue
        ctx = ctx_from_files(tmp_path, BASE, {**BASE, "demo/shell.py": line.encode()})
        findings = fn(ctx)
        assert len(findings) == 1, rule_id
        (finding,) = findings
        assert finding.rule_id == rule_id
        assert finding.severity is severity
        assert finding.path == "demo/shell.py"
        assert finding.details["pattern"] == pattern
        assert finding.details["old_tree_scan"] == "full"


def test_capability_rules_ignore_near_misses(tmp_path: Path) -> None:
    near_misses = [
        (pypi_shell_exec_added, "import subprocess\nprint('done')\n"),  # no call, no os.system
        (pypi_eval_exec_added, "total = parse_int(value, 10)  # evaluate later\n"),
        (pypi_net_access_added, "import json\n"),
        (pypi_env_enum_added, "home = os.path.expanduser('~')\n"),
    ]
    for fn, line in near_misses:
        ctx = ctx_from_files(tmp_path, BASE, {**BASE, "demo/shell.py": line.encode()})
        assert fn(ctx) == [], fn.__name__


def test_capability_already_present_in_the_old_tree_is_not_new(tmp_path: Path) -> None:
    line = b"import os\nos.system('echo hi')\n"
    ctx = ctx_from_files(
        tmp_path,
        {"demo/legacy.py": line},
        {"demo/legacy.py": line, "demo/shell.py": line},
    )
    assert pypi_shell_exec_added(ctx) == []


def test_non_python_files_are_out_of_scope(tmp_path: Path) -> None:
    line = b"import os\nos.system('echo hi')\n"
    ctx = ctx_from_files(tmp_path, BASE, {**BASE, "README.md": line, "docs/notes.txt": line})
    assert pypi_shell_exec_added(ctx) == []


def test_install_hook_ignores_an_unrelated_added_line(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"setup.py": b"from setuptools import setup\nsetup(name='demo')\n"},
        {"setup.py": b"from setuptools import setup\nsetup(name='demo')\nprint('hi')\n"},
    )
    # The added line is unrelated; the setup( line was already there.
    assert pypi_install_hook_added(ctx) == []


def test_install_hook_ignores_a_version_bump_of_the_existing_call(tmp_path: Path) -> None:
    # The setup( line changes text but the hook is the same one: the old tree already
    # had it, so the modified line is not a new hook.
    ctx = ctx_from_files(
        tmp_path,
        {"setup.py": b"setup(name='demo')\n"},
        {"setup.py": b"setup(name='demo2')\n"},
    )
    assert pypi_install_hook_added(ctx) == []


def test_install_hook_fires_when_a_build_file_gains_setup(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {},
        {"setup.py": b"from setuptools import setup\nsetup(name='demo')\n"},
    )
    findings = pypi_install_hook_added(ctx)
    assert len(findings) == 1
    assert findings[0].path == "setup.py"
    assert findings[0].details["pattern"] == "setup_call"


def test_dependency_rule_fires_for_a_newly_declared_dependency(tmp_path: Path) -> None:
    old = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\nRequires-Dist: requests>=2.0\n"
    new = (
        b"Metadata-Version: 2.1\nName: demo\nVersion: 1.1.0\n"
        b"Requires-Dist: requests>=2.0\n"
        b"Requires-Dist: evil-dep\n"
    )
    ctx = ctx_from_files(
        tmp_path,
        {"demo-1.0.0/PKG-INFO": old},
        {"demo-1.1.0/PKG-INFO": new},
        ecosystem=Ecosystem.PYPI,
    )
    findings = pypi_dependency_added(ctx)
    assert len(findings) == 1
    (finding,) = findings
    assert finding.rule_id == PYPI_DEPENDENCY_ADDED
    assert finding.path is None
    assert finding.details["dependency"] == "evil-dep"


def test_dependency_rule_is_gated_by_experimental(tmp_path: Path) -> None:
    old = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"
    new = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.1.0\nRequires-Dist: evil-dep\n"
    ctx = ctx_from_files(
        tmp_path,
        {"demo-1.0.0/PKG-INFO": old},
        {"demo-1.1.0/PKG-INFO": new},
        ecosystem=Ecosystem.PYPI,
    )
    assert PYPI_DEPENDENCY_ADDED not in {f.rule_id for f in run_rules(ctx)}
    assert PYPI_DEPENDENCY_ADDED in {f.rule_id for f in run_rules(ctx, experimental=True)}


def test_committed_installer_tree_fires_every_pypi_rule(tmp_path: Path) -> None:
    ctx = pypi_package_context(tmp_path, "pypi_synthetic_installer")
    found = {f.rule_id for f in run_rules(ctx, experimental=True)}
    assert found == {
        PYPI_INSTALL_HOOK_ADDED,
        PYPI_SHELL_EXEC_ADDED,
        PYPI_EVAL_EXEC_ADDED,
        PYPI_NET_ACCESS_ADDED,
        PYPI_ENV_ENUM_ADDED,
        PYPI_DEPENDENCY_ADDED,
    }


def test_committed_benign_tree_fires_no_pypi_rule(tmp_path: Path) -> None:
    ctx = pypi_package_context(tmp_path, "pypi_benign_bump")
    assert run_rules(ctx, experimental=True) == []


def test_new_capability_in_a_moved_file_still_fires(tmp_path: Path) -> None:
    """A file that moves directories (the src-layout restructure) but gains a
    capability is a real addition: the old tree lacks it, so it must fire even though
    the file moved rather than being edited in place.
    """
    ctx = ctx_from_files(
        tmp_path,
        {"requests/utils.py": b"VALUE = 1\n", "requests/api.py": b"# api\n"},
        {
            "src/requests/utils.py": b"VALUE = 1\nresult = eval('payload')\n",
            "src/requests/api.py": b"# api\n",
        },
        ecosystem=Ecosystem.PYPI,
    )
    findings = pypi_eval_exec_added(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == PYPI_EVAL_EXEC_ADDED
    assert findings[0].path == "requests/utils.py"
