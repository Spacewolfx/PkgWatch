"""The version a release ships with has to be one version everywhere.

``pkgwatch --version``, the built distribution's metadata and the default User-Agent all
read a different literal, so a release bump that misses one of them ships a build that
contradicts itself.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pkgwatch import __version__
from pkgwatch.config import DEFAULT_TOML, FetchConfig

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_the_distribution_metadata_matches_the_runtime_version() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project = tomllib.loads(text)["project"]

    assert project["version"] == __version__


def test_the_default_user_agent_carries_the_current_version() -> None:
    assert FetchConfig().user_agent == f"pkgwatch/{__version__}"
    assert f'user_agent = "pkgwatch/{__version__}"' in DEFAULT_TOML
