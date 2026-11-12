"""Entry point for ``python -m pkgwatch`` (the GitHub Action invokes it this way)."""

from __future__ import annotations

import sys

from pkgwatch.cli import main

if __name__ == "__main__":
    sys.exit(main())
