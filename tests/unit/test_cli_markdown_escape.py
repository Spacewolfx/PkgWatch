"""``_md_escape`` sanitizes package-controlled text for Markdown that GitHub turns into HTML.

The compare Markdown report is pasted into a PR comment, so a value containing raw markup
would be interpreted as HTML. The reference behaviour (lock/report.py ``_md``) html-escapes
first, then escapes the Markdown table/emphasis specials.
"""

from __future__ import annotations

from pkgwatch import cli


def test_md_escape_html_escapes_dangerous_markup() -> None:
    out = cli._md_escape('<script>alert("x")</script>')

    for char in ("<", ">", '"'):
        assert char not in out
    assert "&lt;script&gt;" in out


def test_md_escape_still_protects_markdown_table_cells() -> None:
    assert cli._md_escape("a|b") == "a\\|b"
    assert cli._md_escape("a`b") == "a\\`b"
    assert cli._md_escape("a\\b") == "a\\\\b"
    assert cli._md_escape("*x_ [y]") == "\\*x\\_ \\[y\\]"
