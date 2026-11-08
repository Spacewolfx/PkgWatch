"""Family 3 — obfuscation signals, npm (SPEC §4.5.1).

These rules report a *signal*, never intent. They read ADDED lines of new text views only,
never file names: a ``*.min.js`` or ``dist/`` path is not a reason to stay quiet, because
that would turn a naming convention into an evasion path.

All thresholds come from ``ctx.obfuscation`` (SPEC §6.5.1, ``[obfuscation]`` in config):
``min_blob_length``, ``entropy_min_length``, ``entropy_threshold_bits`` and
``min_escapes_per_line``. ``LIKELY_MINIFIED_LINE_LENGTH`` (500) defines
``details["likely_minified"]`` — a reporting flag for the reader, never a suppression.
Operator decision 2026-11-07: initial untuned values, not measured.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

BASE64_BLOB_PRESENT = "BASE64_BLOB_PRESENT"
HIGH_ENTROPY_STRINGS = "HIGH_ENTROPY_STRINGS"
HEX_ESCAPE_DENSITY = "HEX_ESCAPE_DENSITY"

LIKELY_MINIFIED_LINE_LENGTH = 500

# Quoted string literals in either quote style. Each match has exactly one non-None group.
_STRING_LITERAL_RE = re.compile(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"|`((?:\\.|[^`\\])*)`")
_ESCAPE_RE = re.compile(r"\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]+\}")

_Hit = tuple[str, int, str, dict[str, str | int | float | bool]]


def _literals(text: str) -> list[str]:
    return [
        next(group for group in match.groups() if group is not None)
        for match in _STRING_LITERAL_RE.finditer(text)
    ]


def _entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _added_text_lines(ctx: DiffContext) -> list[tuple[str, int, str]]:
    """(path, 1-based new line, text) for every ADDED line of every new text view."""
    lines: list[tuple[str, int, str]] = []
    for view in sorted(ctx.files_new.values(), key=lambda item: item.path):
        if not view.is_text:
            continue
        lines.extend((view.path, number, text) for number, text in scan.added_lines(view))
    return lines


def _likely_minified(text: str) -> bool:
    return len(text) >= LIKELY_MINIFIED_LINE_LENGTH


def _emit(
    ctx: DiffContext, hits: Sequence[_Hit], *, rule_id: str, severity: Severity
) -> list[Finding]:
    return [
        scan.finding(
            ctx,
            rule_id=rule_id,
            rule_version=1,
            severity=severity,
            path=path,
            evidence=evidence,
            line_start=number,
            line_end=number,
            details=details,
        )
        for path, number, evidence, details in hits
    ]


@registry.register(
    rule_id=BASE64_BLOB_PRESENT,
    rule_version=1,
    severity="low",
    ecosystems=("npm",),
    families=(RuleFamily.OBFUSCATION,),
    why_it_matters="A long encoded run is not readable as ordinary source.",
    common_benign_causes="Bundled assets, inline images, or source maps.",
)
def base64_blob_present(ctx: DiffContext) -> list[Finding]:
    """Detects a base64-like run of at least ``min_blob_length`` inside a quoted string.

    Only ADDED lines of new text views are scanned. The finding reports the length of the
    run, never the blob itself. ``details["likely_minified"]`` is true when the matching
    line reaches ``LIKELY_MINIFIED_LINE_LENGTH`` (500).

    Ignores deliberately: runs outside quoted strings, runs shorter than
    ``min_blob_length``, removed or unchanged lines, and the meaning of the encoded data.
    No file name — including ``*.min.js`` and ``dist/`` — suppresses a finding.
    """
    minimum = ctx.obfuscation.min_blob_length
    pattern = re.compile(rf"[A-Za-z0-9+/=_-]{{{minimum},}}")
    hits: list[_Hit] = []
    for path, number, text in _added_text_lines(ctx):
        for literal in _literals(text):
            match = pattern.search(literal)
            if match is None:
                continue
            length = len(match.group(0))
            hits.append(
                (
                    path,
                    number,
                    f"base64-like run of {length} characters in a quoted string",
                    {
                        "pattern": "base64_blob",
                        "length": length,
                        "likely_minified": _likely_minified(text),
                    },
                )
            )
            break
    return _emit(ctx, hits, rule_id=BASE64_BLOB_PRESENT, severity=Severity.LOW)


@registry.register(
    rule_id=HIGH_ENTROPY_STRINGS,
    rule_version=1,
    severity="low",
    ecosystems=("npm",),
    families=(RuleFamily.OBFUSCATION,),
    why_it_matters="A high-entropy literal can hold packed or encoded content.",
    common_benign_causes="A bundled token, checksum table, or minified output.",
)
def high_entropy_strings(ctx: DiffContext) -> list[Finding]:
    """Detects a quoted literal whose Shannon entropy reaches ``entropy_threshold_bits``.

    A literal must be at least ``entropy_min_length`` characters long; entropy is bits per
    character over its characters. The finding reports length and entropy, never the
    literal. ``details["likely_minified"]`` uses ``LIKELY_MINIFIED_LINE_LENGTH`` (500).

    Ignores deliberately: short literals, literals below ``entropy_threshold_bits``, text
    outside quotes, removed or unchanged lines, and any claim about what the literal means.
    No file name — including ``*.min.js`` and ``dist/`` — suppresses a finding.
    """
    minimum = ctx.obfuscation.entropy_min_length
    threshold = ctx.obfuscation.entropy_threshold_bits
    hits: list[_Hit] = []
    for path, number, text in _added_text_lines(ctx):
        for literal in _literals(text):
            if len(literal) < minimum:
                continue
            bits = _entropy(literal)
            if bits < threshold:
                continue
            hits.append(
                (
                    path,
                    number,
                    f"{len(literal)}-char string literal, {bits:.2f} bits/char",
                    {
                        "pattern": "high_entropy_string",
                        "length": len(literal),
                        "entropy_bits": round(bits, 2),
                        "likely_minified": _likely_minified(text),
                    },
                )
            )
            break
    return _emit(ctx, hits, rule_id=HIGH_ENTROPY_STRINGS, severity=Severity.LOW)


@registry.register(
    rule_id=HEX_ESCAPE_DENSITY,
    rule_version=1,
    severity="low",
    ecosystems=("npm",),
    families=(RuleFamily.OBFUSCATION,),
    why_it_matters="Many numeric escapes make a line hard to read as written.",
    common_benign_causes="Generated character tables or encoded assets in a bundle.",
)
def hex_escape_density(ctx: DiffContext) -> list[Finding]:
    """Detects at least ``min_escapes_per_line`` hex or unicode escapes on one ADDED line.

    Counts ``\\xHH``, ``\\uHHHH`` and ``\\u{...}`` spellings. The finding reports the count,
    never the line. ``details["likely_minified"]`` uses ``LIKELY_MINIFIED_LINE_LENGTH`` (500).

    Ignores deliberately: lines below ``min_escapes_per_line``, escaped characters written
    literally rather than as escapes, removed or unchanged lines, and the decoded content.
    No file name — including ``*.min.js`` and ``dist/`` — suppresses a finding.
    """
    minimum = ctx.obfuscation.min_escapes_per_line
    hits: list[_Hit] = []
    for path, number, text in _added_text_lines(ctx):
        count = len(_ESCAPE_RE.findall(text))
        if count < minimum:
            continue
        hits.append(
            (
                path,
                number,
                f"{count} hex/unicode escapes on one added line",
                {
                    "pattern": "escape_density",
                    "escapes": count,
                    "likely_minified": _likely_minified(text),
                },
            )
        )
    return _emit(ctx, hits, rule_id=HEX_ESCAPE_DENSITY, severity=Severity.LOW)
