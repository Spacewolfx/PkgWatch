# pkgwatch lock: remaining work (operator decisions dated 2026-11-07)

Static analysis only. Never execute, import, install or build package content.
Never run npm, npx, node or package scripts, including in tests.
Do not change rule logic, severities, weights, or the `compare` command.
Do not touch eval/measure_m2/ or data/. No live registry calls in tests.
Errors print stable codes, never exception messages. Package-controlled strings
are untrusted in every output format. If SPEC conflicts with code, STOP and ask.
Do ONE milestone, report, and wait for approval.

## Status
- L0 compare fixes: reported done, not reviewed by operator.
- L1 lockfile parser and planner: done (SPEC section 9.1).
- L2 lock run: done from a truncated brief. Missing parts are in L2b.

## L2b (do this next)
1. Download cache keyed by VERIFIED integrity, default in the user cache dir,
   never inside the repo. Re-verify the digest on every read. Corrupt entry:
   delete and re-fetch. Add --no-cache.
2. Retry with exponential backoff only on 429, 5xx and timeouts. Cap attempts.
   Honour Retry-After. Add a polite per-request delay ([lock] config).
3. "Unanalysed" policy. A changed pair that cannot be analysed is NOT clean.
   This covers: unsupported source on the new side (git, file, link, http,
   other host, missing resolved) and MULTIPLE_VERSIONS.
   - Header and JSON show an "unanalysed" count plus a prominent warning line.
   - Never fold it into "no findings".
   - --strict-skips makes unanalysed pairs exit 2. Default exit code unchanged.
4. Check that duplicate JSON keys in a lockfile are detected (reject with a
   stable code) rather than silently taking the last value. Add a test.
5. Tests (offline): cache hit, miss, corruption, --no-cache; retry on 429 then
   success; retry cap reached; Retry-After; unanalysed warning;
   --strict-skips; duplicate keys; existing invariants unchanged
   (installer pair = same four findings, score 94; benign pair = 0).

## L3 policy, baseline, noise control
- Optional .pkgwatch.toml (--config): fail_on, max_pairs, ignored rule IDs.
  Every ignore REQUIRES a reason string. Ignored findings are counted and
  printed, never silent.
- Baseline: --update-baseline FILE writes acknowledged findings; --baseline FILE
  hides a finding only when (package name, rule_id, path, SHA-256 of the
  evidence text) matches an entry. The match does NOT include the version.
  If the evidence changes, the finding reappears. Each entry stores a mandatory
  reason and a date. Baselined findings are counted and printed. Write the
  exact match rule in SPEC.
- --markdown output: PR-comment sized, collapsible details, same disclaimer,
  evidence capped at 200 chars, Markdown and HTML escaped in every
  package-controlled string.
- Tests: ignore without reason is an error; baseline matches and stops matching
  when evidence changes; Markdown escaping of hostile strings.

## L4 GitHub Action and docs
- action.yml (composite), docs/ci.md, an example workflow.
- Trigger on pull_request, never pull_request_target. permissions: contents:
  read only. Write the report to $GITHUB_STEP_SUMMARY by default. PR comment is
  OPT-IN and documents its extra permission. Pin third-party actions by full
  commit SHA; use TODO placeholders for SHAs you cannot verify, never invent
  hashes. No secrets are read.
- The Action cannot run here: test the renderer, exit-code mapping and --plan,
  and mark the Action "untested on GitHub".
- README: "How to use in a PR" and "Limitations" (static only, npm only, exact
  versions, lockfile v2/v3 only, new packages not diffed, obfuscated or runtime
  behaviour missed, unknown false-positive rate). Keep the "not measured"
  statement. Use only example output from real runs.

## Report format after each milestone
1. Files changed, one line each.
2. Raw output of ruff format --check ., ruff check ., mypy --strict src/,
   pytest -v (every skip with its reason).
3. SPEC changes.
4. TODOs and unverified assumptions.
5. Exact smoke commands for the operator.
6. First step of the next milestone, not its implementation.