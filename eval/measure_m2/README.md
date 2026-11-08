# M2 measurement harness

One-off script that measures whether the family 1 and 2 npm rules added in M2 are useful:
do they fire on real malicious releases and stay quiet on real benign ones?

It is **not part of the product**. Nothing under `src/` or `tests/` imports it, and it adds no
detection logic — it only calls `pkgwatch.diff`, `pkgwatch.rules`, `pkgwatch.sandbox` and
`pkgwatch.score` as they already exist.

**All results are static-only.** No package code is ever executed, imported, installed or built,
here or anywhere else in this repository.

## What is measured

For each `(package, previous_version, version)` pair:

1. The npm registry document (`GET https://registry.npmjs.org/<name>`, SPEC §3) supplies the
   tarball URL and the `dist.integrity` / `dist.shasum` values. Tarballs are downloaded to the
   gitignored `data/raw/` cache and the recorded integrity is verified **before** anything is
   analysed.
2. Both sides are extracted through `pkgwatch.sandbox.extract_archive` with the product's
   configured limits. Any `ArchiveRejected` code is recorded and the pair is excluded.
3. `pkgwatch.diff.build_diff_context` produces the context; `pkgwatch.rules.run_rules` runs the
   seven registered npm rules.
4. `pkgwatch.score.engine.score` scores the findings with the SPEC §5 weights, unchanged.
5. The pair is labelled by stratum only — `malicious` (from the OSSF advisories) or `benign` —
   and metrics are computed at the two thresholds the SPEC already declares (alert 40,
   escalate 70). No threshold is tuned here.

Rules measured: `NPM_INSTALL_SCRIPT_ADDED`, `NPM_SCRIPT_INJECTION_FROM_METADATA`,
`JS_CHILD_PROCESS_ADDED`, `DYNAMIC_EVAL_ADDED`, `NET_ACCESS_ADDED`,
`FS_WRITE_OUTSIDE_PACKAGE_ADDED`, `ENV_ENUMERATION_ADDED` (`rule_set_version` is recorded per run).

Sampling:

- **malicious** — pairs from npm OSV records in the local `ossf/malicious-packages` clone, where
  the affected version has a registry predecessor. Predecessors are chosen by `published_at`
  from the document's `time` map (SPEC §6.1), so no semver comparator is needed.
- **benign hard negatives** — the most recent pair per package in your committed list, restricted
  to pairs where at least one side declares an install-time script.
- **benign controls** — a seeded random sample of listed packages with no install-time script.
- `--seed` (default 1234) and `--max-pairs` (default 200, applied per pool) make the draw
  reproducible. Malicious names are removed from the benign pools. Everything skipped is counted
  with a stable reason code and written to `pairs.json` and `run.json`.

Reported metrics: per-stratum pair counts, share with any finding, share at alert and at escalate,
median and max score, per-rule hit counts, exclusion and sandbox-rejection tallies, and at each
threshold the malicious recall, benign false-alarm rate, hard-negative false-alarm rate and Youden's J.

## What is *not* measured

- **Dynamic behaviour.** Nothing is installed, imported or run. A rule that only looks at file
  content cannot see what happens at install time; this harness does not try to compensate.
- **Whether a package is actually malicious.** The OSSF advisory is treated as the label, with its
  commit and license recorded, nothing more.
- **Precision against a curated benign corpus.** The benign set is whatever names you supply; it is
  not a random sample of npm and contains no guarantee of correctness.
- **Advisories that state ranges instead of versions.** Evaluating them needs the
  `pkgwatch.version` comparator described in SPEC §6.4, which does not exist yet. Those records are
  counted (`ranges_only_packages_skipped`) and skipped; the harness refuses to grow its own
  comparator.
- **Stratification by shipped metadata.** The install-script check reads `versions.<v>.scripts`
  from the registry document, not the `package.json` inside the tarball. They normally agree, but a
  package can differ; a pair can therefore land in the wrong benign stratum. The strata are still
  honest because rule 1 itself sees the real shipped file.
- **Rule coverage of the whole ecosystem.** Families 1–2 only, npm only, and only the pairs the two
  inputs make available.
- **Any model layer.** No LLM is called anywhere in this script; M3 outputs cannot leak into it.

The brief that produced this harness was truncated in the middle of step 3 of "Procedure per
pair". Steps 1–3 are verbatim from it; the scoring call, the metric definitions and the four output
files are a reconstruction and should be re-checked against the intended measurement before the
numbers are used for anything.

## Inputs (both required, neither has a default)

- `--ossf-dir` — a local clone of <https://github.com/ossf/malicious-packages>. Only npm OSV
  entries are read. The run records the clone's commit SHA (resolved from `.git`, or
  `--ossf-commit`) and the digest and first line of its `LICENSE`. No LICENSE file → the run stops.
- `--benign-list` — a committed text file, one npm name per line, with a header that records where
  the list came from and when it was retrieved. The script never fetches a popularity list itself,
  so that provenance has to be written down or the run stops. See `benign_list.example.txt`.

Missing or unusable inputs produce a `TODO:` message and exit 2. The script does not substitute a
guessed advisory source, an invented package list or an unverified endpoint. It also refuses a
directory with no `advisories/` inside, so a mistyped `--ossf-dir` fails immediately instead of
walking an unrelated tree.

## How to rerun

```bash
cd pkgwatch
uv run python eval/measure_m2/measure.py --self-check          # no network, no package bytes

uv run python eval/measure_m2/measure.py \
  --ossf-dir ~/src/malicious-packages \
  --benign-list eval/measure_m2/benign_list.txt \
  --seed 1234 --max-pairs 200

uv run python eval/measure_m2/measure.py --config eval/measure_m2/measure.example.toml --offline
```

Useful switches: `--offline` (cached documents and tarballs only, no requests at all),
`--refresh-docs`, `--sleep` (0.2 s between requests by default), `--limit N` (first N pairs,
deterministic — for a smoke run), `--keep-extracted`, `--pkgwatch-config` (product TOML, so the
sandbox limits and weights used are the deployed ones), `--out-dir`.

Everything downloaded goes to `data/raw/docs`, `data/raw/artifacts` and `data/raw/extract`, which
are gitignored. Re-running reuses that cache; `--offline` then analyses from the cache alone and
makes no request at all (the self-check asserts this, and that a pair whose artifact is missing is
excluded with `ARTIFACT_NOT_CACHED_OFFLINE` rather than guessed).

## Outputs (in `out/`, committed)

| File | Contents |
| --- | --- |
| `pairs.json` | every sampled pair: name, both versions, publish time, stratum, origin, pool sizes, skip counters. Coordinates only. |
| `results.json` | one row per pair: label, score, alert/escalate flags, rule ids, finding count, files changed, exclusion reason. |
| `metrics.json` | per-stratum aggregates and the separation numbers at both thresholds. |
| `run.json` | what produced the numbers: advisory commit and license, benign list provenance, rule set version, weights, sandbox limits, Python and package versions, counters, `static_only: true`. |

None of these files contains package content. Per-finding evidence strings do — and therefore stay
out of `out/`: pass `--with-evidence <path outside the repo>` to write them anywhere else.

## Status

No live measurement has been run. Both required inputs are operator-supplied and neither is present
in this checkout yet, so `out/` is empty apart from `.gitkeep`. `--self-check` is the only evidence
available so far: it exercises OSV selection, predecessor choice, digest verification, strata,
sampling determinism, metric arithmetic, the provenance guards and the offline refusals without
touching the network or any package bytes.
