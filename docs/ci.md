# Continuous integration

`pkgwatch lock` fails a pull request when a dependency update changes what is installed
or what the code does. This document describes the wiring, the trust model, and what is
still unresolved. **The Action and the example workflow are untested on GitHub** — nothing
here is claimed to have run on a real runner yet.

## Setup

1. Copy [examples/github-workflow.yml](../examples/github-workflow.yml) to
   `.github/workflows/lock.yml` in your repository.
2. Pin every `uses:` by full commit SHA (never invent a hash) and point the action at
   the published pkgwatch action once publishing exists — see "Install and publishing"
   below. Until then the file documents the intended shape only.
3. Optionally commit a `.pkgwatch.toml` and/or a `baseline.json` **on the base branch**.
   They are only ever read from there (no action is needed in the PR to enable them).

## Where each file comes from

| Input | Source |
|---|---|
| pkgwatch itself (action + package) | The pinned pkgwatch action ref (`GITHUB_ACTION_PATH`) |
| old lockfile (`--old`) | Base branch |
| new lockfile (`--new`) | PR head (the workspace root) |
| config (`.pkgwatch.toml`) | Base branch, when it already exists there |
| baseline (`baseline.json`) | Base branch, when it already exists there |
| report | `$GITHUB_STEP_SUMMARY`, always |

**A PR must not be able to silence its own findings.** The workflow triggers on
`pull_request` — never `pull_request_target` — with `permissions: contents: read`, and
the action sources config, baseline and the old lockfile from a base-branch checkout
(`.base/`). So `pkgwatch.toml` and `baseline.json` added or edited inside a PR are
never read: if they exist only on the PR, they are simply absent for that run. A PR
that wants to acknowledge a finding updates the baseline on the base branch in a
separate, reviewed commit.

## Exit-code mapping

The action exits with pkgwatch's exit code, so the job fails accordingly:

| Exit | Meaning | Job |
|---|---|---|
| `0` | No findings at or above `--fail-on` | pass |
| `1` | Findings at or above `--fail-on` | fail, report in the summary |
| `2` | Error or incomplete analysis | fail, report in the summary |

## Report and comments

The Markdown report is always appended to `$GITHUB_STEP_SUMMARY`. Posting it as a PR
comment is opt-in (`comment: "true"` in the action's `with:`) and requires
`pull-requests: write` for the job — the read-only workflow above does not have it.

## Install and publishing

Licensed under MIT (see `LICENSE`). No PyPI package is published yet; the publishing
path is TODO: choose an index, publish, and pin the SHAs in `action.yml` and the example
workflow by full commit hash. Until then the action installs pkgwatch from its own
checkout (`python -m pip install "$GITHUB_ACTION_PATH"`).

## Limitations

Same as the tool overall: static analysis only, npm only, exact versions only,
`package-lock.json` v2/v3 only, brand-new packages analysed without a baseline (their
findings are noisier), lifecycle evidence is only the manifest line, obfuscated or
runtime behaviour is missed, and the false-positive rate is unknown. Detection quality
has not been measured.
