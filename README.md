# ksec-fasttrack

A standalone tool for Linux kernel security patches, tracking **6.18 LTS** and **7.3** (configurable).

1. **Gather.** Collects fixes not yet in a stable release, from the stable queue and from mainline.
2. **Verify.** Checks that they apply as a series, with no fuzz, on the current stable head.
3. **List.** Reports every known security issue that is still unpatched.
4. **Make the missing patches.** Builds work packages for them, so they can be backported with Claude.

It is not tied to any build system. The output is plain patch sets that anything can consume.

## Quick start

```
./fasttrack.sh sync                         # pull sources (first run: linux.git ~5 GB)
./fasttrack.sh run                          # gather + verify; see out/report.md
./fasttrack.sh cve --unpatched --claude     # backport every unpatched issue with Claude
```

## Sources

| Source | Gives | Role |
|---|---|---|
| `stable-queue.git` | stable maintainers' backports queued for the next point release | preferred; days ahead of the release |
| `vulns.git` | CVE records: mainline fix commits, per-series affected / fixed-in | decides what is a security fix and what is still open |
| `linux.git` `master` + `linux-X.Y.y` | the base to verify on; mainline commits to pick | — |
| kernel.org `releases.json` | latest release per series | warns when the mirror is stale |
| CISA KEV | actively exploited CVEs | urgency (issue in CI) |

## `run`: gather, verify, list

Writes to `out/`:

```
patches/6.18/series.conf                  apply order
patches/6.18/0001-<sha12>-<slug>.patch    upstream patch + X-Fasttrack-* provenance headers
patches/6.18/base                         stable commit the set was verified on
patches/6.18/fasttrack.json               provenance (CVE, source, KEV)
report.md                                 what was included, what was not, and why
unpatched.json                            open security issues: CVE, fix commit, files, prerequisite hints
```

Each candidate gets one verdict:

| Verdict | Meaning |
|---|---|
| `accepted` | applies with no fuzz on the stable head plus all earlier accepted patches |
| `needs-backport` | does not apply unchanged; goes to `unpatched.json` |
| `already-present` | reverse-applies: stable has it even if the CVE record lags |
| `commit-missing` | fix commit not in the mirror yet |

`run` never adapts anything. The patch set contains only upstream bytes.

## `cve`: specific incidents

```
./fasttrack.sh cve CVE-2026-1234 CVE-2026-5678     # by id
./fasttrack.sh cve --commit <sha> --id my-incident  # no CVE record yet: work from the fix commit
./fasttrack.sh cve --unpatched                      # everything the last run left open
     --series 6.18     only this series
     --adapt           also try a 3-way cherry-pick (marked "adapted", for review)
     --package         write a backport work package for what still does not apply
     --claude          work package + run Claude Code on it (implies --adapt)
```

Per series it goes down a ladder and stops at the first rung that works:

1. Not affected, or already fixed at the stable head: nothing to do.
2. Stable-queue backport, applied unchanged.
3. Mainline commit, applied unchanged.
4. 3-way cherry-pick (`--adapt`).
5. A Claude backport in a work package (`--claude`).

Results are written to `out/cve/<ID>/<series>/` (same layout as `patches/`), with a summary in `out/cve-report.md`.

Each result has one outcome: `patched`, `patched-needs-review`, `partial`, `unpatched`, `fixed-in-tree`, `not-affected`, `already-present` or `no-fix-known`. The exit code is 1 while anything is still unpatched.

## Making missing patches with Claude

`out/work/<ID>/<series>/` contains:

- `tree/`: a worktree at the stable head, with every part of the fix that did apply already committed
- `upstream-<sha12>.patch`: the fix that does not apply
- `BRIEF.md`: the CVE description, the conflicting files, and mainline commits on those files that the series lacks (likely prerequisites). It also gives the rules: smallest change, keep upstream logic, one commit per upstream commit with `commit <sha> upstream.` and a `[ Backport: ... ]` note, compile-check touched files, and write `RESULT.md`.

You can use it in two ways:

- **Interactive.** `cd out/work/CVE-…/6.18 && claude`, then ask it to follow BRIEF.md. You stay in the loop.
- **Headless.** `--claude` runs `claude_cmd` from `fasttrack.yaml` (default: `claude -p`, edits allowed, shell limited to git/make/grep/sed/ls/cat). Set `--claude-model` to choose the model.

Either way, the tool then takes Claude's commits and re-verifies the whole series, with no fuzz, on a fresh tree. It marks them `claude-backport` and the outcome `patched-needs-review`. A Claude backport is never mixed into `patches/`. It stays under `cve/` until a human reviews it. In CI it arrives as a PR.

## Automation

`.github/workflows/fasttrack.yml` runs on a self-hosted runner, labelled `fasttrack`, that keeps `/srv/fasttrack` on persistent disk.

- **Hourly:** sync, then `run`. Publishes `patches/`, the report and `unpatched.json` to the `generated` branch. Opens an issue when a pending CVE is actively exploited.
- **Manual dispatch:** takes CVE ids, or `unpatched`, plus an optional fix commit and a Claude toggle. The results open a PR into `generated` for review. Claude in CI needs the `ANTHROPIC_API_KEY` secret.

## Tests

```
python3 -m unittest discover -s tests
```

The tests build a synthetic kernel history covering every verdict and outcome, including a 3-way adapt and a work package completed by a stand-in for `claude`.

## Limits

- **"Applies" is not "correct".** Verification proves textual application on the stable head. Compile and boot testing belong to the consumer. Claude is asked to compile-check, and reports what it could not verify.
- **Prerequisite hints are heuristic.** They list mainline commits on the same files whose subject is not in stable.
- **Claude backports need human review.** Read `RESULT.md` and the `[ Backport: ]` notes before shipping one.
- **`series:` is explicit.** Update it when trunk moves on.
