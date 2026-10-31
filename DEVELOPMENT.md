# Development

How the tool works. For what the repository gives, see [README.md](README.md).

## Quick start

```
./fasttrack.sh sync                         # pull sources; linux.git is shallow from v<oldest series>
./fasttrack.sh run                          # gather + verify; see report.md
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

`linux.git` is a **full clone of [armbian/linux](https://github.com/armbian/linux)** (about
4 GB). It mirrors linux-stable, with `master` and the `linux-X.Y.y` branches, and its heads
match kernel.org. Full history means every fix commit has its parent, so patches come
straight from git. `shallow: true` is still available; it cuts history at the oldest
series' release tag. Fixes that sit on that cut are then downloaded as patches from
git.kernel.org. A configured series with no stable branch yet
(trunk before its first point release) is skipped with a warning.

## `run`: gather, verify, list

Writes to the repository itself (`out: .`), and CI commits the result:

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
| `backported` | does not apply unchanged; a reviewed backport from `cve/` in the set carries it |
| `superseded` | a `cve/` backport that is not needed: the fix applies unchanged or is in tree |

`run` adapts nothing itself. The patch set holds upstream patches unchanged, then the reviewed backports from `cve/`.

### Patches retire themselves

Nothing accumulates. `patches/<series>/` is rebuilt from scratch on every run, so a
fix drops out as soon as the stable head carries it, in either of two ways:

- **The CVE record says so:** it lists a fixed-in version at or below the stable head.
- **The stable tree shows it:** the patch reverse-applies on the stable head. This catches fixes
  that shipped while the CVE record still lags.

A series directory with nothing left is deleted. `report.md` records each drop as a
`retired` event.

`fasttrack prune` does the same for incident results under `cve/<ID>/<series>/`. It runs
hourly in CI, and a set is deleted once every patch in it reverse-applies on the stable
head, or once the head reaches the version that carries the fix.

## `cve`: specific incidents

```
./fasttrack.sh cve CVE-2026-1234 CVE-2026-5678     # by id
./fasttrack.sh cve --commit <sha> --id my-incident  # no CVE record yet: work from the fix commit
./fasttrack.sh cve --unpatched                      # everything the last run left open
     --series 6.18     only this series
     --adapt           also try a 3-way cherry-pick (marked "adapted", for review)
     --package         write a backport work package for what still does not apply
     --claude          work package + run Claude Code on it (implies --adapt)
     --retry           run Claude again where attempts.json already has a result
```

Per series it goes down a ladder and stops at the first rung that works:

1. Not affected, or already fixed at the stable head: nothing to do.
2. Stable-queue backport, applied unchanged.
3. Mainline commit, applied unchanged.
4. A backport the author posted to the stable mailing list, applied unchanged (`stable_list: true`).
5. 3-way cherry-pick (`--adapt`).
6. A Claude backport in a work package (`--claude`). With `--unpatched`, only for fixes
   older than `claude_min_age_days` (default 21): stable usually takes newer ones itself.

Results are written to `cve/<ID>/<series>/` (same layout as `patches/`), with a summary in `cve-report.md`.

Each result has one outcome: `patched`, `patched-needs-review`, `partial`, `unpatched`, `fixed-in-tree`, `not-affected`, `already-present` or `no-fix-known`. The exit code is 1 while anything is still unpatched.

## Making missing patches with Claude

`work/<ID>/<series>/` contains:

- `tree/`: a worktree at the stable head, with every part of the fix that did apply already committed
- `upstream-<sha12>.patch`: the fix that does not apply
- `BRIEF.md`: the CVE description, the conflicting files, and mainline commits on those files that the series lacks (likely prerequisites). It also gives the rules: smallest change, keep upstream logic, one commit per upstream commit with `commit <sha> upstream.` and a `[ Backport: ... ]` note, compile-check touched files, and write `RESULT.md`.

You can use it in two ways:

- **Interactive.** `cd work/CVE-…/6.18 && claude`, then ask it to follow BRIEF.md. You stay in the loop.
- **Headless.** `--claude` runs `claude_cmd` from `fasttrack.yaml` (default: `claude -p`, edits allowed, shell limited to git/make/grep/sed/ls/cat). Set `--claude-model` to choose the model.

`attempts.json` on `main` records every Claude run: date, outcome and cost. A CVE that Claude already tried is skipped, so a rerun of `--unpatched` pays only for new issues. Pass `--retry` to run it again.

Either way, the tool then takes Claude's commits and re-verifies the whole series, with no fuzz, on a fresh tree. It marks them `claude-backport` and the outcome `patched-needs-review`. A Claude backport arrives as a PR into `cve/`. A human reviews it there.

Once merged, the next `run` adds it to `patches/<series>/`, after the clean mainline picks. It is verified with the whole set, and it is all-or-nothing per `cve/` directory. `X-Fasttrack-Backport` names its source directory. A backport is left out when:

- the mainline fix now applies unchanged or is in tree. `report.md` counts it as no longer needed, and `prune` deletes it.
- it does not apply or build on top of the set. `report.md` lists it, and the fix shows as open again. Make it again with `--retry`.

## Automation

`.github/workflows/fasttrack.yml` runs on a standard GitHub-hosted runner by default. No special runner or persistent disk is needed.

- **Cache:** `data/` (the shallow `linux.git`, `vulns.git`, `stable-queue.git`) lives in the Actions cache. A fresh cache entry is made each ISO week, and between those every run starts from the last entry and fetches only what is new. Changing `fasttrack.yaml` starts a new cache.
- **Change check, every 15 minutes:** `fasttrack fingerprint` hashes the heads of `vulns.git`, `stable-queue.git` and the stable branches, the KEV and release feeds, and the tool's own files. It takes a few seconds. A full run starts only for a new hash.
- **Full run:** sync, `run`, then `prune`. Changes to `patches/`, `cve/` deletions, `report.md`, `unpatched.json`, `state.json` and `events.json` go to `main` through a PR that the bot merges itself. A run with nothing new commits nothing. Opens an issue labelled `security` when a pending CVE is actively exploited.
- **Release:** when a full run changes `patches/`, the job tags `patches-YYYYMMDD-HHMM`. The release notes list the fixes per series (`fasttrack release-notes`). Each series is attached as `armbian-cve-<series>-<tag>.tar.gz`.
- **Runners:** repo variable `FASTTRACK_RUNNER` moves the full run to a self-hosted runner label, `BUILDTEST_RUNNER` the build test. Use a fixed runner for the full run, so `data/` stays on disk.
- **Manual dispatch:** takes CVE ids, or `unpatched`, plus an optional fix commit and a Claude toggle. Results go to `cve/` on a branch, with a PR into `main` for review. Claude in CI needs the `ANTHROPIC_API_KEY` secret.

## Build test

With `build_check: x86` in `fasttrack.yaml`, `run` and `cve` build the `.c` files each patch changes, with `allmodconfig`. A file that does not build even without the patch is not counted. A patch that applies but does not build is `needs-backport`, and its compiler errors go into BRIEF.md. A Claude backport that does not build is rejected. Its errors go to `build-errors.log` in the work package, and the next BRIEF.md shows them. Pass `--no-build` to skip the check.

`scripts/build-test.sh <arm64|arm|riscv|x86> [series dir ...]` applies each series on its stable base. It builds the changed `.c` files with `allmodconfig` and reports errors and new warnings. The `build-test` workflow runs it for each architecture on PRs and merges that change `cve/` or `patches/`. Logs are in the job artifacts.

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
