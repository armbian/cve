---
name: contribute
description: Backport open kernel CVEs with the fasttrack tool, review the results with the user, and open a pull request. Use when the user wants to contribute backports to armbian/cve.
---

# Contribute CVE backports

Follow CONTRIBUTING.md. Do the steps for the user. Stop where this file says to ask.

## 1. Check the setup

- Run `command -v claude`. If it fails, tell the user to put `~/.local/bin` on `PATH`. If you are Claude Code yourself, you can do the backports without the CLI: see step 3.
- Run `python3 -c "import yaml"`. If it fails, tell the user to run `pip install pyyaml`. Stop.
- Run `command -v make gcc bison flex bc`. If one is missing, give the user the `apt install` line from CONTRIBUTING.md. Stop.
- Run `git status --short` and `git branch --show-current`. Work from an up-to-date `main` with no local changes. If there are changes, ask the user what to do.
- Run `git pull`. Work packages start from `patches/<series>/`, so it must be current.
- If `data/linux` does not exist, tell the user that `sync` downloads about 5 GB, then run `./fasttrack.sh -v sync` in the background.

## 2. Pick CVEs

- List open CVEs with the command from CONTRIBUTING.md, step 2.
- Also list the rows under "cve/ backport does not apply on this base" in `report.md`. These need `--retry`.
- Remove each CVE that has an open pull request: `gh pr list --state open --search <CVE id>`.
- Show the list to the user. Mark the fixes that are less than three weeks in mainline.
- Ask the user which CVEs to do, and how many. Recommend 3–5. Each one uses $0.30–1.00 of the user's Claude plan.

## 3. Run

Run, in the background:

```
./fasttrack.sh -v cve <CVE ids> --series <series> --claude
```

Use one command per series. Wait for it to finish. Do not edit files in `work/` while it runs.

Without the `claude` CLI, do the run in three steps:

1. `./fasttrack.sh -v cve <CVE ids> --series <series> --package`
2. Do the task in each `work/<CVE>/<series>/BRIEF.md` yourself. Commit in `tree/`, and write `RESULT.md`.
3. `./fasttrack.sh -v cve <CVE ids> --series <series> --collect`

When one backport needs another, collect them one at a time, in that order.

## 4. Review with the user

For each CVE, read `work/<CVE>/<series>/RESULT.md`, the patch in `cve/<CVE>/<series>/`, and the `upstream-*.patch` file.

Give the user, per CVE:

- the result line from the tool,
- what the backport changes, in two or three sentences,
- each difference from upstream, and whether its `[ Backport: ]` reason is correct,
- anything that looks wrong or that you cannot verify.

For "not affected", check the reason in `RESULT.md` against the tree in `work/<CVE>/<series>/tree`. When it is correct, add `"reviewed": "<date>"` and a one-line `"reason"` to its entry in `attempts.json`. The report then shows it as reviewed.

Do not fix a backport by hand. If a backport is wrong, run that CVE again with `--retry`, or leave it out.

Ask the user which CVEs to submit. Submit only the ones the user approves.

## 5. Submit

- Restore the files the hourly job owns: `git checkout -- cve-report.md cve-result.json`.
- Remove the `cve/` directories and `attempts.json` entries for CVEs the user did not approve.
- Make a branch `backports-<user>-<date>`. Stage only `cve/` and `attempts.json`.
- Commit with `git commit -s`. Message: `cve: Claude backports for <N> CVEs on <series>`.
- Show the user the diff summary. Ask before you push.
- Push. Use the user's fork if they cannot push to armbian/cve.
- Open the PR with the label `security`. Keep the text short. Give the CVE ids and results, what was reviewed, open questions, and the boards tested ("none" if none).
- Give the user the PR link.
