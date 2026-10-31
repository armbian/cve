---
name: contribute
description: Backport open kernel CVEs with the fasttrack tool, review the results with the user, and open a pull request. Use when the user wants to contribute backports to armbian/cve.
---

# Contribute CVE backports

Follow CONTRIBUTING.md. Do the steps for the user. Stop where this file says to ask.

## 1. Check the setup

- Run `command -v claude`. If it fails, tell the user to put `~/.local/bin` on `PATH`. Stop.
- Run `python3 -c "import yaml"`. If it fails, tell the user to run `pip install pyyaml`. Stop.
- Run `command -v make gcc bison flex bc`. If one is missing, give the user the `apt install` line from CONTRIBUTING.md. Stop.
- Run `git status --short` and `git branch --show-current`. Work from an up-to-date `main` with no local changes. If there are changes, ask the user what to do.
- Run `git pull`.
- If `data/linux` does not exist, tell the user that `sync` downloads about 5 GB, then run `./fasttrack.sh -v sync` in the background.

## 2. Pick CVEs

- List open CVEs with the command from CONTRIBUTING.md, step 2.
- Remove each CVE that has an open pull request: `gh pr list --state open --search <CVE id>`.
- Show the list to the user. Mark the fixes that are less than three weeks in mainline.
- Ask the user which CVEs to do, and how many. Recommend 3–5. Each one uses $0.30–1.00 of the user's Claude plan.

## 3. Run

Run, in the background:

```
./fasttrack.sh -v cve <CVE ids> --series <series> --claude
```

Use one command per series. Wait for it to finish. Do not edit files in `work/` while it runs.

## 4. Review with the user

For each CVE, read `work/<CVE>/<series>/RESULT.md`, the patch in `cve/<CVE>/<series>/`, and the `upstream-*.patch` file.

Give the user, per CVE:

- the result line from the tool,
- what the backport changes, in two or three sentences,
- each difference from upstream, and whether its `[ Backport: ]` reason is correct,
- anything that looks wrong or that you cannot verify.

For "not affected", check the reason in `RESULT.md` against the tree in `work/<CVE>/<series>/tree`.

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
