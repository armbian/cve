# Contribute backports with your own Claude

Some kernel security fixes do not apply to our stable kernels. Claude Code can backport them. You can help by running Claude Code on your own subscription. Each backport arrives as a pull request for review.

## What you need

- Linux, about 10 GB of free disk space.
- [Claude Code](https://docs.claude.com/en/docs/claude-code), logged in. `claude` must be on your `PATH`.
- Python 3 with PyYAML: `pip install pyyaml`.
- Kernel build tools. On Debian or Ubuntu:

  ```
  sudo apt install build-essential bc bison flex libelf-dev libssl-dev dwarves
  ```

## Cost and time

One CVE takes 1–3 minutes. It uses about $0.30–1.00 of Claude usage, which counts against your plan's limits. When Claude has nothing to do, nothing is used.

## 1. Set up (once)

```
git clone https://github.com/armbian/cve.git
cd cve
./fasttrack.sh -v sync
```

`sync` downloads the kernel sources and the CVE data, about 5 GB. The first time takes a while. Later runs fetch only what is new.

## 2. Pick CVEs

Get the newest list of open issues:

```
git pull
```

List the CVEs that Claude has not tried yet:

```
python3 -c '
import json
done = json.load(open("attempts.json"))
todo = {(c, r["series"]) for r in json.load(open("unpatched.json")) for c in r["cves"]}
for c, s in sorted(todo):
    if s not in done.get(c, {}):
        print(c, s)
'
```

Pick a few. Prefer fixes that have been in mainline for three weeks or more. Stable often takes newer fixes by itself. Before you start, search the [open pull requests](https://github.com/armbian/cve/pulls) for each CVE id. Then you do not do the same work as someone else.

## 3. Run Claude

```
./fasttrack.sh -v cve CVE-2026-12345 CVE-2026-23456 --series 6.18 --claude
```

For each CVE, the tool:

1. makes a work package in `work/<CVE>/<series>/`: a kernel tree, the upstream patch and `BRIEF.md`;
2. runs Claude Code in it, without a prompt from you;
3. checks that Claude's commits apply on a clean tree and build with x86 `allmodconfig`.

The last output line per CVE gives the result:

| Result | Meaning |
|---|---|
| `patched-needs-review` | Claude made a backport. It applies and builds. |
| `not-affected-needs-review` | Claude found that the bug is not in this kernel. |
| `unpatched` | No usable backport. Read `RESULT.md` and `build-errors.log` in the work package. |

To try a CVE again, add `--retry`.

## 4. Review

For each result, read these files in `work/<CVE>/<series>/`:

- `RESULT.md`: what Claude changed, and what it could not verify.
- The patch in `cve/<CVE>/<series>/`. Compare it with the `upstream-*.patch` file. Each difference must have a reason in a `[ Backport: ]` line.

For "not affected", make sure the reason in `RESULT.md` is correct.

Do not submit a backport that you do not understand. Leave it out of the PR, or say what you are unsure about in the PR text.

## 5. Submit

Commit only `cve/` and `attempts.json`. The hourly job writes the other files.

```
git checkout -b backports-<your-name>
git checkout -- cve-report.md cve-result.json 2>/dev/null
git add cve attempts.json
git commit -s -m "cve: Claude backports for <N> CVEs on 6.18"
git push -u origin backports-<your-name>
```

Without write access to armbian/cve, push the branch to your fork.

Open a pull request with the label `security`. In the text, give:

- the CVE ids and the result for each,
- what you reviewed, and anything you are unsure about,
- the boards you tested on, if any.

The `build-test` workflow builds each patch on arm64, arm, riscv and x86. A maintainer reviews and merges.

## Help

- `./fasttrack.sh cve --help` lists all options.
- `README.md` explains how the tool works.
- `claude: not found` means `claude` is not on your `PATH`. Claude Code installs it in `~/.local/bin`.
