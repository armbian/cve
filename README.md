<h2 align="center">
  <a href=#><img src="https://raw.githubusercontent.com/armbian/.github/master/profile/logosmall.png" alt="Armbian logo"></a>
  <br><br>
</h2>

# Armbian Kernel Security Fixes

> [!TIP]
> **Contribute with Claude.** Paste this prompt into Claude Code:
>
> ```
> get https://github.com/armbian/cve and contribute
> ```

## Purpose of This Repository

An automatic backporting service for kernel security fixes. It targets the older LTS kernels **6.18**, **6.12** and **6.1**, and the newest stable, **7.3** — closing the gap between the moment a CVE is public and the moment a stable point release carries the fix.

## How it works

`patches/<series>/` holds every known fix that the stable branch does not have yet:

- Each fix applies cleanly on the stable head, and the whole set builds.
- A fix that does not apply is backported with [Claude Code](https://docs.claude.com/en/docs/claude-code). A human reviews the backport in `cve/<CVE>/<series>/`.
- A fix leaves the folder the moment the stable branch carries it (either the CVE record declares a `fixed-in` version at or below the head, or the patch reverse-applies on the head).

Nothing accumulates: `patches/` is rebuilt from scratch on every run.

## Design in one picture

![Armbian kernel security fixes workflow](docs/images/workflow.png)

## Usage

Apply the patches in `series.conf` order on the commit in `base`.

Check whether a CVE is covered, and if not, why:

```sh
./fasttrack.sh why CVE-2026-1234
```

It needs no `sync`; without a local CVE feed it reads the record from CVE.org.

### Other commands

```sh
./fasttrack.sh sync                         # pull kernel + CVE sources
./fasttrack.sh run                          # gather + verify; writes patches/ and report.md
./fasttrack.sh cve CVE-2026-1234            # resolve a specific incident
./fasttrack.sh cve --unpatched --claude     # backport every open issue with Claude
```

See `./fasttrack.sh --help` for all options.

## Repository layout

| Path | Contents |
|---|---|
| `patches/<series>/` | Verified fixes for a kernel series: `series.conf`, `base`, numbered `.patch` files and `fasttrack.json` provenance |
| `cve/<CVE>/<series>/` | Reviewed per-incident backports (same layout), included into `patches/` on the next run |
| `fasttrack/` | The Python backport tool (`python3 -m fasttrack.cli`) |
| `scripts/` | Helper scripts, including `build-test.sh` used by CI |
| `tests/` | Unit tests for the fasttrack tool |
| `docs/` | Documentation assets |
| `fasttrack.sh` | Thin wrapper that runs `python3 -m fasttrack.cli` |
| `report.md` | Latest gather-and-verify report, per series |
| `cve-report.md` | Latest per-incident resolution report |
| `unpatched.json`, `cves.json`, `attempts.json` | Machine-readable state consumed by the tool |

## Requirements

For contributors running the tool locally:

- Linux with about 10 GB of free disk space
- Python 3 with [PyYAML](https://pyyaml.org/)
- Kernel build tools (Debian/Ubuntu: `build-essential bc bison flex libelf-dev libssl-dev dwarves`)
- [Claude Code](https://docs.claude.com/en/docs/claude-code) on `PATH`, if you want to produce backports

The tool itself is written in **Python 3**; the convenience wrapper `fasttrack.sh` and `scripts/build-test.sh` are **Bash**. CI workflows are **GitHub Actions YAML**.

## Continuous integration

A scheduled job (every 15 minutes) pulls fresh upstream data, gathers and verifies patches, and commits changes back to `main`. On-demand runs let Claude Code backport specific CVEs and open a pull request. Every patch series is compile-tested on `arm64`, `arm`, `riscv` and `x86` with `allmodconfig`.

For the live status of all workflows in this repository, see the Armbian CI overview:

<https://actions.armbian.com/?repo=cve>

## More

- Latest series report: [report.md](report.md)
- Latest incident resolution: [cve-report.md](cve-report.md)
- Contribute by hand: [CONTRIBUTING.md](CONTRIBUTING.md) · Internals: [DEVELOPMENT.md](DEVELOPMENT.md)
- Armbian project: <https://www.armbian.com> · Documentation: <https://docs.armbian.com>
