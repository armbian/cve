"""Pull every upstream source into the data directory. Incremental after the first run.

    vulns.git         kernel CNA CVE records (fix commits, per-series fixed-in)
    stable-queue.git  patches queued for the next point release of each series
    linux.git         master (mainline) + linux-X.Y.y for each configured series
    releases.json     kernel.org's latest release per series (staleness check)
    kev.json          CISA known-exploited catalogue (urgency only)

linux.git is fetched shallow by default: history starts at the release tag of
the oldest tracked series (v6.18 for 6.18 + 7.3). That is enough for everything
the tool does. A CVE fix that landed before vX.Y means X.Y is unaffected, so every
fix it can need is newer than the tag, and the tag commit itself is the fork
point used for prerequisite hints. Set ``shallow: false`` for a full mirror
(~5 GB). Either way, keep the data directory on persistent disk.
"""

from __future__ import annotations

import os
import subprocess
import urllib.request
from pathlib import Path

KORG = "https://git.kernel.org/pub/scm/linux"
DEFAULTS = {
    "vulns": f"{KORG}/security/vulns.git",
    "stable_queue": f"{KORG}/kernel/git/stable/stable-queue.git",
    "linux": f"{KORG}/kernel/git/stable/linux.git",
    "releases": "https://www.kernel.org/releases.json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}


def _git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True)


def _shallow(url: str, dest: Path) -> None:
    if (dest / ".git").is_dir():
        _git("-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", "HEAD")
        _git("-C", str(dest), "reset", "--quiet", "--hard", "FETCH_HEAD")
    else:
        _git("clone", "--quiet", "--depth", "1", url, str(dest))


def _download(url: str, dest: Path) -> bool:
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ksec-fasttrack"})
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as fh:
            fh.write(r.read())
        os.replace(tmp, dest)
        return True
    except Exception as e:  # enrichment only; never fail the sync for it
        print(f"warn: {url}: {e}")
        tmp.unlink(missing_ok=True)
        return False


def oldest_tag(series: list[str]) -> str:
    major, minor = min(tuple(int(x) for x in str(s).split(".")[:2]) for s in series)
    return f"v{major}.{minor}"


def fetch_linux(linux: Path, url: str, series: list[str], shallow: bool = True) -> None:
    """Bare mirror with origin/master and origin/linux-X.Y.y. First fetch decides depth."""
    fresh = not (linux / "objects").is_dir()
    if fresh:
        _git("init", "--quiet", "--bare", str(linux))
        _git("-C", str(linux), "remote", "add", "origin", url)
    heads = set(subprocess.run(["git", "ls-remote", "--heads", url], capture_output=True, text=True,
                               check=True).stdout.split())
    refspecs = ["+refs/heads/master:refs/remotes/origin/master"]
    for s in series:
        if f"refs/heads/linux-{s}.y" in heads:
            refspecs.append(f"+refs/heads/linux-{s}.y:refs/remotes/origin/linux-{s}.y")
        else:
            # e.g. trunk before its first point release; run/cve skip it until it exists
            print(f"warn: linux-{s}.y not on {url}; skipped")
    if fresh and shallow:
        _git("-C", str(linux), "fetch", "--quiet", "--no-tags",
             f"--shallow-exclude={oldest_tag(series)}", "origin", *refspecs)
        # one more commit on every boundary: the release tag commit, i.e. the fork point
        _git("-C", str(linux), "fetch", "--quiet", "--no-tags", "--deepen=1", "origin", *refspecs)
    else:
        _git("-C", str(linux), "fetch", "--quiet", "--prune", "--no-tags", "origin", *refspecs)
    _git("-C", str(linux), "worktree", "prune")


def sync(data: Path, series: list[str], urls: dict | None = None, shallow: bool = True, log=print) -> None:
    u = {**DEFAULTS, **(urls or {})}
    data.mkdir(parents=True, exist_ok=True)

    log("==> vulns.git")
    _shallow(u["vulns"], data / "vulns")
    log("==> stable-queue.git")
    _shallow(u["stable_queue"], data / "stable-queue")

    log(f"==> linux.git (master + {' '.join(series)}{', shallow' if shallow else ''})")
    fetch_linux(data / "linux", u["linux"], series, shallow)

    log("==> feeds")
    _download(u["releases"], data / "releases.json")
    _download(u["kev"], data / "kev.json")
    log(f"==> done: {data}")
