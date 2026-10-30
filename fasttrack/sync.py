"""Pull every upstream source into the data directory. Incremental after the first run.

    vulns.git         kernel CNA CVE records (fix commits, per-series fixed-in)
    stable-queue.git  patches queued for the next point release of each series
    linux.git         master (mainline) + linux-X.Y.y for each configured series
    releases.json     kernel.org's latest release per series (staleness check)
    kev.json          CISA known-exploited catalogue (urgency only)

linux.git is the big one (~5 GB on first fetch): keep the data directory on
persistent disk.
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


def sync(data: Path, series: list[str], urls: dict | None = None, log=print) -> None:
    u = {**DEFAULTS, **(urls or {})}
    data.mkdir(parents=True, exist_ok=True)

    log("==> vulns.git")
    _shallow(u["vulns"], data / "vulns")
    log("==> stable-queue.git")
    _shallow(u["stable_queue"], data / "stable-queue")

    log(f"==> linux.git (master + {' '.join(series)})")
    linux = data / "linux"
    if not (linux / "objects").is_dir():
        _git("init", "--quiet", "--bare", str(linux))
        _git("-C", str(linux), "remote", "add", "origin", u["linux"])
    refspecs = ["+refs/heads/master:refs/remotes/origin/master"]
    refspecs += [f"+refs/heads/linux-{s}.y:refs/remotes/origin/linux-{s}.y" for s in series]
    _git("-C", str(linux), "fetch", "--quiet", "--prune", "--no-tags", "origin", *refspecs)
    _git("-C", str(linux), "worktree", "prune")

    log("==> feeds")
    _download(u["releases"], data / "releases.json")
    _download(u["kev"], data / "kev.json")
    log(f"==> done: {data}")
