"""Pull every upstream source into the data directory. Incremental after the first run.

    vulns.git         kernel CNA CVE records (fix commits, per-series fixed-in)
    stable-queue.git  patches queued for the next point release of each series
    linux.git         master (mainline) + linux-X.Y.y for each configured series
    releases.json     kernel.org's latest release per series (staleness check)
    kev.json          CISA known-exploited catalogue (urgency only)

linux.git is fetched shallow by default: history starts right after the release
tag of the oldest tracked series (v6.18 for 6.18 + 7.3). That is enough for
everything the tool does. A CVE fix that landed before vX.Y means X.Y is
unaffected, so every fix it can need is newer than the tag. Nothing needs the
fork point itself: prerequisite hints are "mainline commits before the fix that
the stable branch does not contain", which is a plain ``fix^ ^stable`` range. Set ``shallow: false`` for a full mirror
(~5 GB). Either way, keep the data directory on persistent disk.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
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


log = logging.getLogger(__name__)


def _git(*args: str, cwd: Path | None = None) -> None:
    # Verbose: let git print its clone/fetch progress.
    if log.isEnabledFor(logging.INFO):
        args = tuple(a for a in args if a != "--quiet")
    log.info("$ git %s", " ".join(args))
    t = time.monotonic()
    subprocess.run(["git", *args], cwd=cwd, check=True)
    log.info("git %s: %.1fs", args[2] if args[0] == "-C" else args[0], time.monotonic() - t)


def _sparse_queue(url: str, dest: Path) -> None:
    """stable-queue, but only its queue-X.Y/ directories: the releases/ archive
    of every past patch is ~3 GB and never read."""
    if not (dest / ".git").is_dir():
        _git("clone", "--quiet", "--depth", "1", "--no-checkout", url, str(dest))
    _git("-C", str(dest), "sparse-checkout", "set", "--no-cone", "/queue-*/")
    _git("-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", "HEAD")
    _git("-C", str(dest), "reset", "--quiet", "--hard", "FETCH_HEAD")


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


def shallow_boundary(series: list[str]) -> str:
    """Exclude the oldest series' release tag and everything before it."""
    return oldest_tag(series)


def fetch_linux(linux: Path, url: str, series: list[str], shallow: bool = True,
                mainline: bool = True) -> None:
    """Bare mirror with origin/linux-X.Y.y (and origin/master when ``mainline``).
    First fetch decides depth."""
    fresh = not (linux / "objects").is_dir()
    if fresh:
        _git("init", "--quiet", "--bare", str(linux))
        _git("-C", str(linux), "remote", "add", "origin", url)
    log.info("list heads on %s", url)
    heads = set(subprocess.run(["git", "ls-remote", "--heads", url], capture_output=True, text=True,
                               check=True).stdout.split())
    refspecs = ["+refs/heads/master:refs/remotes/origin/master"] if mainline else []
    for s in series:
        if f"refs/heads/linux-{s}.y" in heads:
            refspecs.append(f"+refs/heads/linux-{s}.y:refs/remotes/origin/linux-{s}.y")
        else:
            # e.g. trunk before its first point release; run/cve skip it until it exists
            print(f"warn: linux-{s}.y not on {url}; skipped")
    if fresh and shallow:
        _git("-C", str(linux), "fetch", "--quiet", "--no-tags",
             f"--shallow-exclude={shallow_boundary(series)}", "origin", *refspecs)
    else:
        _git("-C", str(linux), "fetch", "--quiet", "--prune", "--no-tags", "origin", *refspecs)
    _git("-C", str(linux), "worktree", "prune")


def sync(data: Path, series: list[str], urls: dict | None = None, shallow: bool = True,
         mainline: bool = True, log=print) -> None:
    u = {**DEFAULTS, **(urls or {})}
    data.mkdir(parents=True, exist_ok=True)

    log("==> vulns.git")
    _shallow(u["vulns"], data / "vulns")
    log("==> stable-queue.git")
    _sparse_queue(u["stable_queue"], data / "stable-queue")

    what = (["master"] if mainline else []) + [f"linux-{s}.y" for s in series]
    log(f"==> linux.git ({' + '.join(what)}{', shallow' if shallow else ''})")
    fetch_linux(data / "linux", u["linux"], series, shallow, mainline)

    log("==> feeds")
    _download(u["releases"], data / "releases.json")
    _download(u["kev"], data / "kev.json")
    log(f"==> done: {data}")


def fingerprint(series: list[str], urls: dict | None = None, extra: list[Path] = ()) -> str:
    """Hash of every input that can change a run's result, without cloning:
    vulns and stable-queue heads, the stable branch heads, the KEV and release
    feeds, and the tool's own files (``extra``). Mainline master is left out:
    it moves all the time, and a run reads it only for commits CVE records name."""
    import hashlib

    u = {**DEFAULTS, **(urls or {})}
    h = hashlib.sha256()
    heads = [(u["vulns"], "HEAD"), (u["stable_queue"], "HEAD")] + \
            [(u["linux"], f"refs/heads/linux-{s}.y") for s in series]
    for url, ref in heads:
        out = subprocess.run(["git", "ls-remote", url, ref], capture_output=True, text=True, timeout=120)
        if out.returncode != 0:
            raise RuntimeError(f"git ls-remote {url} {ref}: {out.stderr.strip()}")
        h.update(f"{url} {out.stdout.split()[0] if out.stdout else '-'}\n".encode())
    for url in (u["kev"], u["releases"]):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ksec-fasttrack"})
            with urllib.request.urlopen(req, timeout=60) as r:
                h.update(hashlib.sha256(r.read()).digest())
        except Exception as e:  # a feed that is down does not block the check
            log.warning("%s: %s", url, e)
    for f in sorted(Path(p) for p in extra):
        h.update(f.as_posix().encode() + f.read_bytes())
    return h.hexdigest()
