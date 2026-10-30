"""Thin wrappers around git. Everything shells out; no libgit2 dependency."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class GitError(RuntimeError):
    pass


# Commits made inside scratch worktrees need an identity even on a bare runner.
_ENV = dict(os.environ)
for _k, _v in (("GIT_AUTHOR_NAME", "ksec-fasttrack"), ("GIT_AUTHOR_EMAIL", "fasttrack@localhost"),
               ("GIT_COMMITTER_NAME", "ksec-fasttrack"), ("GIT_COMMITTER_EMAIL", "fasttrack@localhost")):
    _ENV.setdefault(_k, _v)


# Patches may contain bytes that are not UTF-8 (old commit messages, binary diffs).
# surrogateescape carries them through str unchanged; every file write uses it too.
ENC = {"encoding": "utf-8", "errors": "surrogateescape"}


def _run(repo: Path, args: tuple, input: Optional[str] = None) -> subprocess.CompletedProcess:
    t = time.monotonic()
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, input=input, env=_ENV, **ENC)
    log.debug("git %s -> %d (%.2fs)", " ".join(args), proc.returncode, time.monotonic() - t)
    return proc


def git(repo: Path, *args: str, check: bool = True, input: Optional[str] = None) -> str:
    proc = _run(repo, args, input)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def ok(repo: Path, *args: str, input: Optional[str] = None) -> bool:
    return _run(repo, args, input).returncode == 0


def rev(repo: Path, ref: str) -> Optional[str]:
    return _run(repo, ("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")).stdout.strip() or None


_MK = {k: re.compile(rf"^{k}\s*=\s*(\S*)", re.M) for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL")}


def makefile_version(repo: Path, ref: str) -> tuple[int, int, int]:
    """Kernel version at ``ref``, read from the top-level Makefile."""
    body = git(repo, "show", f"{ref}:Makefile")
    vals = []
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
        m = _MK[key].search(body)
        vals.append(int(m.group(1)) if m and m.group(1).isdigit() else 0)
    return tuple(vals)  # type: ignore[return-value]


# Where to get a commit's patch when its parent is not in the shallow mirror.
PATCH_URLS = [
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={sha}",
    "https://github.com/torvalds/linux/commit/{sha}.patch",
]


def present(repo: Path, sha: str) -> bool:
    return rev(repo, sha) is not None


def in_history(repo: Path, sha: str, ref: str) -> bool:
    """True when ``sha`` is an ancestor of ``ref``: the tree has that exact commit."""
    return bool(sha) and present(repo, sha) and ok(repo, "merge-base", "--is-ancestor", sha, ref)


_SUBJ = re.compile(r"^Subject:\s*(?:\[[^\]]*\]\s*)?(.+(?:\n[ \t].+)*)", re.M)
_DATE = re.compile(r"^Date:\s*(.+)$", re.M)


def commit_subject(repo: Path, sha: str, patch: str = "") -> str:
    if present(repo, sha):
        return git(repo, "log", "-1", "--format=%s", sha).strip()
    m = _SUBJ.search(patch)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def commit_times(repo: Path, shas: list[str]) -> dict[str, int]:
    """Commit time for local commits (via stdin: thousands of SHAs are fine)."""
    local = [s for s in shas if present(repo, s)]
    out: dict[str, int] = {}
    if local:
        for line in git(repo, "log", "--no-walk=unsorted", "--stdin", "--format=%H %ct",
                        input="\n".join(local) + "\n").splitlines():
            h, _, t = line.partition(" ")
            if t.isdigit():
                out[h] = int(t)
    return out


def patch_time(patch: str) -> int:
    import email.utils
    m = _DATE.search(patch)
    try:
        return int(email.utils.parsedate_to_datetime(m.group(1)).timestamp()) if m else 1 << 62
    except (TypeError, ValueError):
        return 1 << 62


def is_boundary(repo: Path, sha: str) -> bool:
    """True when ``sha`` sits on the shallow cut: its parent object is not here,
    so a local diff would be against an empty tree (the whole kernel)."""
    body = git(repo, "cat-file", "-p", sha, check=False)
    parents = [l.split()[1] for l in body.splitlines() if l.startswith("parent ")]
    if not parents:
        return bool(body)                         # a true root commit: no useful diff either
    return not ok(repo, "cat-file", "-e", f"{parents[0]}^{{commit}}")


def _fetch_patch(sha: str) -> Optional[str]:
    import urllib.request
    for tmpl in PATCH_URLS:
        url = tmpl.format(sha=sha)
        log.info("download %s", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ksec-fasttrack"})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read().decode(**ENC)
            if "\ndiff --git " in body:
                return body
            log.info("download %s: not a patch", url)
        except Exception as e:
            log.info("download %s: %s", url, e)
    return None


def upstream_patch(repo: Path, sha: str) -> str:
    """The upstream commit as an mbox patch: from the mirror when it has the commit
    and its parent, otherwise downloaded (cached next to the mirror). The second
    case covers mainline fixes newer than every mirrored stable branch, and
    commits on a shallow cut."""
    if present(repo, sha) and not is_boundary(repo, sha):
        return format_patch(repo, sha)
    cache = Path(repo) / "fasttrack-patches" / f"{sha}.patch"
    if cache.exists():
        return cache.read_text(**ENC)
    body = _fetch_patch(sha)
    if body is None:
        raise GitError(f"{sha[:12]} is on the shallow boundary and its patch could not be downloaded")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(body, **ENC)
    return body


def format_patch(repo: Path, sha: str) -> str:
    """Single commit as an mbox patch, stable across runs (no signature, fixed From line)."""
    return git(repo, "format-patch", "-1", "--stdout", "--no-signature", "--zero-commit", sha)


class Worktree:
    """Disposable detached worktree at ``ref``; removed on exit."""

    def __init__(self, repo: Path, ref: str, path: Path):
        self.repo, self.ref, self.path = repo, ref, path

    def __enter__(self) -> "Worktree":
        if self.path.exists():
            git(self.repo, "worktree", "remove", "--force", str(self.path), check=False)
        git(self.repo, "worktree", "add", "--detach", "--quiet", str(self.path), self.ref)
        return self

    def __exit__(self, *exc) -> None:
        git(self.repo, "worktree", "remove", "--force", str(self.path), check=False)

    def check(self, patch: str, reverse: bool = False) -> bool:
        args = ["apply", "--check"] + (["-R"] if reverse else [])
        return ok(self.path, *args, input=patch)

    def apply(self, patch: str) -> None:
        git(self.path, "apply", "--index", input=patch)

    def commit(self, message: str) -> None:
        git(self.path, "commit", "--quiet", "--no-verify", "-m", message or "fasttrack")

    def apply3(self, patch: str, message: str) -> tuple[bool, list[str]]:
        """3-way apply of a patch (for commits whose parent is not in the mirror)."""
        if ok(self.path, "apply", "-3", "--index", input=patch):
            self.commit(message)
            return True, []
        files = git(self.path, "diff", "--name-only", "--diff-filter=U", check=False).split()
        git(self.path, "reset", "--quiet", "--hard", check=False)
        return False, files

    def cherry_pick(self, sha: str) -> tuple[bool, list[str]]:
        """3-way cherry-pick with full history. Returns (ok, conflicting files)."""
        if ok(self.path, "cherry-pick", "-x", sha):
            return True, []
        files = git(self.path, "diff", "--name-only", "--diff-filter=U", check=False).split()
        git(self.path, "cherry-pick", "--abort", check=False)
        return False, files


_DIFF_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)


def patch_files(patch: str) -> list[str]:
    """Files a patch touches, in order, from its diff headers."""
    out: list[str] = []
    for a, b in _DIFF_FILE.findall(patch):
        for f in (a, b):
            if f not in out:
                out.append(f)
    return out


def files_in(repo: Path, sha: str) -> list[str]:
    """Files a commit touches. Read from its real patch, because on the shallow
    boundary `git show --name-only` would list the entire tree."""
    return patch_files(upstream_patch(repo, sha))


def prerequisite_hints(repo: Path, stable_ref: str, sha: str, files: list[str], limit: int = 15) -> list[str]:
    """Mainline commits touching ``files`` that precede ``sha`` and are not in the
    stable branch, oldest first: the usual reason a fix will not apply.

    ``sha^ ^stable`` needs no merge-base, so it works on a mirror cut at the
    release tag. Stable carries backports under different SHAs, so subjects that
    also appear on stable since the fork are filtered out as well."""
    if not files or not present(repo, sha) or is_boundary(repo, sha):
        return []                                  # no parent here: nothing before it to list
    mainline = git(repo, "log", "--no-merges", "--format=%H%x09%s", f"{sha}^", f"^{stable_ref}",
                   "--", *files, check=False).splitlines()
    in_stable = set(git(repo, "log", "--no-merges", "--format=%s", stable_ref, f"^{sha}",
                        "--", *files, check=False).splitlines())
    out = []
    for line in reversed(mainline):
        h, _, subj = line.partition("\t")
        if subj not in in_stable:
            out.append(f"{h[:12]} {subj}")
    return out[:limit]
