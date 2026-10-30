"""Thin wrappers around git. Everything shells out; no libgit2 dependency."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Optional


class GitError(RuntimeError):
    pass


# Commits made inside scratch worktrees need an identity even on a bare runner.
_ENV = dict(os.environ)
for _k, _v in (("GIT_AUTHOR_NAME", "ksec-fasttrack"), ("GIT_AUTHOR_EMAIL", "fasttrack@localhost"),
               ("GIT_COMMITTER_NAME", "ksec-fasttrack"), ("GIT_COMMITTER_EMAIL", "fasttrack@localhost")):
    _ENV.setdefault(_k, _v)


def git(repo: Path, *args: str, check: bool = True, input: Optional[str] = None) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        input=input,
        env=_ENV,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def ok(repo: Path, *args: str, input: Optional[str] = None) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        input=input,
        env=_ENV,
    ).returncode == 0


def rev(repo: Path, ref: str) -> Optional[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    return out.stdout.strip() or None


_MK = {k: re.compile(rf"^{k}\s*=\s*(\S*)", re.M) for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL")}


def makefile_version(repo: Path, ref: str) -> tuple[int, int, int]:
    """Kernel version at ``ref``, read from the top-level Makefile."""
    body = git(repo, "show", f"{ref}:Makefile")
    vals = []
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
        m = _MK[key].search(body)
        vals.append(int(m.group(1)) if m and m.group(1).isdigit() else 0)
    return tuple(vals)  # type: ignore[return-value]


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

    def cherry_pick(self, sha: str) -> tuple[bool, list[str]]:
        """3-way cherry-pick with full history. Returns (ok, conflicting files)."""
        if ok(self.path, "cherry-pick", "-x", sha):
            return True, []
        files = git(self.path, "diff", "--name-only", "--diff-filter=U", check=False).split()
        git(self.path, "cherry-pick", "--abort", check=False)
        return False, files


def files_in(repo: Path, sha: str) -> list[str]:
    return git(repo, "show", "--name-only", "--format=", sha).split()


def prerequisite_hints(repo: Path, stable_ref: str, sha: str, files: list[str], limit: int = 15) -> list[str]:
    """Mainline commits touching ``files`` between the series fork point and ``sha``
    whose subject is not in the stable branch: the usual reason a fix will not apply."""
    if not files:
        return []
    base = git(repo, "merge-base", stable_ref, sha, check=False).strip()
    if not base:
        return []
    mainline = git(repo, "log", "--no-merges", "--format=%H%x09%s", f"{base}..{sha}^", "--", *files,
                   check=False).splitlines()
    in_stable = set(git(repo, "log", "--no-merges", "--format=%s", f"{base}..{stable_ref}", "--", *files,
                        check=False).splitlines())
    out = []
    for line in reversed(mainline):              # oldest first: apply order
        h, _, subj = line.partition("\t")
        if subj not in in_stable:
            out.append(f"{h[:12]} {subj}")
    return out[:limit]
