"""Mainline follow-ups the patch sets miss: commits with "Fixes: <sha>" for an
upstream commit a patch in patches/<series>/ carries, that neither the stable
base nor the set has. A backport without its follow-up can ship a bug the
follow-up fixed (an uninitialised variable, a double free)."""
from __future__ import annotations

import re
from pathlib import Path

from . import gitutil

_FIXES = re.compile(r"^Fixes:\s*([0-9a-f]{8,40})", re.M | re.I)


def fixes_index(repo: Path, ref: str, since: str = "2022-01-01") -> dict[str, list[tuple[str, str]]]:
    """sha12 of a fixed commit → [(sha, subject)] of the commits that fix it, on ``ref``."""
    out: dict[str, list[tuple[str, str]]] = {}
    log = gitutil.git(repo, "log", f"--since={since}", "--format=%H%x00%s%x00%b%x01", ref)
    for entry in log.split("\x01"):
        if "\x00" not in entry:
            continue
        sha, subject, body = entry.strip("\n").split("\x00", 2)
        for m in _FIXES.finditer(body):
            out.setdefault(m.group(1)[:12], []).append((sha, subject))
    return out


def _carried(series_dir: Path) -> tuple[dict[str, str], set[str]]:
    """Upstream sha → patch file name, and the subjects, of the patches in a series dir."""
    ups: dict[str, str] = {}
    subjects: set[str] = set()
    for f in sorted(series_dir.glob("*.patch")):
        text = f.read_text(**gitutil.ENC)
        for m in re.finditer(r"^(?:X-Fasttrack-Upstream: |commit )([0-9a-f]{40})(?: upstream)?\s*$", text, re.M):
            ups.setdefault(m.group(1), f.name)
        if m := re.search(r"^Subject: (?:\[[^]]*\] )?(.+)$", text, re.M):
            subjects.add(m.group(1).strip())
    return ups, subjects


def missing(repo: Path, series_dir: Path, base: str, index: dict) -> list[dict]:
    """Follow-ups of the set's upstreams that are not in ``base`` and not in the set.
    A stable copy of a follow-up in ``base`` counts as present (same subject)."""
    ups, subjects = _carried(series_dir)
    base_subjects = None
    rows = []
    for up, patch in ups.items():
        for sha, subject in index.get(up[:12], []):
            if sha in ups or subject in subjects or gitutil.in_history(repo, sha, base):
                continue
            if base_subjects is None:
                base_subjects = set(gitutil.git(repo, "log", "--format=%s", "-n", "20000", base).splitlines())
            if subject in base_subjects:
                continue
            rows.append({"patch": patch, "fixes": up[:12], "followup": sha[:12], "subject": subject})
    return rows
