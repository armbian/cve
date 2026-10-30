"""Collect candidates per series, verify they apply unchanged, decide.

Channels, in the order they are tried for any given mainline fix:

1. ``stable-queue`` – the stable maintainers' own backport, queued for the
   next point release. Preferred: it is byte-for-byte what will land, so
   expiry is clean when the release arrives.
2. ``mainline``     – cherry-pick of the mainline fix commit, used only when
   the CVE record says the series is affected and unfixed and nothing is
   queued for it.

A candidate is accepted only if ``git apply`` takes it with no fuzz on top
of the stable branch head plus every earlier accepted candidate. Anything
that needs adaptation is reported, never edited.
"""

from __future__ import annotations

import logging
import re
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from . import gitutil
from .queue import QueuedPatch, load_queue
from .vulns import CveRecord

log = logging.getLogger(__name__)

ACCEPTED = "accepted"
PRESENT = "already-present"     # reverse-applies: the tree has it
CONFLICT = "needs-backport"     # does not apply unchanged
MISSING = "commit-missing"      # neither in the mirror nor downloadable
OTHER_ARCH = "other-arch"       # touches only arch/ trees we do not build


@dataclass
class Candidate:
    series: str
    upstream: str
    subject: str
    source: str                         # stable-queue | mainline
    cves: list[str] = field(default_factory=list)
    kev: bool = False
    verdict: str = ""
    reason: str = ""
    filename: str = ""
    files: list[str] = field(default_factory=list)          # touched or conflicting files
    prerequisites: list[str] = field(default_factory=list)  # "sha12 subject" hints
    patch: str = field(default="", repr=False)

    def public(self) -> dict:
        d = asdict(self)
        d.pop("patch")
        return d


@dataclass
class SeriesResult:
    series: str
    head: str
    head_version: str
    upstream_latest: Optional[str]
    candidates: list[Candidate]

    @property
    def accepted(self) -> list[Candidate]:
        return [c for c in self.candidates if c.verdict == ACCEPTED]


def other_arch(files: list[str], arches: Optional[list[str]]) -> bool:
    """True when every file is under arch/<name>/ and no name is in ``arches``."""
    if not arches or not files:
        return False
    return all(f.startswith("arch/") and f.split("/")[1] not in arches for f in files)


def _slug(text: str, n: int = 52) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:n].rstrip("-") or "patch"


def _index_cves(records: Iterable[CveRecord], series: tuple[int, int]):
    """mainline sha → CVE ids, split by whether this series is still exposed."""
    all_fix: dict[str, list[str]] = {}
    unfixed: dict[str, list[str]] = {}
    subjects: dict[str, str] = {}
    for r in records:
        st, _ = r.status(series)
        for sha in r.fix_commits:
            all_fix.setdefault(sha, []).append(r.cve)
            subjects.setdefault(sha, r.title)
            if st == "unfixed":
                unfixed.setdefault(sha, []).append(r.cve)
    return all_fix, unfixed, subjects


def collect(
    series: tuple[int, int],
    records: list[CveRecord],
    queue_root: Optional[Path],
    kev: dict[str, str],
    queue_mode: str = "cve",
) -> list[Candidate]:
    """Ordered candidate list for one series (queue order first, then mainline)."""
    label = f"{series[0]}.{series[1]}"
    all_fix, unfixed, subjects = _index_cves(records, series)
    out: list[Candidate] = []
    seen: set[str] = set()

    queued: list[QueuedPatch] = load_queue(queue_root, series) if queue_root else []
    log.info("%s: %d CVE fix commits, %d unfixed here; %d patches in stable-queue",
             label, len(all_fix), len(unfixed), len(queued))
    for q in queued:
        cves = all_fix.get(q.upstream or "", [])
        is_kev = any(c in kev for c in cves)
        if queue_mode == "cve" and not cves:
            log.debug("%s: queue %s: no CVE, skipped", label, q.file)
            continue
        key = q.upstream or f"queue:{q.file}"
        if key in seen:
            continue
        seen.add(key)
        out.append(Candidate(label, q.upstream or "", q.subject, "stable-queue",
                             sorted(set(cves)), is_kev, patch=q.body))

    for sha, cves in sorted(unfixed.items()):
        if sha in seen:
            continue
        seen.add(sha)
        out.append(Candidate(label, sha, subjects.get(sha, ""), "mainline",
                             sorted(set(cves)), any(c in kev for c in cves)))
    log.info("%s: %d candidates (%d stable-queue, %d mainline)", label, len(out),
             sum(c.source == "stable-queue" for c in out), sum(c.source == "mainline" for c in out))
    # Queue order is dependency order; never reorder it (KEV only raises urgency).
    return out


def verify(repo: Path, ref: str, candidates: list[Candidate], workdir: Optional[Path] = None,
           arches: Optional[list[str]] = None) -> None:
    """Cumulative, no-fuzz replay on top of ``ref``. Sets verdict on each candidate."""
    with tempfile.TemporaryDirectory(prefix="fasttrack-") as tmpd, \
            gitutil.Worktree(repo, ref, Path(tmpd) / "wt") as wt:
        n = 0
        for i, c in enumerate(candidates, 1):
            _verify_one(repo, ref, wt, c, arches)
            if c.verdict == ACCEPTED:
                n += 1
                c.filename = f"{n:04d}-{(c.upstream or 'q')[:12]}-{_slug(c.subject)}.patch"
            log.info("%s [%d/%d] %s %s: %s - %s", c.series, i, len(candidates), (c.upstream or "-")[:12],
                     c.source, c.verdict, c.subject)


def _verify_one(repo: Path, ref: str, wt: gitutil.Worktree, c: Candidate,
                arches: Optional[list[str]] = None) -> None:
    """Sets the verdict of one candidate; applies it to ``wt`` when accepted."""
    if gitutil.in_history(repo, c.upstream, ref):
        c.verdict, c.reason = PRESENT, "fix commit is in the stable history"
        return
    if c.source == "mainline":
        if not c.patch:
            try:
                c.patch = gitutil.upstream_patch(repo, c.upstream)
            except gitutil.GitError as e:
                c.verdict, c.reason = MISSING, str(e)
                return
        c.subject = gitutil.commit_subject(repo, c.upstream, c.patch) or c.subject
    if other_arch(gitutil.patch_files(c.patch), arches):
        c.verdict, c.reason = OTHER_ARCH, "touches only architectures we do not build"
        c.files = gitutil.patch_files(c.patch)
        return
    if wt.check(c.patch, reverse=True) and not wt.check(c.patch):
        c.verdict, c.reason = PRESENT, "change already in tree"
        return
    if not wt.check(c.patch):
        backport = gitutil.stable_backports(repo, ref).get(c.upstream)
        if backport:
            c.verdict, c.reason = PRESENT, f"stable backport {backport[:12]}"
            return
        c.verdict, c.reason = CONFLICT, "does not apply unchanged; needs a manual backport or prerequisite"
        c.files = gitutil.patch_files(c.patch)
        if c.upstream:
            c.prerequisites = gitutil.prerequisite_hints(repo, ref, c.upstream, c.files)
        return
    wt.apply(c.patch)
    c.verdict = ACCEPTED


def _order_mainline(repo: Path, cands: list[Candidate]) -> None:
    """Mainline picks in upstream order, so multi-commit fixes replay as upstream did.
    Commits not in the mirror are downloaded here and ordered by their patch date."""
    when = gitutil.commit_times(repo, [c.upstream for c in cands if c.source == "mainline"])
    for c in cands:
        if c.source == "mainline" and c.upstream not in when:
            try:
                c.patch = gitutil.upstream_patch(repo, c.upstream)
                when[c.upstream] = gitutil.patch_time(c.patch)
            except gitutil.GitError:
                pass                                   # verify() reports it as commit-missing
    cands.sort(key=lambda c: (c.source != "stable-queue",
                              when.get(c.upstream, 1 << 62) if c.source == "mainline" else 0))


def run_series(
    repo: Path,
    series: tuple[int, int],
    records: list[CveRecord],
    queue_root: Optional[Path],
    kev: dict[str, str],
    releases: dict[str, str],
    queue_mode: str = "cve",
    branch_fmt: str = "linux-{s}.y",
    remote: str = "origin",
    arches: Optional[list[str]] = None,
) -> SeriesResult:
    label = f"{series[0]}.{series[1]}"
    branch = branch_fmt.format(s=label)
    ref = gitutil.rev(repo, f"{remote}/{branch}") or gitutil.rev(repo, branch)
    if not ref:
        raise gitutil.GitError(f"no stable branch {branch} in {repo}")
    hv = ".".join(map(str, gitutil.makefile_version(repo, ref)))
    log.info("%s: stable head %s (%s)", label, ref[:12], hv)
    t = time.monotonic()
    cands = collect(series, records, queue_root, kev, queue_mode)
    _order_mainline(repo, cands)
    log.info("%s: verify %d candidates on %s", label, len(cands), ref[:12])
    verify(repo, ref, cands, arches=arches)
    log.info("%s: done in %.0fs", label, time.monotonic() - t)
    return SeriesResult(label, ref, hv, releases.get(label), cands)
