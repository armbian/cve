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

import concurrent.futures
import json
import logging
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from . import build, gitutil
from .queue import QueuedPatch, load_queue
from .vulns import CveRecord

log = logging.getLogger(__name__)

ACCEPTED = "accepted"
PRESENT = "already-present"     # reverse-applies: the tree has it
CONFLICT = "needs-backport"     # does not apply unchanged
MISSING = "commit-missing"      # neither in the mirror nor downloadable
OTHER_ARCH = "other-arch"       # touches only arch/ trees we do not build
BACKPORTED = "backported"       # a reviewed backport from cve/ carries it
SUPERSEDED = "superseded"       # cve/ backport not needed: the fix applies or is in tree


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
    build_log: str = ""                                     # compiler errors the patch brings in
    backport: str = ""                                      # cve/<ID>/<series> this patch comes from
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
           arches: Optional[list[str]] = None, builder=None) -> None:
    """Cumulative, no-fuzz replay on top of ``ref``. Sets verdict on each candidate.
    ``builder(tree, out)`` makes a :class:`build.Builder` for the compile check:
    one parallel build of the accepted series. A patch that breaks the build is
    rejected and the series replayed without it."""
    with tempfile.TemporaryDirectory(prefix="fasttrack-") as tmpd, \
            gitutil.Worktree(repo, ref, Path(tmpd) / "wt") as wt, \
            concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        warm = pool.submit(gitutil.stable_backports, repo, ref)   # history grep, while make prepares
        b = start_builder(builder, wt.path, Path(tmpd) / "out")
        warm.result()
        rejected: dict[int, str] = {}                              # id(candidate) → build errors
        broken: set[str] = set()                                   # backport sets that do not apply whole
        while True:
            for c in candidates:
                if id(c) in rejected:
                    c.verdict, c.reason = CONFLICT, "applies unchanged but does not build; needs a backport or prerequisite"
                    c.build_log, c.files = rejected[id(c)], gitutil.patch_files(c.patch)
                elif c.backport in broken:
                    c.verdict, c.reason = CONFLICT, f"another patch of {c.backport} does not apply or build"
                elif c.backport and _superseded(c, candidates):
                    c.verdict, c.reason = SUPERSEDED, "the mainline fix applies unchanged or is in tree"
                else:
                    _verify_one(repo, ref, wt, c, arches)
            # A backport set goes in whole or not at all.
            sets = {c.backport for c in candidates
                    if c.backport and (c.verdict == CONFLICT or id(c) in rejected)} - broken
            if sets:
                broken |= sets
                gitutil.git(wt.path, "reset", "--quiet", "--hard", ref)
                continue
            accepted = [c for c in candidates if c.verdict == ACCEPTED]
            bad = b.batch_regressions([c.patch for c in accepted], build.worktree_flip(wt.path)) if b else {}
            if not bad:
                break
            for i, err in bad.items():
                rejected[id(accepted[i])] = err
                log.info("%s %s: applies but does not build", accepted[i].series, accepted[i].upstream[:12])
            gitutil.git(wt.path, "reset", "--quiet", "--hard", ref)
        # A mainline fix that a backport carries is not pending.
        carried = {c.upstream for c in candidates if c.backport and c.verdict == ACCEPTED}
        for c in candidates:
            if not c.backport and c.verdict == CONFLICT and c.upstream in carried:
                c.verdict, c.reason = BACKPORTED, "carried by a reviewed backport from cve/"
        # Hints read only history, not the tree: in parallel.
        conflicts = [c for c in candidates if c.verdict == CONFLICT and c.upstream and not c.backport]
        for c, hints in zip(conflicts, pool.map(
                lambda c: gitutil.prerequisite_hints(repo, ref, c.upstream, c.files), conflicts)):
            c.prerequisites = hints
        n = 0
        for i, c in enumerate(candidates, 1):
            if c.verdict == ACCEPTED:
                n += 1
                c.filename = f"{n:04d}-{(c.upstream or 'q')[:12]}-{_slug(c.subject)}.patch"
            log.info("%s [%d/%d] %s %s: %s - %s", c.series, i, len(candidates), (c.upstream or "-")[:12],
                     c.source, c.verdict, c.subject)


def _superseded(c: Candidate, candidates: list[Candidate]) -> bool:
    """True when every mainline fix that ``c``'s backport set carries applies or is in tree."""
    ups = {x.upstream for x in candidates if x.backport == c.backport}
    fixes = [x for x in candidates if not x.backport and x.upstream in ups]
    return bool(fixes) and all(x.verdict in (ACCEPTED, PRESENT, OTHER_ARCH) for x in fixes)


def load_backports(cve_root: Path, series: str) -> list[Candidate]:
    """Reviewed backports in cve/<ID>/<series>/. On main they passed review."""
    out = []
    # Oldest first: a backport made later was built on top of the earlier ones.
    metas = [(json.loads(f.read_text()), f.parent) for f in cve_root.glob(f"*/{series}/fasttrack.json")]
    for meta, d in sorted(metas, key=lambda m: (m[0].get("made") or "", m[1].parent.name)):
        for p in meta.get("patches", []):
            f = d / p["filename"]
            if not f.exists():
                continue
            # Drop the provenance header that emit wrote; emit writes it again.
            body = re.sub(r"^X-Fasttrack-[^\n]*\n", "", f.read_text(encoding="utf-8", errors="surrogateescape"),
                          count=8, flags=re.M)
            out.append(Candidate(series, p.get("upstream", ""), p.get("subject", ""), p.get("source", "backport"),
                                 cves=p.get("cves", []), kev=p.get("kev", False),
                                 backport=f"{d.parent.name}/{series}", patch=body))
    return out


def start_builder(builder, tree: Path, out: Path):
    """Prepared builder, or None when there is none or it cannot prepare."""
    if not builder:
        return None
    b = builder(tree, out)
    try:
        b.prepare()
    except (build.BuildError, OSError, subprocess.SubprocessError) as e:
        log.warning("build check off: %s", e)
        return None
    return b


def _verify_one(repo: Path, ref: str, wt: gitutil.Worktree, c: Candidate,
                arches: Optional[list[str]] = None) -> None:
    """Sets the verdict of one candidate; applies it to ``wt`` when accepted.
    Prerequisite hints and the build check are left to :func:`verify`."""
    c.reason, c.build_log, c.files, c.prerequisites = "", "", [], []
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
    builder=None,
    cve_root: Optional[Path] = None,
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
    # Reviewed backports go after the clean picks: one patch set per series.
    if cve_root and cve_root.is_dir():
        cands += load_backports(cve_root, label)
    log.info("%s: verify %d candidates on %s", label, len(cands), ref[:12])
    verify(repo, ref, cands, arches=arches, builder=builder)
    log.info("%s: done in %.0fs", label, time.monotonic() - t)
    return SeriesResult(label, ref, hv, releases.get(label), cands)
