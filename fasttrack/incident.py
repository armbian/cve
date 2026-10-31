"""Specific security incidents: resolve, and backport with Claude when nothing applies.

For one incident (a CVE id, or bare fix commits for something not yet in
vulns.git) and one series, the ladder is:

1. not affected / already fixed in the stable head        → nothing to do
2. stable-queue backport, applied unchanged               → ``accepted``
3. mainline commit, applied unchanged                     → ``accepted``
4. backport posted to the stable list, applied unchanged  → ``accepted``
5. mainline commit, 3-way cherry-pick (``--adapt``)       → ``adapted``  (review)
6. otherwise                                              → ``needs-backport``

For step 6 a *work package* is written: a git worktree at the stable head
with every resolved part of the fix already committed, the upstream patch,
the files that conflict, mainline commits the series lacks on those files,
and BRIEF.md. You can ``cd`` there and run ``claude`` yourself, or pass
``--claude`` to run it headless. Claude's commits are then re-verified as a
series on a fresh tree and marked ``claude-backport`` — always for review,
never treated like an upstream patch.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import build, gitutil
from .engine import ACCEPTED, CONFLICT, MISSING, PRESENT, Candidate, _slug, start_builder
from .queue import load_queue
from .vulns import CveRecord, parse_version

log = logging.getLogger(__name__)

ADAPTED = "adapted"
CLAUDE = "claude-backport"
NOT_HERE = "not-in-tree"        # work package found the vulnerable code absent
PATCH_VERDICTS = (ACCEPTED, ADAPTED, CLAUDE)

DEFAULT_CLAUDE_CMD = [
    "claude", "-p",
    "--permission-mode", "acceptEdits",
    "--allowedTools", "Read", "Edit", "Write", "Grep", "Glob",
    "Bash(git:*)", "Bash(make:*)", "Bash(grep:*)", "Bash(sed:*)", "Bash(ls:*)", "Bash(cat:*)",
    "--max-turns", "80",
    "--output-format", "json",
]


@dataclass
class Resolution:
    cve: str
    series: str
    head: str
    head_version: str
    status: str                       # unfixed | fixed-in | unaffected | unknown (no record)
    fixed_in: Optional[str]
    title: str = ""
    description: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    work_dir: Optional[str] = None
    note: str = ""

    @property
    def patches(self) -> list[Candidate]:
        return [c for c in self.candidates if c.verdict in PATCH_VERDICTS]

    @property
    def outcome(self) -> str:
        if self.status == "unaffected":
            return "not-affected"
        if self.status == "fixed-in" and not self.candidates:
            return "fixed-in-tree"
        if not self.candidates:
            return "no-fix-known"
        v = {c.verdict for c in self.candidates}
        if v & {CONFLICT, MISSING}:
            return "partial" if self.patches else "unpatched"
        if CLAUDE in v or ADAPTED in v:
            return "patched-needs-review"
        if NOT_HERE in v:
            return "not-affected-needs-review"
        if v == {PRESENT}:
            return "already-present"
        return "patched"

    def public(self) -> dict:
        d = asdict(self)
        d["candidates"] = [c.public() for c in self.candidates]
        d["outcome"] = self.outcome
        return d


def _stable_ref(repo: Path, label: str, remote: str, branch_fmt: str) -> str:
    branch = branch_fmt.format(s=label)
    ref = gitutil.rev(repo, f"{remote}/{branch}") or gitutil.rev(repo, branch)
    if not ref:
        raise gitutil.GitError(f"no stable branch {branch} in {repo}")
    return ref


def _commit_order(repo: Path, shas: list[str]) -> list[str]:
    when = gitutil.commit_times(repo, shas)
    for s in shas:
        if s not in when:
            try:
                when[s] = gitutil.patch_time(gitutil.upstream_patch(repo, s))
            except gitutil.GitError:
                pass
    return sorted(shas, key=lambda s: when.get(s, 1 << 62))


def resolve(
    repo: Path,
    series: tuple[int, int],
    cve: str,
    fix_commits: list[str],
    record: Optional[CveRecord],
    queue_root: Optional[Path],
    adapt: bool = False,
    remote: str = "origin",
    branch_fmt: str = "linux-{s}.y",
    stable_list: Optional[Callable[[str, str], list[str]]] = None,
    builder=None,
) -> Resolution:
    label = f"{series[0]}.{series[1]}"
    ref = _stable_ref(repo, label, remote, branch_fmt)
    hv = ".".join(map(str, gitutil.makefile_version(repo, ref)))
    status, fixed = record.status(series) if record else ("unknown", None)
    res = Resolution(cve, label, ref, hv, status,
                     ".".join(map(str, fixed[:3])) if fixed else None,
                     record.title if record else "", record.description if record else "")
    log.info("%s %s: stable head %s (%s), record status %s%s, %d fix commit(s)", cve, label, ref[:12], hv,
             status, f" {res.fixed_in}" if res.fixed_in else "", len(fix_commits))
    if status == "unaffected":
        return res
    if status == "fixed-in" and parse_version(hv) >= fixed:
        return res
    if not fix_commits:
        res.note = "no fix commit known; pass --commit when one exists"
        return res
    if status == "fixed-in":
        res.note = f"fixed upstream in {res.fixed_in}, newer than the mirrored {hv}; generating ahead of sync"

    queued = {q.upstream: q for q in (load_queue(queue_root, series) if queue_root else []) if q.upstream}
    for sha in _commit_order(repo, fix_commits):
        q = queued.get(sha)
        if q:
            res.candidates.append(Candidate(label, sha, q.subject, "stable-queue", [cve], patch=q.body))
        else:
            res.candidates.append(Candidate(label, sha, "", "mainline", [cve]))

    with tempfile.TemporaryDirectory(prefix="fasttrack-cve-") as tmpd, \
            gitutil.Worktree(repo, ref, Path(tmpd) / "wt") as wt:
        b = start_builder(builder, wt.path, Path(tmpd) / "out")
        n = 0
        for c in res.candidates:
            have = gitutil.present(repo, c.upstream)
            if gitutil.in_history(repo, c.upstream, ref):
                c.verdict, c.reason = PRESENT, "fix commit is in the stable history"
                continue
            if c.source == "mainline":
                try:
                    c.patch = gitutil.upstream_patch(repo, c.upstream)
                except gitutil.GitError as e:
                    c.verdict, c.reason = MISSING, f"{e}; check the SHA"
                    continue
                c.subject = gitutil.commit_subject(repo, c.upstream, c.patch)
            if wt.check(c.patch, reverse=True) and not wt.check(c.patch):
                c.verdict, c.reason = PRESENT, "change already in tree"
                continue
            if wt.check(c.patch):
                wt.apply(c.patch)
                wt.commit(c.subject)
                c.verdict = ACCEPTED
            elif gitutil.stable_backports(repo, ref).get(c.upstream):
                c.verdict, c.reason = PRESENT, f"stable backport {gitutil.stable_backports(repo, ref)[c.upstream][:12]}"
                continue
            elif stable_list and _take_posted(stable_list(c.upstream, label), wt, c):
                pass
            elif adapt:
                if not have or gitutil.is_boundary(repo, c.upstream):
                    ok, conflicts = wt.apply3(c.patch, f"{c.subject}\n\ncommit {c.upstream} upstream.")
                else:
                    ok, conflicts = wt.cherry_pick(c.upstream)
                if ok:
                    c.patch = gitutil.format_patch(wt.path, "HEAD")
                    c.verdict, c.reason = ADAPTED, "3-way merged against older context; review before use"
                else:
                    c.verdict, c.reason, c.files = CONFLICT, "3-way merge conflicts", conflicts
            else:
                c.verdict, c.reason = CONFLICT, "does not apply unchanged"
            if b and c.verdict in (ACCEPTED, ADAPTED):
                c.build_log = b.regressions([c.patch], build.worktree_flip(wt.path))
                if c.build_log:
                    gitutil.git(wt.path, "reset", "--quiet", "--hard", "HEAD~1")
                    c.verdict, c.reason, c.files = CONFLICT, "applies but does not build", []
            if c.verdict == CONFLICT:
                c.files = c.files or gitutil.patch_files(c.patch)
                c.prerequisites = gitutil.prerequisite_hints(repo, ref, c.upstream, c.files)
                continue
            n += 1
            c.filename = f"{n:04d}-{c.upstream[:12]}-{_slug(c.subject)}.patch"
    for c in res.candidates:
        log.info("%s %s: %s %s: %s - %s", cve, label, c.upstream[:12], c.source, c.verdict, c.subject)
    return res


def _take_posted(posts: list[str], wt: gitutil.Worktree, c: Candidate) -> bool:
    """Apply the newest posted backport that applies unchanged."""
    for body in posts:
        if wt.check(body):
            wt.apply(body)
            wt.commit(f"{c.subject}\n\ncommit {c.upstream} upstream.")
            c.patch, c.source = body, "stable-list"
            c.verdict, c.reason = ACCEPTED, "backport posted to stable@vger.kernel.org"
            return True
    return False


# --------------------------------------------------------------------------- work packages

BRIEF = """\
# Backport {cve} to Linux {series}

{title}

{description}

## Where you are

`./tree` is a git worktree of `linux-{series}.y` at `{head12}` (Linux {version}).
{resolved}
## What does not apply

{failing}

## Your task

1. Make the smallest change in `./tree` that fixes the same bug the upstream commit
   fixes. Keep upstream's logic, naming and error handling; adapt only to the older
   surrounding code. Read the upstream patch file(s) in this directory first.
2. Prefer adapting the fix over pulling prerequisites. If a prerequisite is genuinely
   required and small, cherry-pick it as its own commit with `git cherry-pick -x`.
3. Commit in `./tree`, one commit per upstream commit, keeping the upstream subject
   and author (`git commit --author=...`). Put this at the top of the body:

       commit <full 40-character upstream sha> upstream.

       [ Backport: <one line per difference from upstream, and why> ]

4. Compile-check what you touched, from `./tree`: `make allmodconfig && make prepare`,
   then `make <path>/<file>.o` for each changed `.c` file. The tool rejects a
   backport whose changed `.c` files do not build with x86 allmodconfig.
5. Touch nothing outside `./tree` except `RESULT.md` here. In RESULT.md write what
   you changed, why it is equivalent to upstream, and what you could not verify.

If the vulnerable code does not exist in this tree, make no commit and start RESULT.md
with the line `Not affected`, then explain why.
"""


def prepare_work(repo: Path, res: Resolution, work_root: Path) -> Path:
    """Persistent work package for a resolution that has unpatched parts."""
    wdir = work_root / res.cve / res.series
    tree = wdir / "tree"
    if tree.exists():
        gitutil.git(repo, "worktree", "remove", "--force", str(tree), check=False)
    wdir.mkdir(parents=True, exist_ok=True)
    gitutil.git(repo, "worktree", "add", "--detach", "--quiet", str(tree), res.head)
    for c in res.patches:
        gitutil.git(tree, "apply", "--index", input=c.patch)
        gitutil.git(tree, "commit", "--quiet", "--no-verify", "-m", c.subject or c.upstream)
    start = gitutil.rev(tree, "HEAD")
    (wdir / "start").write_text(start + "\n")

    failing = []
    for c in res.candidates:
        if c.verdict not in (CONFLICT, MISSING):
            continue
        lines = [f"### `{c.upstream[:12]}` {c.subject}", "", f"Reason: {c.reason}."]
        if c.upstream:
            up = wdir / f"upstream-{c.upstream[:12]}.patch"
            try:
                up.write_text(gitutil.upstream_patch(repo, c.upstream), **gitutil.ENC)
            except gitutil.GitError:
                pass
            lines.append(f"Upstream patch: `{up.name}`")
        if c.files:
            lines.append("Files: " + ", ".join(f"`{f}`" for f in c.files))
        if c.build_log:
            lines += ["", "It applies, but these files do not build:", "", "```", c.build_log, "```"]
        if c.prerequisites:
            lines += ["", f"Mainline commits on these files that {res.series} does not have "
                          "(possible prerequisites, oldest first):", ""]
            lines += [f"- `{p}`" for p in c.prerequisites]
        failing.append("\n".join(lines))
    errlog = wdir / "build-errors.log"
    if errlog.exists():
        failing.append("### An earlier backport in this package did not build\n\n"
                       "```\n" + errlog.read_text(**gitutil.ENC).strip() + "\n```")
    resolved = ""
    if res.patches:
        resolved = "\nAlready committed on top (parts of this fix that applied):\n\n" + \
                   "\n".join(f"- `{c.upstream[:12]}` {c.subject} ({c.verdict})" for c in res.patches) + "\n"
    (wdir / "BRIEF.md").write_text(BRIEF.format(
        cve=res.cve, series=res.series, title=res.title, description=res.description or "",
        head12=res.head[:12], version=res.head_version, resolved=resolved,
        failing="\n\n".join(failing) or "(nothing)"))
    res.work_dir = str(wdir)
    log.info("%s %s: work package %s", res.cve, res.series, wdir)
    return wdir


def run_claude(wdir: Path, cmd: Optional[list[str]] = None, timeout: int = 3600) -> int:
    """Run Claude Code headless in the work package. Output goes to claude.log."""
    cmd = list(cmd or DEFAULT_CLAUDE_CMD)
    prompt = (wdir / "BRIEF.md").read_text()
    log.info("$ %s <BRIEF.md (log: %s)", " ".join(shlex.quote(a) for a in cmd), wdir / "claude.log")
    t = time.monotonic()
    rc = _claude(wdir, cmd, prompt, timeout)
    log.info("claude exited %d after %.0fs", rc, time.monotonic() - t)
    return rc


def _claude(wdir: Path, cmd: list[str], prompt: str, timeout: int) -> int:
    with open(wdir / "claude.log", "w") as log:
        log.write("$ " + " ".join(shlex.quote(a) for a in cmd) + " <BRIEF.md\n\n")
        log.flush()
        try:
            proc = subprocess.run(cmd + [prompt], cwd=wdir, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=timeout, stdin=subprocess.DEVNULL)
            return proc.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\n[timed out after {timeout}s]\n")
            return 124
        except FileNotFoundError:
            log.write(f"\n[{cmd[0]} not found]\n")
            return 127


def claude_cost(wdir: Path) -> Optional[float]:
    """total_cost_usd from the JSON result in claude.log (--output-format json)."""
    log_file = wdir / "claude.log"
    if not log_file.exists():
        return None
    for line in reversed(log_file.read_text(**gitutil.ENC).splitlines()):
        if line.startswith("{"):
            try:
                cost = json.loads(line).get("total_cost_usd")
            except ValueError:
                continue
            if isinstance(cost, (int, float)):
                log.info("%s: claude cost $%.2f", wdir, cost)
                return float(cost)
    return None


def collect_work(repo: Path, res: Resolution, wdir: Path, builder=None) -> None:
    """Pick up commits made in the work package and re-verify the whole set.
    With ``builder``, a set that does not build is rejected; the errors go to
    build-errors.log, which the next BRIEF.md shows."""
    tree = wdir / "tree"
    start = (wdir / "start").read_text().strip()
    shas = gitutil.git(tree, "rev-list", "--reverse", f"{start}..HEAD", check=False).split()
    log.info("%s %s: %d commit(s) from the work package", res.cve, res.series, len(shas))
    if not shas:
        result = wdir / "RESULT.md"
        head = result.read_text(**gitutil.ENC)[:300].lower() if result.exists() else ""
        if "not affected" in head:
            for c in res.candidates:
                if c.verdict in (CONFLICT, MISSING):
                    c.verdict, c.reason = NOT_HERE, "vulnerable code not in this tree (work package); see RESULT.md"
            res.note = (res.note + " " if res.note else "") + "not affected per work package; review RESULT.md"
            return
        res.note = (res.note + " " if res.note else "") + "no backport commits in work package; see RESULT.md"
        return
    new = []
    for sha in shas:
        subj = gitutil.git(tree, "log", "-1", "--format=%s", sha).strip()
        body = gitutil.git(tree, "log", "-1", "--format=%B", sha)
        up = _upstream_of(body, res.candidates)
        new.append(Candidate(res.series, up, subj, "claude", [res.cve], verdict=CLAUDE,
                             reason="backport made in work package; review before use",
                             patch=gitutil.format_patch(tree, sha)))
    # Fresh tree, whole series, no fuzz: the same bar as everything else.
    with tempfile.TemporaryDirectory(prefix="fasttrack-recheck-") as tmpd, \
            gitutil.Worktree(repo, res.head, Path(tmpd) / "wt") as wt:
        broken = False
        for c in res.patches + new:
            if broken or not wt.check(c.patch):
                broken = True
                c.verdict, c.reason = CONFLICT, "work-package series does not apply on a clean tree"
                log.info("%s %s: %s does not apply on a clean tree", res.cve, res.series, c.subject)
                continue
            wt.apply(c.patch)
        b = None if broken else start_builder(builder, wt.path, Path(tmpd) / "out")
        err = b.regressions([c.patch for c in new], build.worktree_flip(wt.path)) if b else ""
    errlog = wdir / "build-errors.log"
    if err:
        errlog.write_text(err, **gitutil.ENC)
        for c in new:
            c.verdict, c.reason, c.build_log = CONFLICT, "work-package backport does not build", err
        log.info("%s %s: work-package backport does not build", res.cve, res.series)
    elif b:
        errlog.unlink(missing_ok=True)
    for c in res.candidates:
        if c.verdict in (CONFLICT, MISSING) and any(n.upstream == c.upstream for n in new if n.verdict == CLAUDE):
            c.verdict, c.reason = "superseded", "replaced by work-package backport"
    res.candidates += new
    n = 0
    for c in res.patches:
        n += 1
        c.filename = f"{n:04d}-{(c.upstream or c.source)[:12]}-{_slug(c.subject)}.patch"


_CITE = re.compile(r"^(?:commit ([0-9a-f]{7,40}) upstream|\[ Upstream commit ([0-9a-f]{7,40}) \])", re.M)


def _upstream_of(body: str, candidates: list[Candidate]) -> str:
    """Full upstream sha a work-package commit cites; short shas are matched
    against the incident's fix commits."""
    for a, b in _CITE.findall(body):
        cited = a or b
        full = next((c.upstream for c in candidates if c.upstream and c.upstream.startswith(cited)), "")
        return full or (cited if len(cited) == 40 else "")
    return ""


def load_unpatched(path: Path) -> dict[str, list[str]]:
    """CVE id → fix commits, from the unpatched.json a ``run`` writes."""
    out: dict[str, list[str]] = {}
    if path.exists():
        for row in json.loads(path.read_text()):
            for cve in row.get("cves", []):
                out.setdefault(cve, [])
                if row.get("upstream") and row["upstream"] not in out[cve]:
                    out[cve].append(row["upstream"])
    return out


def prune(repo: Path, cve_root: Path, remote: str = "origin", branch_fmt: str = "linux-{s}.y") -> list[str]:
    """Delete incident patch sets that the current stable head no longer needs.

    A set is retired when every patch in it reverse-applies on the stable head
    (stable shipped the same change) or the head is at or past the version the
    CVE record says carries the fix. Returns "ID series: reason" for each removal.
    """
    import shutil

    removed: list[str] = []
    if not cve_root.is_dir():
        return removed
    with tempfile.TemporaryDirectory(prefix="fasttrack-prune-") as tmpd, contextlib.ExitStack() as stack:
        trees: dict[str, gitutil.Worktree] = {}       # checks only: one tree per stable head
        for sdir in sorted(p for p in cve_root.glob("*/*") if p.is_dir()):
            cid, label = sdir.parent.name, sdir.name
            try:
                ref = _stable_ref(repo, label, remote, branch_fmt)
            except gitutil.GitError:
                log.info("prune %s %s: no stable branch, kept", cid, label)
                continue                                   # series no longer tracked/synced: leave it alone
            meta = sdir / "fasttrack.json"
            patches = [sdir / n for n in _series_names(sdir)]
            reason = ""
            if meta.exists():
                fixed = json.loads(meta.read_text()).get("fixed_in")
                hv = ".".join(map(str, gitutil.makefile_version(repo, ref)))
                if fixed and parse_version(hv) >= parse_version(fixed):
                    reason = f"stable {hv} carries the fix (fixed in {fixed})"
            if not reason and patches:
                if ref not in trees:
                    trees[ref] = stack.enter_context(gitutil.Worktree(repo, ref, Path(tmpd) / ref[:12]))
                # reverse the whole series, newest first: all present means absorbed
                if all(trees[ref].check(p.read_text(**gitutil.ENC), reverse=True) for p in reversed(patches)):
                    reason = "stable head already contains every patch"
            log.info("prune %s %s: %s", cid, label, reason or "still needed")
            if reason:
                shutil.rmtree(sdir)
                removed.append(f"{cid} {label}: {reason}")
            if sdir.parent.is_dir() and not any(sdir.parent.iterdir()):
                sdir.parent.rmdir()
    return removed


def _series_names(d: Path) -> list[str]:
    sc = d / "series.conf"
    if not sc.exists():
        return sorted(p.name for p in d.glob("*.patch"))
    return [l.strip() for l in sc.read_text().splitlines() if l.strip() and not l.startswith("#")]
