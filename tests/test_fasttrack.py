"""End-to-end tests on a synthetic kernel history.

    master:        base ─ A ─ B ─ C ─ D ─ E                (fixes for CVE-1..4, 6)
    linux-6.18.y:  base ─ rework(baz, adapt) ─ B' ─ "Linux 6.18.2"

    CVE-1  A  unfixed, applies unchanged              → mainline pick
    CVE-2  B  fixed in 6.18.2 (= head)                → nothing to do
    CVE-3  C  unfixed, stable reworked the same lines → needs backport (Claude case)
    CVE-4  D  unfixed, queued in stable-queue         → stable-queue patch
    CVE-5  -  fixed in mainline 6.17                  → not affected
    CVE-6  E  unfixed, context differs nearby         → strict: needs backport; --adapt: 3-way ok
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from fasttrack import build, cli, emit, engine, incident, sync, vulns
from fasttrack.queue import load_queue


def sh(cwd, *args, input=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, input=input).stdout


def sh_bytes(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True).stdout


def commit(repo, msg, **files):
    for name, body in files.items():
        (repo / name).write_text(body)
    sh(repo, "git", "add", "-A")
    sh(repo, "git", "commit", "-q", "-m", msg)
    return sh(repo, "git", "rev-parse", "HEAD").strip()


def makefile(sub):
    return f"VERSION = 6\nPATCHLEVEL = 18\nSUBLEVEL = {sub}\nEXTRAVERSION =\n"


def lines(tag, n=12):
    return "".join(f"{tag} line {i}\n" for i in range(n))


def fix(tag, *subs):
    body = lines(tag)
    for a, b in subs:
        body = body.replace(a, b)
    return body


AFFECTED = [{"version": "5.10", "status": "affected"},
            {"version": "0", "lessThan": "5.10", "status": "unaffected", "versionType": "semver"},
            {"version": "6.19-rc3", "lessThanOrEqual": "*", "status": "unaffected",
             "versionType": "original_commit_for_fix"}]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        r = self.repo = self.tmp / "linux"
        r.mkdir()
        sh(r, "git", "init", "-q", "-b", "master")
        sh(r, "git", "config", "user.email", "t@t")
        sh(r, "git", "config", "user.name", "t")
        self.rc1 = commit(r, "Linux 6.18-rc1", Makefile=makefile(0))
        base = commit(r, "base", Makefile=makefile(0), **{f"{t}.c": lines(t) for t in
                                                         ("foo", "bar", "baz", "qux", "adapt")})
        self.A = commit(r, "foo: fix overflow", **{"foo.c": fix("foo", ("foo line 6", "foo line 6 FIXED"))})
        self.B = commit(r, "bar: fix uaf", **{"bar.c": fix("bar", ("bar line 6", "bar line 6 FIXED"))})
        self.C = commit(r, "baz: fix race", **{"baz.c": fix("baz", ("baz line 6", "baz line 6 FIXED"))})
        self.D = commit(r, "qux: fix leak", **{"qux.c": fix("qux", ("qux line 6", "qux line 6 FIXED"))})
        self.E = commit(r, "adapt: fix bounds", **{"adapt.c": fix("adapt", ("adapt line 6", "adapt line 6 FIXED"))})

        sh(r, "git", "checkout", "-q", "-b", "linux-6.18.y", base)
        commit(r, "stable-only rework", **{
            "baz.c": fix("baz", ("baz line 5", "baz line 5 REWORKED"), ("baz line 6", "baz line 6 REWORKED")),
            "adapt.c": fix("adapt", ("adapt line 3", "adapt line 3 STABLE"))})
        sh(r, "git", "cherry-pick", self.B)
        commit(r, "Linux 6.18.2", Makefile=makefile(2))
        sh(r, "git", "checkout", "-q", "master")

        q = self.tmp / "data" / "stable-queue" / "queue-6.18"
        q.mkdir(parents=True)
        patch_d = sh(r, "git", "format-patch", "-1", "--stdout", self.D)
        (q / "qux-fix-leak.patch").write_text(patch_d.replace("\n\n", f"\n\ncommit {self.D} upstream.\n\n", 1))
        (q / "unrelated.patch").write_text("Subject: [PATCH] misc: tidy\n\ncommit " + "e" * 40 + " upstream.\n")
        (q / "series").write_text("qux-fix-leak.patch\nunrelated.patch\n")

        pub = self.tmp / "data" / "vulns" / "cve" / "published" / "2026"
        pub.mkdir(parents=True)

        def rec(cve, sha, versions):
            body = {"cveMetadata": {"cveId": cve}, "containers": {"cna": {
                "title": cve + " title", "descriptions": [{"lang": "en", "value": cve + " description"}],
                "affected": [{"product": "Linux", "vendor": "Linux", "versions": versions}]}}}
            (pub / f"{cve}.json").write_text(json.dumps(body))
            (pub / f"{cve}.sha1").write_text(sha + "\n")

        rec("CVE-2026-0001", self.A, AFFECTED)
        rec("CVE-2026-0002", self.B, AFFECTED + [
            {"version": "6.18.2", "lessThanOrEqual": "6.18.*", "status": "unaffected", "versionType": "semver"}])
        rec("CVE-2026-0003", self.C, AFFECTED)
        rec("CVE-2026-0004", self.D, AFFECTED)
        rec("CVE-2026-0005", "f" * 40, [{"version": "5.10", "status": "affected"},
                                        {"version": "6.17", "lessThanOrEqual": "*", "status": "unaffected",
                                         "versionType": "original_commit_for_fix"}])
        rec("CVE-2026-0006", self.E, AFFECTED)
        self.data = self.tmp / "data"
        self.records = list(vulns.iter_records(self.data / "vulns"))

        # the data layout `fasttrack sync` produces: bare mirror with remote-tracking refs
        sh(self.tmp, "git", "clone", "-q", "--bare", str(r), str(self.data / "linux"))
        sh(self.tmp, "git", "-C", str(self.data / "linux"), "fetch", "-q", str(r),
           "+refs/heads/master:refs/remotes/origin/master",
           "+refs/heads/linux-6.18.y:refs/remotes/origin/linux-6.18.y")
        self.cfg = self.tmp / "fasttrack.yaml"
        self.out = self.tmp / "out"
        self.cfg.write_text(f"series: ['6.18']\ndata: {self.data}\nout: {self.out}\ncve_since_year: 2020\n")

    def run_618(self, kev=None, mode="cve"):
        return engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue",
                                 kev or {}, {"6.18": "6.18.2"}, queue_mode=mode, remote="none")

    def resolve(self, cve, adapt=False, commits=None):
        rec = vulns.find(self.data / "vulns", cve)
        return incident.resolve(self.data / "linux", (6, 18), cve, commits or (rec.fix_commits if rec else []),
                                rec, self.data / "stable-queue", adapt=adapt)


class TestVulns(Fixture):
    def test_status_per_series(self):
        by = {r.cve: r for r in self.records}
        self.assertEqual(by["CVE-2026-0001"].status((6, 18))[0], "unfixed")
        self.assertEqual(by["CVE-2026-0002"].status((6, 18)), ("fixed-in", (6, 18, 2, 99)))
        self.assertEqual(by["CVE-2026-0005"].status((6, 18))[0], "unaffected")
        self.assertEqual(by["CVE-2026-0001"].status((5, 4))[0], "unaffected")
        self.assertEqual(by["CVE-2026-0001"].status((7, 3))[0], "unaffected")
        self.assertEqual(by["CVE-2026-0001"].description, "CVE-2026-0001 description")

    def test_split_entries(self):
        # Real records: git ranges first, the mainline fix version in a second entry.
        p = self.tmp / "CVE-2024-26670.json"
        p.write_text(json.dumps({"containers": {"cna": {"affected": [
            {"product": "Linux", "versions": [
                {"version": "a" * 40, "lessThan": "b" * 40, "status": "affected", "versionType": "git"},
                {"version": "6.1.57", "lessThan": "6.2", "status": "affected", "versionType": "semver"}]},
            {"product": "Linux", "versions": [
                {"version": "6.6", "status": "affected"},
                {"version": "6.8", "lessThanOrEqual": "*", "status": "unaffected",
                 "versionType": "original_commit_for_fix"}]}]}}}))
        self.assertEqual(vulns.parse_record(p).status((6, 18))[0], "unaffected")

    def test_stable_backport_by_reference(self):
        # stable carries C under its own content; only the message names C
        sh(self.repo, "git", "checkout", "-q", "linux-6.18.y")
        commit(self.repo, f"baz: fix race\n\ncommit {self.C} upstream.",
               **{"baz.c": fix("baz", ("baz line 5", "baz line 5 REWORKED"), ("baz line 6", "baz line 6 OWN FIX"))})
        sh(self.repo, "git", "checkout", "-q", "master")
        c = {c.upstream: c for c in self.run_618().candidates}[self.C]
        self.assertEqual(c.verdict, engine.PRESENT)
        self.assertIn("stable backport", c.reason)

    def test_other_arch(self):
        arches = ["arm", "arm64", "riscv", "x86"]
        self.assertTrue(engine.other_arch(["arch/s390/kernel/a.c", "arch/parisc/b.c"], arches))
        self.assertFalse(engine.other_arch(["arch/s390/a.c", "mm/b.c"], arches))
        self.assertFalse(engine.other_arch(["arch/arm64/a.c"], arches))
        self.assertFalse(engine.other_arch(["arch/s390/a.c"], None))

    def test_claude_cost(self):
        (self.tmp / "claude.log").write_text('$ claude -p\n\n{"type": "result", "total_cost_usd": 1.234}\n')
        self.assertAlmostEqual(incident.claude_cost(self.tmp), 1.234)

    def test_find(self):
        self.assertEqual(vulns.find(self.data / "vulns", "cve-2026-0003").fix_commits, [self.C])
        self.assertIsNone(vulns.find(self.data / "vulns", "CVE-2026-9999"))


class TestQueue(Fixture):
    def test_upstream_marker(self):
        q = load_queue(self.data / "stable-queue", (6, 18))
        self.assertEqual([p.upstream for p in q], [self.D, "e" * 40])
        self.assertEqual(q[0].subject, "qux: fix leak")


class TestRun(Fixture):
    def test_verdicts(self):
        res = self.run_618()
        v = {c.upstream: (c.source, c.verdict) for c in res.candidates}
        self.assertEqual(v[self.D], ("stable-queue", engine.ACCEPTED))
        self.assertEqual(v[self.A], ("mainline", engine.ACCEPTED))
        self.assertEqual(v[self.C], ("mainline", engine.CONFLICT))
        self.assertEqual(v[self.E], ("mainline", engine.CONFLICT))      # strict: no fuzz, no 3-way
        self.assertNotIn(self.B, v)
        self.assertNotIn("e" * 40, v)
        self.assertEqual([c.upstream for c in res.accepted], [self.D, self.A])

    def test_already_present(self):
        sh(self.repo, "git", "checkout", "-q", "linux-6.18.y")
        sh(self.repo, "git", "cherry-pick", self.A)
        sh(self.repo, "git", "checkout", "-q", "master")
        self.assertEqual({c.upstream: c.verdict for c in self.run_618().candidates}[self.A], engine.PRESENT)

    def test_queue_mode_all(self):
        q = [c for c in self.run_618(mode="all").candidates if c.source == "stable-queue"]
        self.assertEqual([c.verdict for c in q], [engine.ACCEPTED, engine.CONFLICT])

    def test_cli_run_writes_patches_and_unpatched_list(self):
        self.assertEqual(cli.main(["--config", str(self.cfg), "run"]), 0)
        d = self.out / "patches" / "6.18"
        series = [l for l in (d / "series.conf").read_text().splitlines() if l and not l.startswith("#")]
        self.assertEqual(len(series), 2)
        unp = json.loads((self.out / "unpatched.json").read_text())
        self.assertEqual(sorted(u["cves"][0] for u in unp), ["CVE-2026-0003", "CVE-2026-0006"])
        self.assertIn("baz.c", next(u for u in unp if u["upstream"] == self.C)["files"])
        # emitted files, provenance headers included, apply in order with plain git
        base = (d / "base").read_text().strip()
        wt = self.tmp / "wt"
        sh(self.repo, "git", "worktree", "add", "-q", "--detach", str(wt), base)
        for name in series:
            sh(wt, "git", "apply", str(d / name))
        self.assertIn("FIXED", (wt / "foo.c").read_text())

    def test_output_is_deterministic(self):
        cli.main(["--config", str(self.cfg), "run"])
        d = self.out / "patches" / "6.18"
        first = {p.name: p.read_text() for p in d.iterdir()}
        cli.main(["--config", str(self.cfg), "run"])
        self.assertEqual(first, {p.name: p.read_text() for p in d.iterdir()})

    def test_release_notes(self):
        res = self.run_618(kev={"CVE-2026-0004": "x"})
        emit.write_series_dir(self.out, res)
        md = emit.release_notes(self.out, ["added 6.18: 2 patch(es)"], "Patches 2026-10-31")
        self.assertIn("# Patches 2026-10-31", md)
        self.assertIn("- added 6.18: 2 patch(es)", md)
        self.assertIn(f"## 6.18 (base 6.18.2, {len(res.accepted)} fixes)", md)
        self.assertIn("CVE-2026-0004 🔥 KEV", md)
        self.assertIn(f"`{self.A[:12]}`", md)

    def test_events(self):
        res = self.run_618(kev={"CVE-2026-0004": "x"})
        state, events = emit.diff_state({"series": {"6.18": {"version": "6.18.1", "accepted": [self.A]}}}, [res])
        self.assertIn("new-stable 6.18: 6.18.1 → 6.18.2", events)
        self.assertTrue(any("CVE-2026-0004" in e for e in events))
        self.assertEqual(emit.diff_state(state, [res])[1], [])

    def test_report_groups(self):
        c = engine.Candidate("6.18", "a" * 40, "fix foo", "mainline", ["CVE-2026-0009"], verdict=engine.CONFLICT)
        res = engine.SeriesResult("6.18", "b" * 40, "6.18.2", None, [c])
        self.assertIn("Needs a backport (1)", emit.report([res], []))
        md = emit.report([res], [], {"CVE-2026-0009": {"6.18": {"outcome": "not-affected-needs-review"}}})
        self.assertIn("Not affected per work package (needs review) (1)", md)
        self.assertNotIn("Needs a backport", md)
        self.assertNotIn("fasttrack cve <ID>", md)
        # Another series keeps the row.
        self.assertIn("Needs a backport (1)",
                      emit.report([res], [], {"CVE-2026-0009": {"7.3": {"outcome": "not-affected-needs-review"}}}))

    def test_report_reviewed(self):
        c = engine.Candidate("6.18", "a" * 40, "fix foo", "mainline", ["CVE-2026-0009"], verdict=engine.CONFLICT)
        res = engine.SeriesResult("6.18", "b" * 40, "6.18.2", None, [c])
        md = emit.report([res], [], {"CVE-2026-0009": {"6.18": {
            "outcome": "not-affected-needs-review", "reviewed": "2026-10-31", "reason": "no foo driver"}}})
        self.assertIn("Not affected (reviewed) (1)", md)
        self.assertIn("fix foo — no foo driver", md)
        self.assertNotIn("needs review", md)

    def cve_backport(self, cve, upstream, old, new):
        """A cve/<cve>/6.18 set made on the stable head, as `fasttrack cve --collect` writes it."""
        wt = self.tmp / f"bp-{cve}"
        sh(self.repo, "git", "worktree", "add", "-q", "--detach", str(wt), "linux-6.18.y")
        f = wt / f"{old.split()[0]}.c"
        f.write_text(f.read_text().replace(old, new))
        sh(wt, "git", "commit", "-qam", "backport")
        c = engine.Candidate("6.18", upstream, "backport", "claude", [cve], verdict=engine.ACCEPTED,
                             filename=f"0001-{upstream[:12]}-backport.patch",
                             patch=sh(wt, "git", "format-patch", "-1", "--stdout"))
        emit.write_patch_dir(self.tmp / "cve" / cve / "6.18", "6.18", "h", "6.18.2", [c])

    def run_with_cve(self):
        return engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue", {},
                                 {"6.18": "6.18.2"}, remote="none", cve_root=self.tmp / "cve")

    def test_cve_backport_joins_patch_set(self):
        self.cve_backport("CVE-2026-0003", self.C, "baz line 6 REWORKED", "baz line 6 FIXED")
        res = self.run_with_cve()
        v = {(c.upstream, c.backport): c.verdict for c in res.candidates}
        self.assertEqual(v[(self.C, "")], engine.BACKPORTED)
        self.assertEqual(v[(self.C, "CVE-2026-0003/6.18")], engine.ACCEPTED)
        self.assertNotIn(self.C, [r["upstream"] for r in emit.unpatched([res])])
        d = emit.write_series_dir(self.out, res)
        body = next(d.glob(f"*-{self.C[:12]}-*.patch")).read_text()
        self.assertEqual(body.count("X-Fasttrack-Source: claude"), 1)
        self.assertIn("X-Fasttrack-Backport: cve/CVE-2026-0003/6.18", body)
        self.assertIn("### Included (3)", emit.report([res], []))

    def test_cve_backport_stale_or_superseded(self):
        self.cve_backport("CVE-2026-0003", self.C, "baz line 6 REWORKED", "baz line 6 FIXED")
        self.cve_backport("CVE-2026-0001", self.A, "foo line 6", "foo line 6 FIXED")
        # The stable head moves under the baz backport.
        sh(self.repo, "git", "checkout", "-q", "linux-6.18.y")
        commit(self.repo, "baz rework 2", **{"baz.c": fix("baz", ("baz line 5", "baz line 5 REWORKED"),
                                                          ("baz line 6", "baz line 6 AGAIN"))})
        sh(self.repo, "git", "checkout", "-q", "master")
        res = self.run_with_cve()
        v = {(c.upstream, c.backport): c.verdict for c in res.candidates}
        self.assertEqual(v[(self.C, "CVE-2026-0003/6.18")], engine.CONFLICT)
        self.assertEqual(v[(self.C, "")], engine.CONFLICT)
        self.assertEqual(v[(self.A, "CVE-2026-0001/6.18")], engine.SUPERSEDED)
        self.assertEqual([r["upstream"] for r in emit.unpatched([res])].count(self.C), 1)
        self.assertIn("cve/ backport does not apply on this base (1)", emit.report([res], []))


class TestIncident(Fixture):
    def test_outcomes(self):
        self.assertEqual(self.resolve("CVE-2026-0001").outcome, "patched")
        self.assertEqual(self.resolve("CVE-2026-0002").outcome, "fixed-in-tree")
        self.assertEqual(self.resolve("CVE-2026-0005").outcome, "not-affected")
        r4 = self.resolve("CVE-2026-0004")
        self.assertEqual((r4.outcome, r4.patches[0].source), ("patched", "stable-queue"))
        self.assertEqual(self.resolve("CVE-2026-0003").outcome, "unpatched")

    def test_adapt_three_way(self):
        self.assertEqual(self.resolve("CVE-2026-0006").outcome, "unpatched")
        r = self.resolve("CVE-2026-0006", adapt=True)
        self.assertEqual((r.outcome, r.patches[0].verdict), ("patched-needs-review", incident.ADAPTED))
        self.assertIn("cherry picked from commit", r.patches[0].patch)
        self.assertEqual(self.resolve("CVE-2026-0003", adapt=True).outcome, "unpatched")  # real conflict stays

    def test_commit_without_cve_record(self):
        r = self.resolve("my-incident", commits=[self.A])
        self.assertEqual((r.status, r.outcome), ("unknown", "patched"))

    def test_work_package_and_claude(self):
        fake = self.tmp / "fake-claude"
        fake.write_text("""#!/bin/sh
set -e
p=$(ls upstream-*.patch | head -1); s=${p#upstream-}; s=${s%.patch}
full=$(git -C tree rev-parse "$s")
sed -i 's/baz line 6 REWORKED/baz line 6 REWORKED FIXED/' tree/baz.c
git -C tree -c user.name=c -c user.email=c@c commit -qam "baz: fix race" -m "commit $full upstream." -m "[ Backport: context reworked in stable ]"
echo ok > RESULT.md
""")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        with open(self.cfg, "a") as fh:
            fh.write(f"claude_cmd: ['{fake}']\n")
        rc = cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude"])
        self.assertEqual(rc, 0)
        wdir = self.out / "work" / "CVE-2026-0003" / "6.18"
        brief = (wdir / "BRIEF.md").read_text()
        self.assertIn("CVE-2026-0003 description", brief)
        self.assertIn("baz.c", brief)
        result = json.loads((self.out / "cve-result.json").read_text())[0]
        self.assertEqual(result["outcome"], "patched-needs-review")
        self.assertEqual([c["verdict"] for c in result["candidates"]], ["superseded", incident.CLAUDE])
        pdir = self.out / "cve" / "CVE-2026-0003" / "6.18"
        patch = next(pdir.glob("0001-*.patch")).read_text()
        self.assertIn("X-Fasttrack-Source: claude", patch)
        self.assertIn(f"commit {self.C} upstream.", patch)

        # a second run does not pay again; --retry does
        self.assertEqual(json.loads((self.out / "attempts.json").read_text())
                         ["CVE-2026-0003"]["6.18"]["outcome"], "patched-needs-review")
        (wdir / "RESULT.md").unlink()
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude"])
        self.assertFalse((wdir / "RESULT.md").exists())
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude", "--retry"])
        self.assertTrue((wdir / "RESULT.md").exists())

    def _fake_claude(self, script):
        fake = self.tmp / "fake-claude"
        fake.write_text("#!/bin/sh\nset -e\n" + script)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        with open(self.cfg, "a") as fh:
            fh.write(f"claude_cmd: ['{fake}']\n")

    def _cve_outcome(self):
        return json.loads((self.out / "cve-result.json").read_text())[0]["outcome"]

    def test_short_sha_supersedes(self):
        # Claude cites the fix by a 12-character sha
        self._fake_claude(f"""sed -i 's/baz line 6 REWORKED/baz line 6 REWORKED FIXED/' tree/baz.c
git -C tree -c user.name=c -c user.email=c@c commit -qam "baz: fix race" -m "commit {self.C[:12]} upstream."
""")
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude"])
        self.assertEqual(self._cve_outcome(), "patched-needs-review")

    def test_not_affected_by_work_package(self):
        self._fake_claude("printf 'Not affected\\n\\nThe code is not here.\\n' > RESULT.md\n")
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude"])
        self.assertEqual(self._cve_outcome(), "not-affected-needs-review")

    def test_claude_not_found(self):
        with open(self.cfg, "a") as fh:
            fh.write(f"claude_cmd: ['{self.tmp}/no-claude']\n")
        self.assertEqual(cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--claude"]), 2)
        self.assertFalse((self.out / "attempts.json").exists())

    def test_collect_existing_work_package(self):
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--package"])
        tree = self.out / "work" / "CVE-2026-0003" / "6.18" / "tree"
        sh(tree, "sed", "-i", "s/baz line 6 REWORKED/baz line 6 REWORKED FIXED/", "baz.c")
        sh(tree, "git", "-c", "user.name=c", "-c", "user.email=c@c", "commit", "-qam", "baz: fix race",
           "-m", f"commit {self.C} upstream.")
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--collect"])
        self.assertEqual(self._cve_outcome(), "patched-needs-review")
        self.assertTrue(tree.is_dir())

    def test_open_result_keeps_backport(self):
        d = self.out / "cve" / "CVE-2026-0003" / "6.18"
        d.mkdir(parents=True)
        (d / "fasttrack.json").write_text("{}")
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--package"])
        self.assertTrue((d / "fasttrack.json").exists())

    def test_work_package_on_patch_set(self):
        cli.main(["--config", str(self.cfg), "run"])
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--package"])
        wdir = self.out / "work" / "CVE-2026-0003" / "6.18"
        tree = wdir / "tree"
        self.assertIn("fasttrack: patches/6.18 set", sh(tree, "git", "log", "--format=%s"))
        self.assertIn("FIXED", (tree / "foo.c").read_text())          # A from the set
        self.assertIn("current patch set", (wdir / "BRIEF.md").read_text())
        sh(tree, "sed", "-i", "s/baz line 6 REWORKED/baz line 6 REWORKED FIXED/", "baz.c")
        sh(tree, "git", "-c", "user.name=c", "-c", "user.email=c@c", "commit", "-qam", "baz: fix race",
           "-m", f"commit {self.C} upstream.")
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0003", "--collect"])
        self.assertEqual(self._cve_outcome(), "patched-needs-review")
        meta = json.loads((self.out / "cve" / "CVE-2026-0003" / "6.18" / "fasttrack.json").read_text())
        self.assertTrue(meta["made"])
        # The next run carries the backport in the one patch set.
        cli.main(["--config", str(self.cfg), "run"])
        self.assertIn("X-Fasttrack-Backport: cve/CVE-2026-0003/6.18",
                      "".join(p.read_text() for p in (self.out / "patches" / "6.18").glob("*.patch")))

    def test_unpatched_round_trip(self):
        cli.main(["--config", str(self.cfg), "run"])
        rc = cli.main(["--config", str(self.cfg), "cve", "--unpatched", "--adapt"])
        self.assertEqual(rc, 1)  # CVE-3 still needs a backport
        rows = {r["cve"]: r["outcome"] for r in json.loads((self.out / "cve-result.json").read_text())}
        self.assertEqual(rows, {"CVE-2026-0003": "unpatched", "CVE-2026-0006": "patched-needs-review"})

    def test_stable_list_backport(self):
        # the author's backport of C onto the reworked stable code, as posted to the list
        sh(self.repo, "git", "checkout", "-q", "-b", "posted", "linux-6.18.y")
        commit(self.repo, f"baz: fix race\n\ncommit {self.C} upstream.",
               **{"baz.c": fix("baz", ("baz line 5", "baz line 5 REWORKED"), ("baz line 6", "baz line 6 REWORKED FIXED"))})
        posted = sh(self.repo, "git", "format-patch", "-1", "--stdout", "HEAD")
        sh(self.repo, "git", "checkout", "-q", "master")
        seen = []
        rec = vulns.find(self.data / "vulns", "CVE-2026-0003")
        res = incident.resolve(self.data / "linux", (6, 18), "CVE-2026-0003", rec.fix_commits, rec,
                               self.data / "stable-queue",
                               stable_list=lambda sha, s: seen.append((sha, s)) or ["junk", posted])
        self.assertEqual(seen, [(self.C, "6.18")])
        self.assertEqual(res.outcome, "patched")
        self.assertEqual(res.candidates[0].source, "stable-list")

    def test_young_fix_waits_for_stable(self):
        with open(self.cfg, "a") as fh:
            fh.write(f"claude_min_age_days: 100000\nclaude_cmd: ['false']\n")
        cli.main(["--config", str(self.cfg), "run"])
        cli.main(["--config", str(self.cfg), "cve", "--unpatched", "--claude"])
        self.assertFalse((self.out / "work" / "CVE-2026-0003" / "6.18" / "claude.log").exists())
        self.assertFalse((self.out / "attempts.json").exists())
        notes = {r["cve"]: r["note"] for r in json.loads((self.out / "cve-result.json").read_text())}
        self.assertIn("waits", notes["CVE-2026-0003"])


class FakeBuilder(build.Builder):
    """Compile check without make: a .c file "fails" when it contains ``broken``."""
    broken = ""

    def prepare(self):
        self.ready = True

    def _make(self, *targets, timeout=0):
        out = []
        for t in (t for t in targets if not t.startswith("-")):
            if self.broken and self.broken in (self.tree / (t[:-2] + ".c")).read_text():
                out += [f"{self.tree}/{t[:-2]}.c:7:1: error: broken build",
                        f"make[2]: *** [scripts/Makefile.build:287: {t}] Error 1"]
        return not out, "\n".join(out)


def fake_builder(broken):
    return lambda tree, out: type("B", (FakeBuilder,), {"broken": broken})(tree, out)


class TestBuildCheck(Fixture):
    def test_run_rejects_patch_that_does_not_build(self):
        res = engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue", {},
                                {"6.18": "6.18.2"}, remote="none", builder=fake_builder("foo line 6 FIXED"))
        a = next(c for c in res.candidates if c.upstream == self.A)
        self.assertEqual(a.verdict, engine.CONFLICT)
        self.assertIn("foo.c:7:1: error: broken build", a.build_log)
        self.assertNotIn(str(self.tmp), a.build_log)
        self.assertEqual([c.upstream for c in res.accepted], [self.D])

    def test_file_broken_at_base_is_not_an_error(self):
        res = engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue", {},
                                {"6.18": "6.18.2"}, remote="none", builder=fake_builder("foo line 3"))
        self.assertEqual([c.upstream for c in res.accepted], [self.D, self.A])

    def test_backport_on_top_of_backport_for_pick_that_does_not_build(self):
        # Mainline A applies but does not build. cve/0001 backports A; cve/0011 is made on top of it.
        wt = self.tmp / "bp"
        sh(self.repo, "git", "worktree", "add", "-q", "--detach", str(wt), "linux-6.18.y")
        for cve, upstream, old, new in (("CVE-2026-0001", self.A, "foo line 6", "foo line 6 FIX"),
                                        ("CVE-2026-0011", "f" * 40, "foo line 6 FIX", "foo line 6 FIX MORE")):
            f = wt / "foo.c"
            f.write_text(f.read_text().replace(old, new))
            sh(wt, "git", "commit", "-qam", "backport")
            c = engine.Candidate("6.18", upstream, "backport", "claude", [cve], verdict=engine.ACCEPTED,
                                 filename=f"0001-{upstream[:12]}-backport.patch",
                                 patch=sh(wt, "git", "format-patch", "-1", "--stdout"))
            emit.write_patch_dir(self.tmp / "cve" / cve / "6.18", "6.18", "h", "6.18.2", [c])
        res = engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue", {},
                                {"6.18": "6.18.2"}, remote="none", builder=fake_builder("foo line 6 FIXED"),
                                cve_root=self.tmp / "cve")
        v = {(c.upstream, c.backport): c.verdict for c in res.candidates}
        self.assertEqual(v[(self.A, "")], engine.BACKPORTED)
        self.assertEqual(v[(self.A, "CVE-2026-0001/6.18")], engine.ACCEPTED)
        self.assertEqual(v[("f" * 40, "CVE-2026-0011/6.18")], engine.ACCEPTED)

    def test_backport_needs_prerequisite_from_superseded_set(self):
        # cve/0001 holds a prerequisite (bar.c) and the backport of A. Mainline A applies, so the
        # set is superseded in the first pass, but A and cve/0011 build only with the prerequisite.
        class B(FakeBuilder):
            def _make(self, *targets, timeout=0):
                out = []
                for t in (t for t in targets if not t.startswith("-")):
                    text = (self.tree / (t[:-2] + ".c")).read_text()
                    if ("foo line 6 FIXED" in text or "USES" in text) and \
                            "PROVIDED" not in (self.tree / "bar.c").read_text():
                        out.append(f"{self.tree}/{t[:-2]}.c:7:1: error: missing prerequisite")
                return not out, "\n".join(out)

        wt = self.tmp / "bp"
        sh(self.repo, "git", "worktree", "add", "-q", "--detach", str(wt), "linux-6.18.y")

        def made(filename, upstream, name, old, new):
            f = wt / name
            f.write_text(f.read_text().replace(old, new))
            sh(wt, "git", "commit", "-qam", "backport")
            return engine.Candidate("6.18", upstream, "backport", "claude", [], verdict=engine.ACCEPTED,
                                    filename=filename,
                                    patch=sh(wt, "git", "format-patch", "-1", "--stdout"))
        pre = made("0001-pre.patch", "d" * 40, "bar.c", "bar line 3\n", "bar line 3 PROVIDED\n")
        a = made("0002-a.patch", self.A, "foo.c", "foo line 6\n", "foo line 6 FIXED\n")
        emit.write_patch_dir(self.tmp / "cve" / "CVE-2026-0001" / "6.18", "6.18", "h", "6.18.2", [pre, a])
        q = made("0001-q.patch", "f" * 40, "qux.c", "qux line 0\n", "qux line 0 USES\n")
        emit.write_patch_dir(self.tmp / "cve" / "CVE-2026-0011" / "6.18", "6.18", "h", "6.18.2", [q])
        res = engine.run_series(self.repo, (6, 18), self.records, self.data / "stable-queue", {},
                                {"6.18": "6.18.2"}, remote="none", builder=B, cve_root=self.tmp / "cve")
        v = {(c.upstream, c.backport): c.verdict for c in res.candidates}
        self.assertEqual(v[(self.A, "")], engine.BACKPORTED)
        self.assertEqual(v[("d" * 40, "CVE-2026-0001/6.18")], engine.ACCEPTED)
        self.assertEqual(v[("f" * 40, "CVE-2026-0011/6.18")], engine.ACCEPTED)

    def test_claude_backport_that_does_not_build(self):
        rec = vulns.find(self.data / "vulns", "CVE-2026-0001")
        bld = fake_builder("foo line 6 FIXED")
        res = incident.resolve(self.data / "linux", (6, 18), "CVE-2026-0001", rec.fix_commits, rec,
                               self.data / "stable-queue", builder=bld)
        self.assertEqual(res.outcome, "unpatched")
        wdir = incident.prepare_work(self.data / "linux", res, self.out / "work")
        self.assertIn("do not build", (wdir / "BRIEF.md").read_text())
        # the backport keeps the broken line: rejected, and the next brief shows why
        tree = wdir / "tree"
        sh(tree, "sed", "-i", "s/foo line 6/foo line 6 FIXED/", "foo.c")
        sh(tree, "git", "-c", "user.name=c", "-c", "user.email=c@c", "commit", "-qam", "foo: fix overflow",
           "-m", f"commit {self.A} upstream.")
        incident.collect_work(self.data / "linux", res, wdir, bld)
        self.assertEqual(res.outcome, "unpatched")
        self.assertTrue((wdir / "build-errors.log").exists())
        incident.prepare_work(self.data / "linux", res, self.out / "work")
        self.assertIn("earlier backport", (wdir / "BRIEF.md").read_text())
        # a backport that builds clears the log
        tree = wdir / "tree"
        sh(tree, "sed", "-i", "s/foo line 6/foo line 6 FIX/", "foo.c")
        sh(tree, "git", "-c", "user.name=c", "-c", "user.email=c@c", "commit", "-qam", "foo: fix overflow",
           "-m", f"commit {self.A} upstream.")
        incident.collect_work(self.data / "linux", res, wdir, bld)
        self.assertEqual(res.outcome, "patched-needs-review")
        self.assertFalse((wdir / "build-errors.log").exists())

    def test_target_for_included_c(self):
        t = self.tmp / "k"
        (t / "kernel").mkdir(parents=True)
        (t / "kernel" / "Makefile").write_text("obj-y += build_policy.o\n")
        (t / "kernel" / "build_policy.c").write_text('# include "ext.c"\n')
        b = build.Builder(t, t / "out")
        self.assertEqual(b.target("kernel/ext.c"), "kernel/build_policy.o")
        self.assertEqual(b.target("kernel/build_policy.c"), "kernel/build_policy.o")


class TestFingerprint(Fixture):
    def test_changes_with_upstream_heads(self):
        urls = {"vulns": str(self.data / "linux"), "stable_queue": str(self.data / "linux"),
                "linux": str(self.data / "linux"), "kev": "file:///nonexistent", "releases": "file:///nonexistent"}
        fp = lambda: sync.fingerprint(["6.18"], urls, [self.cfg])
        first = fp()
        self.assertEqual(fp(), first)
        sh(self.data / "linux", "git", "update-ref", "refs/heads/linux-6.18.y", self.A)
        self.assertNotEqual(fp(), first)

    def test_changes_with_attempts(self):
        # A reviewed "not affected" in attempts.json changes report.md: a run is due.
        import contextlib, io
        repo = str(self.data / "linux")
        with open(self.cfg, "a") as fh:
            fh.write(f"sources: {{vulns: {repo}, stable_queue: {repo}, linux: {repo}, "
                     "kev: 'file:///nonexistent', releases: 'file:///nonexistent'}\n")

        def fp():
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.main(["--config", str(self.cfg), "fingerprint"])
            return buf.getvalue().split()[-1]
        first = fp()
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "attempts.json").write_text('{"CVE-2026-0003": {"6.18": {"reviewed": "2026-11-01"}}}\n')
        self.assertNotEqual(fp(), first)


class TestExpiry(Fixture):
    def _land_in_stable(self, sha, sub):
        sh(self.repo, "git", "checkout", "-q", "linux-6.18.y")
        sh(self.repo, "git", "cherry-pick", sha)
        commit(self.repo, f"Linux 6.18.{sub}", Makefile=makefile(sub))
        sh(self.repo, "git", "checkout", "-q", "master")
        sh(self.tmp, "git", "-C", str(self.data / "linux"), "fetch", "-q", str(self.repo),
           "+refs/heads/linux-6.18.y:refs/remotes/origin/linux-6.18.y")

    def test_run_drops_patches_stable_absorbed(self):
        cli.main(["--config", str(self.cfg), "run"])
        self.assertEqual(len(list((self.out / "patches" / "6.18").glob("*.patch"))), 2)
        self._land_in_stable(self.A, 3)                       # CVE record still lags
        cli.main(["--config", str(self.cfg), "run"])
        names = [p.name for p in (self.out / "patches" / "6.18").glob("*.patch")]
        self.assertEqual(len(names), 1)
        self.assertNotIn(self.A[:12], " ".join(names))
        self.assertIn("retired 6.18: 1", (self.out / "report.md").read_text())

    def test_prune_retires_incidents(self):
        cli.main(["--config", str(self.cfg), "cve", "CVE-2026-0001", "CVE-2026-0006", "--adapt"])
        cve = self.out / "cve"
        self.assertTrue((cve / "CVE-2026-0001" / "6.18").is_dir())
        cli.main(["--config", str(self.cfg), "prune"])
        self.assertTrue((cve / "CVE-2026-0001" / "6.18").is_dir())  # nothing landed yet
        self._land_in_stable(self.A, 3)
        cli.main(["--config", str(self.cfg), "prune"])
        self.assertFalse((cve / "CVE-2026-0001").exists())
        self.assertTrue((cve / "CVE-2026-0006" / "6.18").is_dir())


class TestHints(Fixture):
    def test_prerequisite_hint(self):
        pre = commit(self.repo, "baz: refactor locking", **{"baz.c": lines("baz") + "lock\n"})
        fixc = commit(self.repo, "baz: fix late", **{"baz.c": lines("baz").replace("baz line 2", "baz line 2 X") + "lock\n"})
        from fasttrack import gitutil
        hints = gitutil.prerequisite_hints(self.repo, "linux-6.18.y", fixc, ["baz.c"])
        self.assertEqual([h.split(" ", 1)[1] for h in hints], ["baz: fix race", "baz: refactor locking"])


class TestShallowBoundary(Fixture):
    """A fix merged from a topic branch that started before the cut: in the mirror
    its parent is gone, so a local format-patch would emit the whole tree."""

    def test_boundary_fix_uses_real_patch(self):
        from fasttrack import gitutil
        r = self.repo
        sh(r, "git", "checkout", "-q", "-b", "topic", self.rc1)
        (r / "newdrv.c").write_bytes(b"int x; /* caf\xc0 */\n")     # not UTF-8 on purpose
        sh(r, "git", "add", "newdrv.c")
        sh(r, "git", "commit", "-q", "-m", "newdrv: fix bounds")
        F = sh(r, "git", "rev-parse", "HEAD").strip()
        sh(r, "git", "checkout", "-q", "master")
        sh(r, "git", "merge", "-q", "--no-ff", "-m", "Merge topic", "topic")
        sh(r, "git", "tag", "v6.18", self.rc1)
        pub = self.data / "vulns" / "cve" / "published" / "2026"
        (pub / "CVE-2026-0007.json").write_text(json.dumps({"cveMetadata": {"cveId": "CVE-2026-0007"},
            "containers": {"cna": {"title": "t", "affected": [{"product": "Linux", "versions": AFFECTED}]}}}))
        (pub / "CVE-2026-0007.sha1").write_text(F + "\n")

        mirror = self.tmp / "shallow"
        sync.fetch_linux(mirror, f"file://{r}", ["6.18"], shallow=True)
        self.assertTrue(gitutil.is_boundary(mirror, F))
        self.assertIn("Makefile", gitutil.format_patch(mirror, F))       # the bug: whole tree
        served = self.tmp / "served"
        served.mkdir()
        (served / f"{F}.patch").write_bytes(sh_bytes(r, "git", "format-patch", "-1", "--stdout", F))
        old = gitutil.PATCH_URLS
        gitutil.PATCH_URLS = [f"file://{served}/{{sha}}.patch"]
        try:
            records = list(vulns.iter_records(self.data / "vulns"))
            res = engine.run_series(mirror, (6, 18), records, None, {}, {})
            c = next(c for c in res.candidates if c.upstream == F)
            self.assertEqual(c.verdict, engine.ACCEPTED)
            self.assertNotIn("Makefile", c.patch)
            d = emit.write_series_dir(self.out, res)
            raw = next(d.glob(f"*{F[:12]}*")).read_bytes()
            self.assertIn(b"caf\xc0", raw)                                   # bytes preserved
            self.assertTrue((mirror / "fasttrack-patches" / f"{F}.patch").exists())  # cached
        finally:
            gitutil.PATCH_URLS = old

    def test_boundary_without_download_is_reported_not_fatal(self):
        from fasttrack import gitutil
        old = gitutil.PATCH_URLS
        gitutil.PATCH_URLS = ["file:///nonexistent/{sha}"]
        try:
            sh(self.repo, "git", "tag", "v6.18", self.rc1)
            mirror = self.tmp / "shallow"
            sync.fetch_linux(mirror, f"file://{self.repo}", ["6.18"], shallow=True)
            base = sh(mirror, "git", "rev-list", "--max-parents=0", "origin/master").split()
            self.assertTrue(base and gitutil.is_boundary(mirror, base[0]))
            with self.assertRaises(gitutil.GitError):
                gitutil.upstream_patch(mirror, base[0])
        finally:
            gitutil.PATCH_URLS = old


class TestStableBranchesOnly(Fixture):
    """mainline_branch: false — fixes not in any mirrored branch are downloaded."""

    def test_same_verdicts_without_master(self):
        from fasttrack import gitutil
        mirror = self.tmp / "two-branches"
        sync.fetch_linux(mirror, f"file://{self.repo}", ["6.18"], shallow=False, mainline=False)
        self.assertFalse(gitutil.present(mirror, self.A))
        served = self.tmp / "served"
        served.mkdir()
        for sha in (self.A, self.C, self.D, self.E):
            (served / f"{sha}.patch").write_bytes(sh_bytes(self.repo, "git", "format-patch", "-1", "--stdout", sha))
        old = gitutil.PATCH_URLS
        gitutil.PATCH_URLS = [f"file://{served}/{{sha}}.patch"]
        try:
            res = engine.run_series(mirror, (6, 18), self.records, self.data / "stable-queue", {}, {})
            v = {c.upstream: c.verdict for c in res.candidates}
            self.assertEqual(v[self.A], engine.ACCEPTED)
            self.assertEqual(v[self.C], engine.CONFLICT)
            self.assertEqual(v[self.E], engine.CONFLICT)
            self.assertEqual([c.upstream for c in res.accepted], [self.D, self.A])
            self.assertEqual(next(c for c in res.candidates if c.upstream == self.A).subject, "foo: fix overflow")
            self.assertEqual(next(c for c in res.candidates if c.upstream == self.C).files, ["baz.c"])
            r = incident.resolve(mirror, (6, 18), "CVE-2026-0006", [self.E],
                                 vulns.find(self.data / "vulns", "CVE-2026-0006"), None, adapt=True)
            self.assertEqual(r.outcome, "patched-needs-review")       # 3-way apply, not cherry-pick
        finally:
            gitutil.PATCH_URLS = old


class TestShallow(Fixture):
    def test_shallow_mirror_is_sufficient(self):
        # history before the release tag must not be needed
        sh(self.repo, "git", "checkout", "-q", "-b", "old", "master~5")
        commit(self.repo, "pre-release noise", **{"foo.c": lines("foo") + "old\n"})
        sh(self.repo, "git", "checkout", "-q", "master")
        base = sh(self.repo, "git", "merge-base", "master", "linux-6.18.y").strip()
        sh(self.repo, "git", "tag", "v6.18", self.rc1)    # cut below base; base is the first kept commit
        sh(self.repo, "git", "config", "uploadpack.allowFilter", "true")
        mirror = self.tmp / "shallow"
        sync.fetch_linux(mirror, f"file://{self.repo}", ["6.18", "7.3"], shallow=True)
        self.assertTrue((mirror / "shallow").exists())
        self.assertEqual(sync.shallow_boundary(["7.3", "6.18"]), "v6.18")
        self.assertNotIn(self.rc1, sh(mirror, "git", "rev-list", "--all"))           # history really cut
        res = engine.run_series(mirror, (6, 18), self.records, self.data / "stable-queue", {}, {})
        v = {c.upstream: c.verdict for c in res.candidates}
        self.assertEqual(v[self.A], engine.ACCEPTED)
        self.assertEqual(v[self.C], engine.CONFLICT)
        # hints work without a merge-base: a mainline baz.c change the stable branch lacks
        hint = next(c for c in res.candidates if c.upstream == self.C)
        self.assertEqual(hint.files, ["baz.c"])
        r = incident.resolve(mirror, (6, 18), "CVE-2026-0006", [self.E],
                             vulns.find(self.data / "vulns", "CVE-2026-0006"), None, adapt=True)
        self.assertEqual(r.outcome, "patched-needs-review")
        # second sync is a plain incremental fetch
        sync.fetch_linux(mirror, f"file://{self.repo}", ["6.18", "7.3"], shallow=True)


if __name__ == "__main__":
    unittest.main()
