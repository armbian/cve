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

from fasttrack import cli, emit, engine, incident, vulns
from fasttrack.queue import load_queue


def sh(cwd, *args, input=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, input=input).stdout


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

    def test_events(self):
        res = self.run_618(kev={"CVE-2026-0004": "x"})
        state, events = emit.diff_state({"series": {"6.18": {"version": "6.18.1", "accepted": [self.A]}}}, [res])
        self.assertIn("new-stable 6.18: 6.18.1 → 6.18.2", events)
        self.assertTrue(any("CVE-2026-0004" in e for e in events))
        self.assertEqual(emit.diff_state(state, [res])[1], [])


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

    def test_unpatched_round_trip(self):
        cli.main(["--config", str(self.cfg), "run"])
        rc = cli.main(["--config", str(self.cfg), "cve", "--unpatched", "--adapt"])
        self.assertEqual(rc, 1)  # CVE-3 still needs a backport
        rows = {r["cve"]: r["outcome"] for r in json.loads((self.out / "cve-result.json").read_text())}
        self.assertEqual(rows, {"CVE-2026-0003": "unpatched", "CVE-2026-0006": "patched-needs-review"})


if __name__ == "__main__":
    unittest.main()
