"""ksec-fasttrack: gather kernel security patches, verify them, list what is unpatched,
and build the missing ones (optionally with Claude).

    fasttrack sync                          pull all upstream sources
    fasttrack run                           patches/<series>/ + report + unpatched.json
    fasttrack cve CVE-2026-1234 [...]       one or more specific incidents
    fasttrack cve --commit <sha> --id NAME  incident with no CVE record yet
    fasttrack cve --unpatched               every issue the last run could not patch
        --adapt     also try a 3-way cherry-pick (marked for review)
        --claude    build a work package and let Claude Code make the backport
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import emit, engine, feeds, gitutil, incident, sync, vulns


def _series(text: str) -> tuple[int, int]:
    a, b = str(text).split(".")[:2]
    return int(a), int(b)


def _cfg(args) -> dict:
    cfg = yaml.safe_load(Path(args.config).read_text()) or {}
    cfg.setdefault("data", "data")
    cfg.setdefault("out", "out")
    if getattr(args, "out", None):
        cfg["out"] = args.out
    return cfg


def cmd_sync(args) -> int:
    cfg = _cfg(args)
    sync.sync(Path(cfg["data"]), [str(s) for s in cfg["series"]], cfg.get("sources"),
              shallow=bool(cfg.get("shallow", True)))
    return 0


def cmd_run(args) -> int:
    cfg = _cfg(args)
    data, out = Path(cfg["data"]), Path(cfg["out"])
    out.mkdir(parents=True, exist_ok=True)

    records = list(vulns.iter_records(data / "vulns", since_year=int(cfg.get("cve_since_year", 2024))))
    kev = feeds.load_kev(data / "kev.json")
    releases = feeds.load_releases(data / "releases.json")
    queue_root = data / "stable-queue"

    results = []
    for s in cfg["series"]:
        try:
            results.append(engine.run_series(data / "linux", _series(s), records,
                                             queue_root if queue_root.is_dir() else None,
                                             kev, releases, queue_mode=cfg.get("queue_mode", "cve")))
        except gitutil.GitError as e:
            print(f"{s}: skipped ({e})")

    state_file = out / "state.json"
    prev = json.loads(state_file.read_text()) if state_file.exists() else {}
    state, events = emit.diff_state(prev, results)

    for r in results:
        emit.write_series_dir(out, r)
    (out / "report.md").write_text(emit.report(results, events))
    (out / "unpatched.json").write_text(json.dumps(emit.unpatched(results), indent=2) + "\n")
    (out / "events.json").write_text(json.dumps(events, indent=2) + "\n")
    state_file.write_text(json.dumps(state, indent=2) + "\n")

    for r in results:
        counts: dict[str, int] = {}
        for c in r.candidates:
            counts[c.verdict] = counts.get(c.verdict, 0) + 1
        print(f"{r.series} @ {r.head_version}: "
              + (", ".join(f"{v}={n}" for v, n in sorted(counts.items())) or "nothing pending"))
    for e in events:
        print(f"event: {e}")
    print(f"report: {out / 'report.md'}")

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        flag = lambda p: "true" if any(e.startswith(p) for e in events) else "false"
        with open(gh_out, "a") as fh:
            fh.write(f"new_stable={flag('new-stable')}\nkev={flag('kev')}\n"
                     f"unpatched={len(emit.unpatched(results))}\n")
    return 0


def cmd_cve(args) -> int:
    cfg = _cfg(args)
    data, out = Path(cfg["data"]), Path(cfg["out"])
    series = [_series(s) for s in (args.series or cfg["series"])]
    queue_root = data / "stable-queue"
    queue_root = queue_root if queue_root.is_dir() else None

    incidents: dict[str, list[str]] = {}
    if args.unpatched:
        incidents.update(incident.load_unpatched(out / "unpatched.json"))
        if not incidents:
            print(f"nothing in {out / 'unpatched.json'}; run `fasttrack run` first")
    for cid in args.ids:
        incidents.setdefault(cid.upper(), [])
    if args.commit:
        name = args.id or (args.ids[0].upper() if len(args.ids) == 1 else f"manual-{args.commit[0][:12]}")
        incidents.setdefault(name, [])
        incidents[name] += [c for c in args.commit if c not in incidents[name]]
    if not incidents:
        print("give CVE ids, --commit, or --unpatched")
        return 2

    claude_cmd = cfg.get("claude_cmd") or incident.DEFAULT_CLAUDE_CMD
    if args.claude_model:
        claude_cmd = list(claude_cmd) + ["--model", args.claude_model]

    resolutions = []
    for cid, extra in incidents.items():
        rec = vulns.find(data / "vulns", cid) if cid.startswith("CVE-") else None
        fixes = list(dict.fromkeys((rec.fix_commits if rec else []) + extra))
        if not rec and not fixes:
            print(f"{cid}: not in vulns.git; pass --commit <mainline sha> to work from the fix directly")
        for s in series:
            try:
                res = incident.resolve(data / "linux", s, cid, fixes, rec, queue_root,
                                       adapt=args.adapt or args.claude)
            except gitutil.GitError as e:
                print(f"{cid} {s[0]}.{s[1]}: skipped ({e})")
                continue
            if res.outcome in ("unpatched", "partial") and (args.claude or args.package):
                wdir = incident.prepare_work(data / "linux", res, out / "work")
                if args.claude:
                    print(f"{cid} {res.series}: running Claude in {wdir} ...", flush=True)
                    rc = incident.run_claude(wdir, claude_cmd, timeout=args.claude_timeout)
                    if rc != 0:
                        res.note = (res.note + " " if res.note else "") + f"claude exited {rc}; see claude.log"
                    incident.collect_work(data / "linux", res, wdir)
            emit.write_patch_dir(out / "cve" / cid / res.series, res.series, res.head, res.head_version,
                                 res.patches, {"incident": cid, "outcome": res.outcome})
            resolutions.append(res)
            print(f"{cid} {res.series} @ {res.head_version}: {res.outcome}"
                  + (f" ({len(res.patches)} patch(es))" if res.patches else "")
                  + (f" — {res.note}" if res.note else ""))

    (out / "cve-report.md").write_text(emit.cve_report(resolutions))
    (out / "cve-result.json").write_text(json.dumps([r.public() for r in resolutions], indent=2) + "\n")
    print(f"report: {out / 'cve-report.md'}")
    return 1 if any(r.outcome in ("unpatched", "partial") for r in resolutions) else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="fasttrack", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="fasttrack.yaml")
    p.add_argument("--out", help="output directory (default from config)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("sync", help="pull upstream sources").set_defaults(fn=cmd_sync)
    sub.add_parser("run", help="gather and verify; write patches, report, unpatched list").set_defaults(fn=cmd_run)

    c = sub.add_parser("cve", help="resolve specific incidents")
    c.add_argument("ids", nargs="*", help="CVE ids")
    c.add_argument("--commit", action="append", help="mainline fix commit (repeatable)")
    c.add_argument("--id", help="name for a --commit incident without a CVE (default manual-<sha>)")
    c.add_argument("--series", nargs="+", help="override configured series, e.g. 6.18")
    c.add_argument("--unpatched", action="store_true", help="take every issue from the last run's unpatched.json")
    c.add_argument("--adapt", action="store_true", help="try a 3-way cherry-pick when it does not apply unchanged")
    c.add_argument("--package", action="store_true", help="write a backport work package for unpatched parts")
    c.add_argument("--claude", action="store_true", help="work package + run Claude Code headless on it (implies --adapt)")
    c.add_argument("--claude-model", help="model alias passed to claude --model")
    c.add_argument("--claude-timeout", type=int, default=3600)
    c.set_defaults(fn=cmd_cve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
