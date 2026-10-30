"""Kernel CVE records (vulns.git) → per-series status.

Layout used: ``cve/published/<year>/CVE-*.json`` (CVE JSON 5) with a
sibling ``CVE-*.sha1`` listing the mainline fix commit(s).

For a series S (e.g. 6.18) a record yields one of:

* ``unaffected``  – bug introduced after S, or fixed in mainline before S.0
* ``fixed-in``    – a stable release of S carries the fix (version given)
* ``unfixed``     – S is affected and no S release has the fix yet.
                    These are the gap: candidates for a mainline cherry-pick.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

_V = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:-rc(\d+))?")


def parse_version(text: str) -> Optional[tuple[int, int, int, int]]:
    """(major, minor, patch, rc) with rc=99 for a final release so rcs sort first."""
    m = _V.match(text or "")
    if not m:
        return None
    rc = int(m.group(4)) if m.group(4) else 99
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0), rc)


@dataclass
class CveRecord:
    cve: str
    title: str
    fix_commits: list[str]                      # mainline SHAs
    introduced: Optional[tuple] = None          # first affected series, if bounded
    mainline_fixed: Optional[tuple] = None      # version where mainline got the fix
    stable_fixed: dict[tuple[int, int], tuple] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    description: str = ""

    def status(self, series: tuple[int, int]) -> tuple[str, Optional[tuple]]:
        s = series
        if self.introduced and s < self.introduced[:2]:
            return "unaffected", None
        if self.mainline_fixed:
            # Fixed in mainline at S.0 or during S's merge window/rcs.
            if self.mainline_fixed[:2] <= s:
                return "unaffected", None
        if s in self.stable_fixed:
            return "fixed-in", self.stable_fixed[s]
        return "unfixed", None


def _linux_entry(rec: dict) -> Optional[dict]:
    for aff in rec.get("containers", {}).get("cna", {}).get("affected", []):
        if aff.get("product") == "Linux" and any(
            v.get("versionType") in ("semver", "original_commit_for_fix") or "lessThanOrEqual" in v
            for v in aff.get("versions", [])
        ):
            return aff
    return None


def parse_record(path: Path) -> Optional[CveRecord]:
    try:
        rec = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    cve = rec.get("cveMetadata", {}).get("cveId") or path.stem
    cna = rec.get("containers", {}).get("cna", {})
    title = cna.get("title", "")

    sha_file = path.with_suffix(".sha1")
    fixes = []
    if sha_file.exists():
        fixes = [l.strip() for l in sha_file.read_text().split() if re.fullmatch(r"[0-9a-f]{40}", l.strip())]

    out = CveRecord(cve=cve, title=title, fix_commits=fixes)
    for d in cna.get("descriptions", []):
        if d.get("lang", "en").startswith("en"):
            out.description = d.get("value", "").strip()
            break
    aff = _linux_entry(rec)
    if not aff:
        return out
    out.files = list(aff.get("programFiles", []))

    for v in aff.get("versions", []):
        ver = parse_version(v.get("version", ""))
        status = v.get("status")
        vtype = v.get("versionType")
        if status == "affected" and ver and "lessThan" not in v and "lessThanOrEqual" not in v:
            out.introduced = ver
        elif status == "unaffected" and v.get("version") == "0" and v.get("lessThan"):
            out.introduced = parse_version(v["lessThan"]) or out.introduced
        elif status == "unaffected" and vtype == "original_commit_for_fix" and ver:
            out.mainline_fixed = ver
        elif status == "unaffected" and ver and str(v.get("lessThanOrEqual", "")).endswith(".*"):
            out.stable_fixed[ver[:2]] = ver
    # Older records lack original_commit_for_fix; a "lessThanOrEqual: *" entry plays that role.
    if out.mainline_fixed is None:
        for v in aff.get("versions", []):
            if v.get("status") == "unaffected" and v.get("lessThanOrEqual") == "*":
                out.mainline_fixed = parse_version(v.get("version", ""))
    return out


def iter_records(root: Path, since_year: int = 0) -> Iterator[CveRecord]:
    """Walk ``cve/published``. ``root`` may be the repo or the published dir."""
    pub = root / "cve" / "published" if (root / "cve").is_dir() else root
    for year_dir in sorted(pub.iterdir()):
        if not year_dir.is_dir() or (year_dir.name.isdigit() and int(year_dir.name) < since_year):
            continue
        for f in sorted(year_dir.glob("CVE-*.json")):
            r = parse_record(f)
            if r:
                yield r


def find(root: Path, cve_id: str) -> Optional[CveRecord]:
    """One record by id, or None if vulns.git does not (yet) have it."""
    pub = root / "cve" / "published" if (root / "cve").is_dir() else root
    cve_id = cve_id.upper()
    for f in sorted(pub.glob(f"*/{cve_id}.json")):
        return parse_record(f)
    return None
