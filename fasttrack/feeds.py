"""Small enrichment feeds: CISA KEV (actively exploited) and kernel.org releases.

Both are optional. A missing or unreadable file degrades to "no data",
never to a failed run — enrichment changes priority, not correctness.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def load_kev(path: Optional[Path]) -> dict[str, str]:
    """CVE id → dateAdded, for kernel entries in the CISA KEV catalogue."""
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        if "linux" in (v.get("product", "") + v.get("vendorProject", "")).lower():
            out[v["cveID"]] = v.get("dateAdded", "")
    return out


def load_releases(path: Optional[Path]) -> dict[str, str]:
    """series → latest version from kernel.org releases.json, e.g. {'6.18': '6.18.9'}."""
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    out = {}
    for r in data.get("releases", []):
        ver = r.get("version", "")
        parts = ver.split(".")
        if len(parts) >= 2 and r.get("moniker") in ("stable", "longterm"):
            out[f"{parts[0]}.{parts[1]}"] = ver
    return out
