"""stable-queue.git: patches already selected for the next point release.

``queue-X.Y/series`` lists patch files in apply order. Each patch names
its mainline origin in one of the two forms the stable maintainers use:

    commit 0123abcd... upstream.
    [ Upstream commit 0123abcd... ]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_UPSTREAM = re.compile(
    r"^(?:commit ([0-9a-f]{40}) upstream\.?|\[\s*Upstream commit ([0-9a-f]{40})\s*\])",
    re.M | re.I,
)
_SUBJECT = re.compile(r"^Subject:\s*(?:\[[^\]]*\]\s*)?(.+(?:\n[ \t].+)*)", re.M)


@dataclass
class QueuedPatch:
    series: tuple[int, int]
    file: str
    upstream: Optional[str]
    subject: str
    body: str


def _subject(body: str) -> str:
    m = _SUBJECT.search(body)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def load_queue(root: Path, series: tuple[int, int]) -> list[QueuedPatch]:
    qdir = root / f"queue-{series[0]}.{series[1]}"
    sfile = qdir / "series"
    if not sfile.exists():
        return []
    out = []
    for line in sfile.read_text().splitlines():
        name = line.split("#", 1)[0].strip()
        if not name:
            continue
        p = qdir / name
        if not p.exists():
            continue
        body = p.read_text(encoding="utf-8", errors="surrogateescape")
        m = _UPSTREAM.search(body)
        up = (m.group(1) or m.group(2)) if m else None
        out.append(QueuedPatch(series, name, up, _subject(body), body))
    return out
