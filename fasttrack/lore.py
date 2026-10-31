"""Backports posted to the stable mailing list, before they reach stable-queue.

When a fix does not apply to a stable branch, the stable team asks the author
for a backport. Authors post it to stable@vger.kernel.org as "[PATCH 6.18.y] ...",
often weeks before it is queued. Taking that patch is free and is the author's
own adaptation, so it comes before a Claude backport.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .gitutil import ENC

log = logging.getLogger(__name__)

LORE = "https://lore.kernel.org/stable/"
_ATOM = "{http://www.w3.org/2005/Atom}"


def _get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ksec-fasttrack"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode(**ENC)


def backports(sha: str, series: str) -> list[str]:
    """Patches posted for ``series`` that cite upstream ``sha``, newest first."""
    want = re.compile(rf"^\[PATCH[^\]]*?\b{re.escape(series)}(?:\.y)?\b[^\]]*\]")
    try:
        feed = ET.fromstring(_get(f"{LORE}?q={urllib.parse.quote(sha)}&x=A"))
    except Exception as e:                       # enrichment only; never fail the run for it
        log.info("lore %s: %s", sha[:12], e)
        return []
    posts = []
    for entry in feed.iter(f"{_ATOM}entry"):
        title = entry.findtext(f"{_ATOM}title", "")
        link = entry.find(f"{_ATOM}link")
        if want.match(title) and link is not None:
            posts.append((entry.findtext(f"{_ATOM}updated", ""), title, link.get("href")))
    out = []
    for _, title, href in sorted(posts, reverse=True):
        try:
            body = _get(href.rstrip("/") + "/raw")
        except Exception as e:
            log.info("lore %s: %s", href, e)
            continue
        if sha in body and "\ndiff --git " in body:
            log.info("lore %s: %s", sha[:12], title)
            out.append(body)
    return out
