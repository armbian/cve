"""Compile check: build the .c files a patch changes, with allmodconfig.

A patch that applies with no fuzz can still miss a prerequisite. The check
builds each changed .c file after the patch. When a file fails, it builds the
same file without the patch: only files that build at base count as errors.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from . import gitutil

log = logging.getLogger(__name__)

CROSS = {"arm64": "aarch64-linux-gnu-", "arm": "arm-linux-gnueabihf-",
         "riscv": "riscv64-linux-gnu-", "x86": "x86_64-linux-gnu-"}
HOST = {"arm64": "aarch64", "arm": "armv7l", "riscv": "riscv64", "x86": "x86_64"}


def cross_compile(arch: str) -> str:
    """CROSS_COMPILE prefix for ``arch``; empty on a matching host."""
    return "" if platform.machine() == HOST[arch] else CROSS[arch]


class BuildError(Exception):
    pass


class Builder:
    """Out-of-tree allmodconfig build of ``tree`` in ``out``."""

    def __init__(self, tree: Path, out: Path, arch: str = "x86", jobs: Optional[int] = None):
        if arch not in CROSS:
            raise BuildError(f"unknown arch {arch}")
        self.tree, self.out, self.arch = Path(tree), Path(out), arch
        self.jobs = jobs or os.cpu_count() or 1
        self.ready = False

    def _make(self, *targets: str, timeout: int = 1800) -> tuple[bool, str]:
        cmd = ["make", "-s", "-C", str(self.tree), f"O={self.out}", f"ARCH={self.arch}",
               f"CROSS_COMPILE={cross_compile(self.arch)}", f"-j{self.jobs}", *targets]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                               stdin=subprocess.DEVNULL)  # a new Kconfig option must not wait for input
        except subprocess.TimeoutExpired:
            return False, f"make {' '.join(targets)}: timed out after {timeout}s"
        return p.returncode == 0, p.stdout + p.stderr

    def prepare(self) -> None:
        t = time.monotonic()
        self.out.mkdir(parents=True, exist_ok=True)
        for step in (("allmodconfig",), None, ("olddefconfig",), ("prepare",)):
            if step is None:
                subprocess.run([str(self.tree / "scripts/config"), "--file", str(self.out / ".config"),
                                "--disable", "WERROR"], check=True)
                continue
            ok, text = self._make(*step)
            if not ok:
                raise BuildError(f"make {step[0]} failed:\n{text[-2000:]}")
        self.ready = True
        log.info("build check: %s allmodconfig prepared in %.0fs", self.arch, time.monotonic() - t)

    def target(self, f: str) -> str:
        """Object that compiles ``f``: the file itself, or the .c in its directory
        that includes it (e.g. kernel/sched/ext.c in build_policy.c)."""
        d, name = os.path.split(f)
        stem = name[:-2]
        mk = "".join((self.tree / d / m).read_text(errors="replace")
                     for m in ("Makefile", "Kbuild") if (self.tree / d / m).exists())
        if not re.search(rf"\b{re.escape(stem)}\.o\b", mk):
            inc = re.compile(rf'^#\s*include\s+"{re.escape(name)}"', re.M)
            for c in sorted((self.tree / d).glob("*.c")):
                if inc.search(c.read_text(errors="replace")):
                    return os.path.join(d, c.name[:-2] + ".o")
        return f[:-2] + ".o"

    def files(self, patch: str) -> list[str]:
        """Changed .c files this arch can build: no tools/, no other arch/ trees."""
        out = []
        for f in gitutil.patch_files(patch):
            if not f.endswith(".c") or f.startswith(("tools/", "Documentation/")):
                continue
            if f.startswith("arch/") and f.split("/")[1] != self.arch:
                continue
            if (self.tree / f).exists():
                out.append(f)
        return out

    def errors(self, files: list[str]) -> dict[str, str]:
        """file → compiler output, for each file that does not build."""
        bad = {}
        for f in files:
            ok, text = self._make(self.target(f))
            log.debug("build check: %s %s", f, "ok" if ok else "error")
            if not ok:
                bad[f] = text
        return bad

    def failing(self, files: list[str]) -> set[str]:
        """Files whose object does not build, from one parallel ``make -k``."""
        if not files:
            return set()
        objs = {f: self.target(f) for f in files}
        ok, text = self._make("-k", *sorted(set(objs.values())))
        if ok:
            return set()
        bad = set(re.findall(r"\*\*\* \[[^\]]*?: ([^\]\s]+\.o)\] Error", text))
        if not bad:                            # failed outside any object: count all
            return set(files)
        return {f for f, o in objs.items() if o in bad}

    def batch_regressions(self, patches: list[str], apply: Callable[[str, bool], None]) -> dict[int, str]:
        """Like :meth:`regressions` for a whole applied series, with one parallel
        build. Returns index of the patch to blame → compiler errors."""
        files = [set(self.files(p)) for p in patches]
        bad = self.failing(sorted(set().union(*files)))
        if not bad:
            return {}
        for p in reversed(patches):
            apply(p, True)
        try:
            base = self.failing(sorted(bad))
        finally:
            for p in patches:
                apply(p, False)
        out: dict[int, str] = {}
        for f in sorted(bad - base):
            ok, text = self._make(self.target(f))
            if ok:
                continue
            touching = [i for i, fs in enumerate(files) if f in fs]
            culprit = touching[-1] if touching else len(patches) - 1
            if len(touching) > 1:              # the last patch whose removal fixes the build
                undone = []
                for i in reversed(range(len(patches))):
                    apply(patches[i], True)
                    undone.append(i)
                    if i in touching and self._make(self.target(f))[0]:
                        culprit = i
                        break
                for i in reversed(undone):
                    apply(patches[i], False)
            log_text = f"## {f}\n{summary(text.replace(f'{self.tree}/', ''))}"
            out[culprit] = (out[culprit] + "\n" + log_text) if culprit in out else log_text
        return out

    def regressions(self, patches: list[str], apply: Callable[[str, bool], None]) -> str:
        """Compiler errors the patches bring in. The patches are applied to the
        tree; ``apply(patch, reverse)`` flips one in the working tree."""
        files = sorted({f for p in patches for f in self.files(p)})
        bad = self.errors(files)
        if not bad:
            return ""
        for p in reversed(patches):
            apply(p, True)
        try:
            base = self.errors(list(bad))
        finally:
            for p in patches:
                apply(p, False)
        return "\n".join(f"## {f}\n{summary(bad[f].replace(f'{self.tree}/', ''))}" for f in bad if f not in base)


def summary(text: str, lines: int = 40) -> str:
    """The error lines of compiler output, or its tail when none match."""
    keep = [l for l in text.splitlines() if re.search(r"\berror\b", l)] or text.splitlines()[-lines:]
    return "\n".join(keep[:lines])


def worktree_flip(path: Path) -> Callable[[str, bool], None]:
    """``apply`` callback for :meth:`Builder.regressions` on a git worktree."""
    def flip(patch: str, reverse: bool) -> None:
        gitutil.git(path, "apply", *(["-R"] if reverse else []), input=patch)
        gitutil.git(path, "update-index", "-q", "--refresh", check=False)
    return flip
