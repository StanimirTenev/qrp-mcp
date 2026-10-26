"""Hatchling build hook: the commit a wheel or sdist is built from, as qrp_mcp/_build_info.py.

An installed qrp-mcp cannot ask git which revision it is (coverage._tool_pin): it reports
`no_checkout`, and the CBOM said nothing about which code produced it. Built from a git
checkout, the package now carries the commit, and whether the package directory had
uncommitted changes at build time. A build that has no git -- the wheel `python -m build`
makes from the sdist -- keeps the file the sdist carries; a build with neither writes none,
and the installed package reports `no_checkout` as before.

The file is never written into the source tree: it is generated in a temporary directory and
force-included into the artifact.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_NAME = "_build_info.py"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          timeout=30, check=False)


def _commit(root: Path) -> tuple[str, bool] | None:
    """(commit, dirty) when `root` is itself the top of a git checkout tracking the package."""
    try:
        top = _git(root, "rev-parse", "--show-toplevel")
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root.resolve():
            # Not a checkout, or an sdist unpacked inside someone else's repository: that
            # repository's commit is not the one this package was built from.
            return None
        head = _git(root, "rev-parse", "HEAD")
        tracked = _git(root, "ls-files", "--error-unmatch", "src/qrp_mcp/__init__.py")
        if head.returncode != 0 or tracked.returncode != 0:
            return None
        dirty = _git(root, "status", "--porcelain", "--", "src/qrp_mcp")
    except (OSError, subprocess.SubprocessError):
        return None
    return head.stdout.strip(), bool(dirty.stdout.strip())


class BuildInfoHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if self.target_name not in ("wheel", "sdist") or version == "editable":
            return  # an editable install runs from the checkout and asks git itself
        root = Path(self.root)
        target = (f"qrp_mcp/{_NAME}" if self.target_name == "wheel"
                  else f"src/qrp_mcp/{_NAME}")
        if (root / "src" / "qrp_mcp" / _NAME).is_file():
            # An unpacked sdist carries the record of the checkout it was made from, and the
            # packages walk includes it as it is. Asked first: an sdist unpacked into a git
            # repository of its own (distribution packaging) would otherwise be labelled with
            # that repository's commit. The file is never written into a checkout.
            return
        found = _commit(root)
        if found is None:
            return  # no git and nothing carried: the installed package says no_checkout
        commit, dirty = found
        self._tmp = tempfile.mkdtemp(prefix="qrp-build-info-")
        path = os.path.join(self._tmp, _NAME)
        with open(path, "w", encoding="utf-8") as out:
            out.write('"""Written at build time by hatch_build.py; not in the repository."""\n'
                      f"COMMIT = {commit!r}\n"
                      f"DIRTY = {dirty!r}\n")
        build_data.setdefault("force_include", {})[path] = target

    def finalize(self, version: str, build_data: dict, artifact_path: str) -> None:
        tmp = getattr(self, "_tmp", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
