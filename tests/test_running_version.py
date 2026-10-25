"""ZA-OPRAVYANE row 148: the output names the code that ran, not a stale label.

Measured 25.10.2026 (qrp-pokazateli 05-novi-merki): a CBOM made by 0.36.0 from an
editable checkout said `version: 0.36.0 (installed: 0.33.0)` and `dirty: true`. The
0.33.0 was the distribution metadata an editable install writes once, at install time;
the `dirty` was an untracked `.claude/` directory outside the package. Neither described
the code that did the reading, and a strict revision check would have failed our own
release CBOM.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import __version__, scan
from qrp_mcp.scan import scan_directory

_PKG = Path(__file__).resolve().parents[1] / "src" / "qrp_mcp"


def test_the_version_is_the_running_code_with_no_installed_suffix(monkeypatch):
    monkeypatch.setattr(scan, "_pkg_version", lambda name: "0.33.0")
    assert scan._version() == __version__


def test_a_stale_installed_distribution_is_said_beside_the_version(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_pkg_version", lambda name: "0.33.0")
    (tmp_path / "a.py").write_text("x = 1\n")
    instrument = scan_directory(tmp_path)["coverage"]["instrument"]
    assert instrument["version"] == __version__
    dist = instrument["installed_distribution"]
    assert dist["version"] == "0.33.0"
    assert dist["matches_running_code"] is False
    assert "0.33.0" in dist["meaning"] and __version__ in dist["meaning"]


def test_a_matching_distribution_adds_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(scan, "_pkg_version", lambda name: __version__)
    (tmp_path / "a.py").write_text("x = 1\n")
    assert "installed_distribution" not in scan_directory(tmp_path)["coverage"]["instrument"]


def _pin_from(pkg_parent: Path) -> dict:
    code = "import json; from qrp_mcp.coverage import _tool_pin; print(json.dumps(_tool_pin()))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={"PYTHONPATH": str(pkg_parent), "PATH": "/usr/bin:/bin"},
                         check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_dirty_is_about_the_running_package_not_the_whole_checkout(tmp_path):
    repo = tmp_path / "tool"
    shutil.copytree(_PKG, repo / "src" / "qrp_mcp",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (repo / ".gitignore").write_text("__pycache__/\n")
    for args in (["init", "-q"], ["add", "."],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True)
    # Untracked work outside the package (an agent's worktree folder) is not the code.
    (repo / ".claude").mkdir()
    (repo / ".claude" / "notes.md").write_text("x\n")
    pin = _pin_from(repo / "src")
    assert pin["pinned"] is True and pin["dirty"] is False
    # A changed module inside the package is.
    with open(repo / "src" / "qrp_mcp" / "oids.py", "a") as handle:
        handle.write("\n# edited\n")
    assert _pin_from(repo / "src")["dirty"] is True
