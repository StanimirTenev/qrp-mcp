"""Defects found by a review of 0.7.2, each reproduced before it was fixed.

The scanner is pointed at code its user did not write. Nothing in that code, its
file names or its repository configuration may run a program, crash the scan, or
disappear from the count.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="needs git")
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                              reason="root ignores permissions")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "a.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    return repo


# --- 1. a scanned repository must not be able to run programs ------------------

@needs_git
@posix_only
def test_repository_fsmonitor_is_not_executed(tmp_path):
    repo = _repo(tmp_path)
    marker = tmp_path / "PWNED"
    _git(repo, "config", "core.fsmonitor", f"touch {marker}; false")
    scan_directory(str(repo))
    assert not marker.exists()


@needs_git
@posix_only
def test_repository_clean_filter_is_not_executed(tmp_path):
    repo = _repo(tmp_path)
    marker = tmp_path / "PWNED-filter"
    (repo / ".gitattributes").write_text("*.py filter=evil\n")
    _git(repo, "config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'")
    _git(repo, "config", "filter.evil.smudge", "cat")
    # A changed file is what makes status consult the clean filter.
    (repo / "a.py").write_text("import hashlib\nhashlib.md5(b'y')\n")
    result = scan_directory(str(repo))
    assert not marker.exists()
    pin = result["coverage"]["corpus"]["pinned_at"]
    assert pin["dirty"] is None and pin["dirty_not_checked"]


# --- 9. the corpus pin describes the scanned directory, not its repository -----

@needs_git
def test_ignored_directory_is_not_pinned_to_the_repository_commit(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("out/\n")
    _git(repo, "add", ".gitignore")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ignore")
    (repo / "out").mkdir()
    (repo / "out" / "gen.c").write_text("RSA_generate_key_ex(r, 2048, e, NULL);\n")
    pin = scan_directory(str(repo / "out"))["coverage"]["corpus"]["pinned_at"]
    assert pin["pinned"] is False and pin["reason"] == "not_tracked"


@needs_git
def test_dirty_flag_is_scoped_to_the_scanned_directory(tmp_path):
    repo = _repo(tmp_path)
    (repo / "sub").mkdir()
    (repo / "sub" / "b.py").write_text("x = 1\n")
    _git(repo, "add", "sub/b.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sub")
    (repo / "sibling.txt").write_text("untracked elsewhere\n")
    pin = scan_directory(str(repo / "sub"))["coverage"]["corpus"]["pinned_at"]
    assert pin["dirty"] is False


@needs_git
def test_shallow_clone_is_detected_from_a_subdirectory(tmp_path):
    repo = _repo(tmp_path)
    (repo / "sub").mkdir()
    (repo / "sub" / "b.py").write_text("x = 1\n")
    _git(repo, "add", "sub/b.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sub")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(clone)],
                   check=True, capture_output=True)
    pin = scan_directory(str(clone / "sub"))["coverage"]["corpus"]["pinned_at"]
    assert pin["shallow"] is True
