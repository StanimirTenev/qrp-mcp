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


# --- 2, 3. what the walk cannot see is reported, never dropped ------------------

@posix_only
@not_root
def test_directory_that_cannot_be_entered_is_reported_not_fatal(tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    nox = tmp_path / "nox"
    nox.mkdir()
    (nox / "a.py").write_text("x = 1\n")
    nox.chmod(0o644)  # listable, not enterable
    try:
        r = scan_directory(str(tmp_path))
    finally:
        nox.chmod(0o755)
    # The file is visible by name, so it is counted, as unreadable -- not dropped.
    assert "nox/a.py" in r["unreadable_files"]
    assert "read every one" not in r["verdict"]


@posix_only
@not_root
def test_directory_that_cannot_be_read_is_reported_not_silent(tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    nor = tmp_path / "nor"
    nor.mkdir()
    (nor / "b.c").write_text("int x;\n")
    nor.chmod(0o000)
    try:
        r = scan_directory(str(tmp_path))
    finally:
        nor.chmod(0o755)
    assert r["unreadable_directories"] == ["nor/"]
    assert r["coverage"]["directories_not_entered"]["count"] == 1
    assert r["coverage"]["accounts_for_every_file"] is False
    assert "read every one" not in r["verdict"]


@posix_only
def test_broken_symlink_is_counted_as_unreadable(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "gone.py").symlink_to(tmp_path / "does-not-exist.py")
    r = scan_directory(str(tmp_path))
    assert "gone.py" in r["unreadable_files"]
    fs = sum(r["files_scanned"].values())
    assert fs + len(r["unreadable_files"]) + sum(r["files_skipped_by_type"].values()) \
        == r["files_present"]


def test_a_file_named_like_an_excluded_directory_is_scanned(tmp_path):
    (tmp_path / "build").write_text("x\n")      # a file, not a directory
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("x\n")
    r = scan_directory(str(tmp_path))
    excluded = r["coverage"]["scope"]["files_excluded_before_counting"]["by_directory"]
    assert excluded == {"dist": 1}
    assert r["files_present"] == 1


# --- 4, 5. names the filesystem allows must not break the output ----------------

@pytest.mark.skipif(sys.platform != "linux", reason="needs a byte-oriented filesystem")
def test_file_name_that_is_not_utf8_is_scanned_and_serialisable(tmp_path):
    name = os.fsdecode(b"k\\xffey.c".replace(b"\\\\xff", b"\\xff"))
    name = os.fsdecode(b"k\xffey.c")
    (tmp_path / name).write_text("RSA_generate_key_ex(r, 2048, e, NULL);\n")
    r = scan_directory(str(tmp_path))
    text = json.dumps(r)                      # used to raise
    text.encode("utf-8")
    assert any("\\\\xff" in e["path"] or "\\xff" in e["path"]
               for e in r["evidence"]["source_code"])


def test_filesystem_root_name_does_not_break_the_request(monkeypatch):
    from qrp_mcp import scan as scan_mod
    empty = {"detected_algorithms": [], "source_code_findings": [], "ci_pipeline_findings": [],
             "iac_findings": [], "embedded_key_findings": [], "files_scanned": {},
             "files_present": 0, "files_present_by_extension": {}, "files_skipped_by_type": {},
             "unreadable_files": [], "unreadable_directories": [], "files_excluded_by_dir": {}}
    monkeypatch.setattr(scan_mod.detectors, "scan_repo", lambda p: empty)
    monkeypatch.setattr(scan_mod.coverage, "build", lambda **kw: {"stub": True})
    monkeypatch.setattr(scan_mod.coverage, "verdict_line", lambda b: "stub")
    root = Path(Path.cwd().anchor)
    r = scan_mod.scan_directory(str(root))    # used to fail: empty asset name
    assert r["target"] == str(root)


# --- 10. compare_coverage answers instead of crashing ---------------------------

def test_compare_on_incomplete_blocks_is_unestablished():
    from qrp_mcp.coverage import compare
    r = compare({}, {})
    assert r["verdict"] == "unestablished"
    assert {u["reason"] for u in r["unestablished"]} >= {"block_incomplete"}


# --- 12. the command line fails with a message, before the work ------------------

def test_cli_rejects_a_missing_path_without_a_traceback(tmp_path, capsys):
    from qrp_mcp.server import scan_to_file
    with pytest.raises(SystemExit) as e:
        scan_to_file([str(tmp_path / "nope")])
    assert e.value.code == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_checks_the_output_folder_before_scanning(tmp_path, capsys, monkeypatch):
    from qrp_mcp import server
    called = []
    monkeypatch.setattr(server, "scan_directory", lambda p: called.append(p) or {})
    with pytest.raises(SystemExit):
        server.scan_to_file([str(tmp_path), "--out", str(tmp_path / "missing" / "r.json")])
    assert not called
    assert "does not exist" in capsys.readouterr().err


def test_version_and_help_do_not_start_the_server(capsys, monkeypatch):
    from qrp_mcp import server, __version__
    monkeypatch.setattr(server.mcp, "run", lambda: pytest.fail("server started"))
    for arg, expect in (("--version", __version__), ("--help", "qrp-mcp scan PATH")):
        with pytest.raises(SystemExit) as e:
            server.main([arg])
        assert e.value.code == 0 and expect in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        server.main(["--bogus"])
    assert e.value.code == 2
