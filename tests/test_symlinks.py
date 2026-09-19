"""A symlink must not carry the scan outside the directory it was given.

Found by an external audit of 0.9.0 (F01, F02). A link named linked.py inside the
scanned tree, pointing at a file next to it, was read: the scan reported the
outside file's line as if it were linked.py. The tool is pointed at code its user
did not write, and the excerpt travels into the MCP client's context and into any
exported CBOM, so reading outside the stated boundary is the boundary failing.

The policy: a symlink is not followed, and it is counted and named. That is the
same answer this scanner gives everywhere else -- the limit is declared rather
than left for the reader to discover.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")
SECRET = "SYNTHETIC_ONLY_MUST_NOT_APPEAR"


@posix_only
def test_a_link_to_a_file_outside_the_root_is_not_read(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (outside / "secret.py").write_text(
        f'rsa.generate_private_key(key_size=2048); secret = "{SECRET}"\n')
    (repo / "linked.py").symlink_to(outside / "secret.py")
    result = scan_directory(repo)
    # The leak, not the mechanism.
    assert SECRET not in json.dumps(result)
    assert result["detected_algorithms"] == []


@posix_only
def test_the_skipped_link_is_named_with_a_reason(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (outside / "secret.py").write_text("x = 1\n")
    (repo / "linked.py").symlink_to(outside / "secret.py")
    result = scan_directory(repo)
    links = result["symlinks_not_followed"]
    assert [entry["path"] for entry in links] == ["linked.py"]
    assert links[0]["target"] == "outside the scanned directory"
    assert links[0]["kind"] == "file"


@posix_only
def test_a_link_inside_the_root_names_its_target_relatively(tmp_path):
    """Inside the root the target is safe to print, and useful."""
    (tmp_path / "real.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "alias.py").symlink_to(tmp_path / "real.py")
    result = scan_directory(tmp_path)
    # The real file is still read: only the link is skipped.
    assert "MD5" in result["detected_algorithms"]
    links = result["symlinks_not_followed"]
    assert [(e["path"], e["target"]) for e in links] == [("alias.py", "real.py")]


@posix_only
def test_a_link_to_a_directory_outside_the_root_is_counted_not_dropped(tmp_path):
    """The audit's F02: files_present was 0 and the verdict claimed completeness."""
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (outside / "a.py").write_text(f'secret = "{SECRET}"\n')
    (repo / "linked_dir").symlink_to(outside, target_is_directory=True)
    result = scan_directory(repo)
    assert SECRET not in json.dumps(result)
    links = result["symlinks_not_followed"]
    assert [(e["path"], e["kind"]) for e in links] == [("linked_dir/", "directory")]
    # A directory that was not entered holds an unknown number of files, so the
    # scan may not claim to account for every one.
    assert result["coverage"]["accounts_for_every_file"] is False
    assert "read every one" not in result["verdict"]


@posix_only
def test_a_symlink_loop_does_not_hang_or_raise(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "loop").symlink_to(tmp_path / "loop")
    result = scan_directory(tmp_path)
    assert result["files_present"] >= 1


@posix_only
def test_the_file_count_still_adds_up(tmp_path):
    """present = scanned + unreadable + skipped_by_type + symlinks, always."""
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (outside / "secret.py").write_text("x = 1\n")
    (repo / "real.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (repo / "notes.md").write_text("prose\n")
    (repo / "linked.py").symlink_to(outside / "secret.py")
    (repo / "gone.py").symlink_to(outside / "does-not-exist.py")
    result = scan_directory(repo)
    parts = (sum(result["files_scanned"].values())
             + len(result["unreadable_files"])
             + sum(result["files_skipped_by_type"].values())
             + len([e for e in result["symlinks_not_followed"] if e["kind"] == "file"]))
    assert parts == result["files_present"]


# --- F07, F08: the two small ones from the same audit -------------------------

def test_certificate_evidence_order_does_not_depend_on_the_hash_seed(tmp_path):
    """The evidence list came off a set, so its order changed between processes.

    Two algorithm OIDs in one blob: RSA and Ed25519. Eight interpreters, eight
    different PYTHONHASHSEED values, one answer.
    """
    import subprocess
    import sys
    (tmp_path / "oids.der").write_bytes(
        bytes.fromhex("06092a864886f70d01010106032b6570"))
    code = ("import json,sys; from qrp_mcp.scan import scan_directory; "
            "print(json.dumps([e['algorithm'] for e in "
            "scan_directory(sys.argv[1])['evidence']['source_code']]))")
    seen = set()
    for seed in map(str, range(1, 9)):
        done = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
                              capture_output=True, text=True, check=True,
                              env={**os.environ, "PYTHONHASHSEED": seed})
        seen.add(done.stdout.strip())
    assert len(seen) == 1, seen


def test_a_tilde_in_the_output_path_is_written_not_refused(tmp_path):
    """The check expanded ~ and the write did not, so --out passed and then failed."""
    import subprocess
    import sys
    (tmp_path / "a.py").write_text("rsa.generate_private_key(key_size=1024)\n")
    home = tmp_path / "home"
    home.mkdir()
    done = subprocess.run(
        [sys.executable, "-m", "qrp_mcp.server", "scan", str(tmp_path),
         "--out", "~/result.json"],
        capture_output=True, text=True, env={**os.environ, "HOME": str(home)})
    assert done.returncode == 0, done.stderr[-400:]
    assert (home / "result.json").is_file()


@posix_only
def test_the_verdict_names_the_linked_directory_as_the_reason(tmp_path):
    """"The reasons do not add up" described the arithmetic, not the cause."""
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (outside / "a.py").write_text("x = 1\n")
    (repo / "linked_dir").symlink_to(outside, target_is_directory=True)
    verdict = scan_directory(repo)["verdict"]
    assert "1 linked directory was not followed" in verdict
    assert "do not add up" not in verdict
