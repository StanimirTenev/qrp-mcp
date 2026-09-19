"""Two runs are comparable when the same tool read the same content.

An external audit of 0.9.0 found three ways this claim was wrong (F03, F04, F05),
and they are one defect: the comparison keyed on a commit, and a commit does not
identify what was read.

* a dirty emitter still compared, because the tool's own `dirty` was never read;
* an unverified corpus still compared, because `None` was treated as clean;
* two different subdirectories of one commit compared, at 100% and 0% coverage;
* adding a git-ignored file that the scan reads changed the corpus and neither pin
  noticed.

The repair is to say what was read: a digest over the files examined and the
files deliberately not examined. The git pin stays, as provenance a human can
check, but it no longer carries the conclusion.
"""
from __future__ import annotations

import copy
import json
import subprocess
import shutil

import pytest

from qrp_mcp import coverage
from qrp_mcp.scan import scan_directory

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _block(target, tool_dirty=False):
    block = json.loads(json.dumps(scan_directory(target)["coverage"]))
    block["instrument"]["source_commit"] = {"pinned": True, "commit": "a" * 40,
                                            "dirty": tool_dirty}
    return block


def _pinned(block, commit="b" * 40, dirty=False):
    block["corpus"]["pinned_at"] = {"pinned": True, "commit": commit, "dirty": dirty,
                                    "shallow": False}
    return block


# --- F03: the tri-state, for both pins ---------------------------------------

def test_a_dirty_emitter_is_not_comparable(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    first = _pinned(_block(tmp_path))
    second = _pinned(_block(tmp_path, tool_dirty=True))
    result = coverage.compare(first, second)
    assert result["verdict"] == "not_comparable"
    assert any("instrument_dirty" == d["reason"] for d in result["differences"])


def test_an_unverified_emitter_is_unestablished(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    first = _pinned(_block(tmp_path))
    second = _pinned(_block(tmp_path))
    second["instrument"]["source_commit"]["dirty"] = None
    result = coverage.compare(first, second)
    assert result["verdict"] == "unestablished"
    assert any("instrument_cleanliness_unknown" == u["reason"]
               for u in result["unestablished"])


def test_an_unverified_corpus_is_unestablished_not_clean(tmp_path):
    """`dirty: None` means nobody checked. It used to read as False."""
    (tmp_path / "a.py").write_text("x = 1\n")
    first = _pinned(_block(tmp_path))
    second = _pinned(_block(tmp_path))
    second["corpus"]["pinned_at"]["dirty"] = None
    second["corpus"]["pinned_at"]["dirty_not_checked"] = "external programs"
    result = coverage.compare(first, second)
    assert result["verdict"] == "unestablished"
    assert any("corpus_cleanliness_unknown" == u["reason"]
               for u in result["unestablished"])


# --- F04, F05: identity is the content ---------------------------------------

@needs_git
def test_two_subdirectories_of_one_commit_are_not_one_corpus(tmp_path):
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    (tmp_path / "a" / "one.py").write_text("from Crypto.PublicKey import RSA\n")
    (tmp_path / "b" / "two.txt").write_text("nothing\n")
    _git(tmp_path, "init", "-q"); _git(tmp_path, "add", ".")
    _git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    first, second = _block(tmp_path / "a"), _block(tmp_path / "b")
    result = coverage.compare(first, second)
    assert result["verdict"] == "not_comparable"
    assert any("corpus_content_differs" == d["reason"] for d in result["differences"])


@needs_git
def test_an_ignored_file_that_the_scan_reads_changes_the_corpus(tmp_path):
    (tmp_path / "a.py").write_text("from Crypto.PublicKey import RSA\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    _git(tmp_path, "init", "-q"); _git(tmp_path, "add", ".")
    _git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    first = _block(tmp_path)
    (tmp_path / "ignored.py").write_text("from Crypto.PublicKey import RSA\n")
    second = _block(tmp_path)
    # git still calls the tree clean: the file is ignored.
    assert first["corpus"]["pinned_at"]["dirty"] is False
    assert second["corpus"]["pinned_at"]["dirty"] is False
    result = coverage.compare(first, second)
    assert result["verdict"] == "not_comparable"


def test_the_same_content_at_a_different_path_is_still_comparable(tmp_path):
    """The property the digest must not break: a path licenses nothing."""
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
        (directory / "notes.md").write_text("prose\n")
    first = _pinned(_block(tmp_path / "one"))
    second = _pinned(_block(tmp_path / "two"))
    assert coverage.compare(first, second)["verdict"] == "comparable"


def test_changing_one_scanned_byte_is_not_comparable(tmp_path):
    (tmp_path / "a.py").write_text("rsa.generate_private_key(key_size=2048)\n")
    first = _pinned(_block(tmp_path))
    (tmp_path / "a.py").write_text("rsa.generate_private_key(key_size=1024)\n")
    second = _pinned(_block(tmp_path))
    assert coverage.compare(first, second)["verdict"] == "not_comparable"


def test_changing_an_unread_file_is_also_not_comparable(tmp_path):
    """A file this tool does not claim is still part of what was there."""
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "notes.md").write_text("prose\n")
    first = _pinned(_block(tmp_path))
    (tmp_path / "notes.md").write_text("much longer prose than before\n")
    second = _pinned(_block(tmp_path))
    assert coverage.compare(first, second)["verdict"] == "not_comparable"


# --- F06: a malformed block gets an answer, not an exception -----------------

@pytest.mark.parametrize("block", [
    {"instrument": "bad"},
    {"instrument": {"source_commit": {"pinned": True}}},
    {},
    {"instrument": {"source_commit": None}, "corpus": None},
    {"instrument": {"source_commit": {"pinned": True, "commit": None}}},
])
def test_a_malformed_block_is_unestablished_never_an_exception(block):
    result = coverage.compare(block, copy.deepcopy(block))
    assert result["verdict"] == "unestablished"
    assert any(u["reason"] == "block_incomplete" for u in result["unestablished"])
