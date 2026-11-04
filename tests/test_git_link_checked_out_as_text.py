"""ZA-OPRAVYANE row 432 (the W2 cross-OS round, 04.11.2026): a git symbolic link checked out as
a text file is named as a link.

certbot has 48 index entries of mode 120000. On Windows (core.symlinks=false) git writes each as
a small text file holding the target path, so 12 `live/*/cert.pem` links became stubs claimed as
PEM and listed `claimed_but_not_decoded`, and coverage read 68.0 % on Linux and 71.2 % on
Windows for one commit. The index mode says what the entry is; the stub is now counted and
listed exactly as the link is on Linux, with `checked_out_as_text`.

Reproduced on Linux: `core.symlinks=false` makes git write the same stub here.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from qrp_mcp.scan import scan_directory

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, capture_output=True)


def _repo(root, symlinks: bool):
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.symlinks", "true" if symlinks else "false")
    (root / "archive").mkdir()
    (root / "archive" / "cert1.pem").write_text("not a certificate\n")
    (root / "live").mkdir()
    (root / "live" / "cert.pem").symlink_to("../archive/cert1.pem")
    (root / "a.py").write_text("k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "x")
    if not symlinks:
        (root / "live" / "cert.pem").unlink()
        _git(root, "checkout", "--", "live/cert.pem")
    return root


def test_a_link_stub_is_counted_as_the_link_is(tmp_path):
    stub_tree = _repo(tmp_path / "windows-like", symlinks=False)
    assert not (stub_tree / "live" / "cert.pem").is_symlink()
    assert (stub_tree / "live" / "cert.pem").read_text() == "../archive/cert1.pem"
    link_tree = _repo(tmp_path / "linux", symlinks=True)
    stub, link = scan_directory(stub_tree, settings=None), scan_directory(link_tree, settings=None)

    assert "live/cert.pem" not in [p if isinstance(p, str) else p.get("path")
                                   for p in stub["claimed_but_not_decoded"]]
    assert "live/cert.pem" not in stub["files_read"]
    entry = next(e for e in stub["symlinks_not_followed"] if e["path"] == "live/cert.pem")
    assert entry["checked_out_as_text"] is True
    assert entry["target"] == "archive/cert1.pem"
    for key in ("files_present", "files_examined", "files_not_examined", "coverage_pct"):
        assert stub["coverage"]["scope"][key] == link["coverage"]["scope"][key], key
    assert stub["coverage"]["corpus"]["content_digest"] == link["coverage"]["corpus"]["content_digest"]
