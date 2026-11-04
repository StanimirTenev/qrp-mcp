"""A linked directory that points into the scanned tree hides nothing (fix list row 389).

Measured on 0.41.0 (W1 fixture 10b-junction-inside): `real/a.cs` and `alias` -> `real`. The
verdict said "This scan cannot account for every file: 1 linked directory was not followed,
so how many files they hold is unknown", while every file under the link's target had been
read under `real/`. The walk enters every directory of the root that is not itself a link, so
a link whose resolved target lies inside the root adds no file the scan did not see. A link
that points outside the root still keeps the claim from being made.
"""

import sys

import pytest

from qrp_mcp.scan import scan_directory

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")


@posix_only
def test_a_link_into_the_tree_keeps_the_statement_whole(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    (tmp_path / "alias").symlink_to(tmp_path / "real", target_is_directory=True)
    r = scan_directory(tmp_path)
    assert r["coverage"]["accounts_for_every_file"] is True
    assert "cannot account" not in r["verdict"]
    assert "alias/ points into the scanned tree (real/), which was walked" in r["verdict"]
    assert r["coverage"]["symlinks_not_followed"]["directories_into_tree"] == 1


@posix_only
def test_a_link_outside_still_withholds_the_claim(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir(); outside.mkdir()
    (repo / "real.py").write_text("x = 1\n")
    (repo / "alias").symlink_to(repo, target_is_directory=True)
    (repo / "out").symlink_to(outside, target_is_directory=True)
    r = scan_directory(repo)
    assert r["coverage"]["accounts_for_every_file"] is False
    assert "1 linked directory was not followed" in r["verdict"]
