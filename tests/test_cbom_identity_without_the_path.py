"""ZA-OPRAVYANE row 430 (the W2 cross-OS round, 04.11.2026): the CBOM's identity does not
depend on where the tree sits.

Two byte-identical certbot trees at `repos\\default\\certbot` and `repos\\nocrlf\\certbot` got
different `serialNumber`s, and `metadata.component.name` was the absolute Windows path, so two
auditors could never produce the same BOM identity for one commit. The serial is now a UUIDv5
over the commit pin, the instrument and the findings digest; the component is named by the
directory's own name and carries the commit as its version. A different result still changes
the serial (test_hardening.py).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory


def _tree(root):
    root.mkdir(parents=True)
    (root / "a.py").write_text("k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    return root


def test_the_same_tree_at_two_paths_has_one_identity(tmp_path):
    a = _tree(tmp_path / "one" / "certbot")
    b = tmp_path / "two" / "deeper" / "certbot"
    shutil.copytree(a, b)
    da, db = cyclonedx.build(scan_directory(a, settings=None)), cyclonedx.build(scan_directory(b, settings=None))
    assert da["serialNumber"] == db["serialNumber"]
    assert da["metadata"]["component"] == db["metadata"]["component"]
    assert da["metadata"]["component"]["name"] == "certbot"
    assert str(tmp_path) not in da["metadata"]["component"]["bom-ref"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_a_pinned_tree_carries_its_commit_as_the_version(tmp_path):
    a = _tree(tmp_path / "repo")
    run = dict(cwd=a, check=True, capture_output=True)
    subprocess.run(["git", "init", "-q"], **run)
    subprocess.run(["git", "add", "."], **run)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit",
                    "-qm", "x"], **run)
    head = subprocess.run(["git", "rev-parse", "HEAD"], text=True, **run).stdout.strip()
    assert cyclonedx.build(scan_directory(a, settings=None))["metadata"]["component"]["version"] == head
