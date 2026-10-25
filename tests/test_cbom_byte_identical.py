"""Two runs over one tree give one CBOM, byte for byte (release A, 05-novi-merki #6).

Measured 25.10.2026 on certbot: our CBOM differed between two runs only in
`metadata.timestamp` and the three `qrp:coverage:window:*` properties; snoot was the only
tool whose CBOM was byte-identical. A document that changes when nothing it describes
changed cannot be signed once and checked later.

The read time still exists and is still said: it lives in the scan result's
`coverage.window`. The CBOM's timestamp is the corpus's own commit time, or
SOURCE_DATE_EPOCH (the reproducible-builds convention), and is absent when neither
identifies the tree -- absent, not invented.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "e = ec.generate_private_key(ec.SECP256R1())\n")
    (root / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768:X25519;\n")
    env = dict(os.environ, GIT_COMMITTER_DATE="2026-10-01T12:00:00+00:00",
               GIT_AUTHOR_DATE="2026-10-01T12:00:00+00:00")
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                       env=env)
    return root


def _cbom_bytes(tree: Path, out: Path, seed: str, **extra: str) -> bytes:
    env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
    env.update(PYTHONPATH=str(SRC), PYTHONHASHSEED=seed, **extra)
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                    "--out", str(out)], check=True, capture_output=True, env=env)
    return out.read_bytes()


def test_two_runs_write_the_same_bytes(checkout, tmp_path):
    # Different hash seeds as well: an unordered set reaching the document would show here.
    first = _cbom_bytes(checkout, tmp_path / "1.json", "1")
    second = _cbom_bytes(checkout, tmp_path / "2.json", "2")
    assert first == second


def test_the_timestamp_is_the_commit_time_of_a_clean_checkout(checkout):
    doc = cyclonedx.build(scan_directory(checkout))
    assert doc["metadata"]["timestamp"] == "2026-10-01T12:00:00+00:00"
    props = {p["name"]: p["value"] for p in doc["properties"]}
    assert "commit" in props["qrp:timestamp_basis"]


def test_source_date_epoch_wins(checkout, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    doc = cyclonedx.build(scan_directory(checkout))
    assert doc["metadata"]["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_no_timestamp_is_invented_for_a_tree_nothing_identifies(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    doc = cyclonedx.build(scan_directory(tmp_path))
    assert "timestamp" not in doc["metadata"]
    props = {p["name"]: p["value"] for p in doc["properties"]}
    assert "not stated" in props["qrp:timestamp_basis"]


def test_the_read_window_is_named_not_silently_dropped(checkout):
    scan = scan_directory(checkout)
    props = {p["name"]: p["value"] for p in cyclonedx.build(scan)["properties"]}
    assert not any(name.startswith("qrp:coverage:window:") for name in props)
    assert "coverage.window" in props["qrp:coverage:window"]
    # And the scan result still carries it.
    assert scan["coverage"]["window"]["started_at"]
