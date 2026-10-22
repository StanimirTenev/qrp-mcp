"""A file the second run skipped by type is unverifiable, not removed (ZA-OPRAVYANE row 59,
the summary probe of 22.10.2026).

An extensionless key file is read only for its first bytes; grown past the peek limit,
the second run skipped it by type. `prove_closure` read the unread files from
`unreadable_files`, `files_left_out`, `unreadable_directories` and `symlinks_not_followed`,
never from `coverage.not_examined[].paths`, so it said the RSA key was "removed -- the file
is not in the second tree" while the file was there, holding the same key. Run the way the
CLI writes its results: scan, level full, round-tripped as JSON.
"""

import json
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from qrp_mcp.closure import prove_closure
from qrp_mcp.scan import scan_directory


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _saved(root):
    result = scan_directory(root)
    result["excerpt_level"] = "full"
    # The emitter's own checkout may be dirty while this test runs; that is not the
    # change under test.
    result["coverage"]["instrument"]["source_commit"] = {"pinned": True, "commit": "t",
                                                         "dirty": False}
    return json.loads(json.dumps(result))


def test_skipped_key_file_is_unverifiable_not_removed(tmp_path):
    _git(tmp_path, "init", "-q", ".")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    (tmp_path / "signing_key").write_bytes(key)
    (tmp_path / "app.py").write_text("print('hi')\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "a")
    before = _saved(tmp_path)
    (tmp_path / "signing_key").write_bytes(key + b"#" * (70 * 1024) + b"\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "b")
    after = _saved(tmp_path)
    assert "signing_key" in after["coverage"]["not_examined"][0]["paths"]

    out = prove_closure(before, after)
    assert out["comparability"]["verdict"] == "comparable", out["comparability"]
    assert not [r for r in out["closure"]["removed"] if r["path"] == "signing_key"]
    assert any(u["path"] == "signing_key" for u in out["closure"]["unverifiable"])
