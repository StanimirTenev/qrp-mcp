"""Rows 391 and 392 (04.11.2026): "weak_key: false" for a key whose size was never read.

`KeyPairGenerator.getInstance("DSA"); dsa.initialize(1024);` -- the size is on the next line
and is not read -- gave DSA with `weak_key: false`: the tool said "not weak" about a 1024-bit
key. The keysize passed to `initialize` is the key length: "keysize - the keysize. This is an
algorithm-specific metric, such as modulus length, specified in number of bits"
(https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyPairGenerator.html).
Where the family has a size table (SP 800-131A Rev. 2) and no size was read, `weak_key` is now
None and the reason says it is not established."""

from __future__ import annotations

import json


def _finding(result, family):
    [f] = [f for f in result["findings"] if f["algorithm_family"] == family]
    return f


def test_unread_size_is_not_called_not_weak(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "K.java").write_text(
        "import java.security.KeyPairGenerator;\nclass K { void k() throws Exception {\n"
        '  KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");\n'
        "  dsa.initialize(1024);\n} }\n")
    f = _finding(scan_directory(tmp_path), "DSA")
    assert f["weak_key"] is None
    assert "not established" in f["reason"]


def test_read_size_still_decides(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import dsa, rsa\n"
        "a = dsa.generate_private_key(key_size=1024)\n"
        "b = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n")
    result = scan_directory(tmp_path)
    assert _finding(result, "DSA")["weak_key"] is True
    assert _finding(result, "RSA")["weak_key"] is False


def test_fixed_size_family_stays_false(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "e.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ed25519\n"
        "k = ed25519.Ed25519PrivateKey.generate()\n")
    assert _finding(scan_directory(tmp_path), "Ed25519")["weak_key"] is False


def test_cli_writes_null(tmp_path):
    import subprocess
    import sys
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "K.java").write_text(
        'class K { Object k = java.security.KeyPairGenerator.getInstance("DSA"); }\n')
    out = tmp_path / "r.json"
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tmp_path / "src"),
                    "--out", str(out)], check=False, capture_output=True)
    f = _finding(json.loads(out.read_text()), "DSA")
    assert f["weak_key"] is None
