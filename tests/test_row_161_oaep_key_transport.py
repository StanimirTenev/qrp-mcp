"""ZA-OPRAVYANE row 161 (Joeri Barbier): pyca `pub.encrypt(k, padding.OAEP(...))` -- wrapping an
archive's AES key, the classic harvest-now-decrypt-later case -- came out `role: undetermined`
and `hndl_exposed: "not determined"`. The line says key transport; the rule's description
("... signature or padding name") said signature, and the two were read together. That
description no longer counts as a signature signal."""

from datetime import date

from qrp_mcp import mandates
from qrp_mcp.remediation import role_of
from qrp_mcp.scan import scan_directory

ARCHIVE = ("from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
           "from cryptography.hazmat.primitives import hashes\n"
           "def seal(k, pub):\n"
           "    return pub.encrypt(k, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), "
           "algorithm=hashes.SHA256(), label=None))\n")


def test_oaep_encrypt_is_key_establishment_and_hndl(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "archive.py").write_text(ARCHIVE)
    r = scan_directory(t)
    rows = [e for e in r["evidence"]["source_code"] if e["line"] == 4 and e["algorithm"] == "RSA"]
    assert rows and all(e["role"] == "key_establishment" for e in rows)
    mandates.apply(r, ["nist-ir-8547"], date(2026, 10, 30))
    assert all(e["hndl_exposed"] is True for e in rows)


def test_description_still_decides_a_silent_line():
    item = {"algorithm": "RSA", "excerpt": "k = load(x)", "description": "RSA signature"}
    assert role_of(item) == "signature"


def test_a_line_with_both_is_still_undetermined():
    item = {"algorithm": "RSA", "excerpt": "sign(x); decrypt(y)", "description": "RSA usage"}
    assert role_of(item) == "undetermined"
