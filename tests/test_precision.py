"""Precision: the axis a second comparison found this scanner losing on.

Measured 19.09.2026 on Cryben, with its authors' own scorer: precision 0.542
against the nearest rival's 0.93, at the same recall. The largest single item in
that gap is not a wrong finding. It is the same finding reported twice -- once
where the module is imported and once where it is called. Of 24 rows the
reference did not place, 20 were import lines two lines from the call.

An import is real evidence and is worth keeping when it is all there is. It is
not worth a row of its own when the call it enables is in the same file.
"""
from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def rows(tmp_path, name: str, body: str) -> list[tuple[int, str]]:
    (tmp_path / name).write_text(body)
    result = scan_directory(tmp_path)
    return [(e["line"], e["algorithm"]) for e in result["evidence"]["source_code"]]


def test_an_import_is_not_reported_beside_the_call_it_enables(tmp_path):
    body = (
        'package main\n'
        '\n'
        'import (\n'
        '\t"crypto/rand"\n'
        '\t"crypto/rsa"\n'
        ')\n'
        '\n'
        'func demo() {\n'
        '\tkey, _ := rsa.GenerateKey(rand.Reader, 2048)\n'
        '\t_ = key\n'
        '}\n'
    )
    found = rows(tmp_path, "a.go", body)
    assert [line for line, family in found if family == "RSA"] == [9], found


def test_an_import_alone_is_still_reported(tmp_path):
    """A file that imports a cryptographic module and never calls it is still
    evidence the module is in the build. Dropping it would trade a duplicate for
    a miss."""
    body = 'package main\n\nimport "crypto/rsa"\n\nvar unused = 1\n'
    found = rows(tmp_path, "b.go", body)
    assert [line for line, family in found if family == "RSA"] == [3], found


def test_each_family_is_judged_on_its_own(tmp_path):
    """An RSA call must not suppress the DSA import in the same file."""
    body = (
        'import (\n'
        '\t"crypto/rsa"\n'
        '\t"crypto/dsa"\n'
        ')\n'
        '\n'
        'k, _ := rsa.GenerateKey(rand.Reader, 2048)\n'
    )
    found = rows(tmp_path, "c.go", body)
    families = {family: line for line, family in found}
    assert families.get("RSA") == 6
    assert families.get("DSA") == 3


def test_python_import_and_call(tmp_path):
    body = (
        'from cryptography.hazmat.primitives.asymmetric import rsa\n'
        '\n'
        'def make():\n'
        '    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n'
    )
    found = rows(tmp_path, "a.py", body)
    assert [line for line, family in found if family == "RSA"] == [4], found


def test_the_finding_says_how_it_was_learned(tmp_path):
    """`evidence_kind` -- asked for by the external audit and by the README's own
    list of what is missing. A bare word in a comment and a real call site must
    not look alike."""
    (tmp_path / "a.go").write_text(
        'import "crypto/rsa"\n'
        '// we should drop rsa here one day\n'
        'k, _ := rsa.GenerateKey(rand.Reader, 2048)\n')
    kinds = {e["line"]: e.get("evidence_kind")
             for e in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert kinds.get(3) == "call"


def test_a_match_inside_a_comment_is_marked_as_one(tmp_path):
    (tmp_path / "a.c").write_text("/* this module used to call RSA_generate_key */\n")
    found = scan_directory(tmp_path)["evidence"]["source_code"]
    assert found and all(e["evidence_kind"] == "comment" for e in found)


def test_a_comment_match_is_not_a_use(tmp_path):
    """The rival strips comments before matching. This tool keeps them and says
    what they are, which is more information, not less -- but a comment must not
    be the only thing standing behind a reported algorithm."""
    (tmp_path / "a.py").write_text("# migrate away from ecdsa before 2030\n")
    result = scan_directory(tmp_path)
    assert result["evidence"]["source_code"][0]["evidence_kind"] == "comment"
    assert result["summary"]["quantum_vulnerable_count"] == 0
    assert result["detected_algorithms"] == []
    assert result["named_but_not_used"] == ["ECDSA"]


# --- Go call sites whose absence left the import standing alone ---------------

@pytest.mark.parametrize("line,family", [
    ("\t_, _ = des.NewCipher(key)", "DES"),
    ("\t_, _ = des.NewTripleDESCipher(key)", "3DES"),
    ("\t_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)", "ECDSA"),
    ("\t_, _ = ecdsa.SignASN1(rand.Reader, priv, digest[:])", "ECDSA"),
    ("\tok := ecdsa.VerifyASN1(pub, digest[:], sig)", "ECDSA"),
    ("\t_ = ed25519.Sign(priv, []byte(\"msg\"))", "Ed25519"),
    ("\tok := ed25519.Verify(pub, msg, sig)", "Ed25519"),
    ("\tpub, priv, _ := ed25519.GenerateKey(rand.Reader)", "Ed25519"),
    ("\tcurve := elliptic.P384()", "EC"),
    ("\t_, _ = ecdh.P256().GenerateKey(rand.Reader)", "ECDH"),
])
def test_a_go_call_site_is_read_so_the_import_need_not_stand_alone(tmp_path, line, family):
    """Measured on Cryben: 10 rows the reference did not place were imports left
    standing because the call two lines below was not recognised. Reading the call
    fixes the location and removes the duplicate in one move."""
    (tmp_path / "a.go").write_text('import "crypto/x"\n\nfunc f() {\n' + line + '\n}\n')
    result = scan_directory(tmp_path)
    found = [(e["line"], e["algorithm"]) for e in result["evidence"]["source_code"]]
    assert (4, family) in found, found
