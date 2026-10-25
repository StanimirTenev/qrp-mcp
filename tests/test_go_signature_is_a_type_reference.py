"""A Go function signature names a type, it does not call anything (qrp-pokazateli 02-tochnost).

`func demo(pub *rsa.PublicKey) {` was reported as a `call`, and on Cryben 9 of 0.36.0's 32
rows off the reference were such signatures, one line above the call they introduce. The
signature is a type reference; where a call of the same family follows within two lines,
the call is the occurrence and the signature is not a second row (measured: -8 off-reference
rows, no reference row lost).
"""

from pathlib import Path

from qrp_mcp import detectors


def _rows(lines: list[str], name: str = "a.go") -> list[tuple[int, str, str]]:
    found = detectors.scan_source_file(Path(name), name, lines=lines)
    return [(f["line"], f["algorithm"], f["evidence_kind"]) for f in found]


def test_signature_alone_is_a_type_reference_not_a_call():
    rows = _rows(["package main", "func other(k *ecdsa.PrivateKey) error {", "\treturn nil", "}"])
    assert rows == [(2, "ECDSA", "reference")]


def test_signature_followed_by_a_call_of_the_same_family_is_one_row():
    rows = _rows(["package main",
                  "func demo(pub *rsa.PublicKey) {",
                  "\trsa.EncryptPKCS1v15(nil, pub, nil)",
                  "}"])
    assert rows == [(3, "RSA", "call")]


def test_same_family_group_merges():
    # ecdsa.PublicKey in the signature, elliptic.P256 call: both EC family group.
    rows = _rows(["func v(pub *ecdsa.PublicKey, h []byte) bool {",
                  "\treturn ecdsa.VerifyASN1(pub, h, sig)", "}"])
    assert [r for r in rows if r[0] == 1] == []
    assert (2, "ECDSA", "call") in rows


def test_a_call_further_away_does_not_absorb_the_signature():
    rows = _rows(["func demo(pub *rsa.PublicKey) {", "\ta := 1", "\tb := 2", "\tc := 3",
                  "\trsa.EncryptPKCS1v15(nil, pub, nil)", "}"])
    assert (1, "RSA", "reference") in rows and (5, "RSA", "call") in rows


def test_method_receiver_signature_and_other_languages_unchanged():
    assert _rows(["func (s *Signer) Sign(k *rsa.PrivateKey) {", "}"]) == [(1, "RSA", "reference")]
    # A C definition keeps its kind: only Go's `func` is read this way.
    c = _rows(["int f(RSA *r) { return RSA_size(r); }"], "a.c")
    assert all(kind == "call" for _, _, kind in c)
