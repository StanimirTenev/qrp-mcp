"""What an RFC 8784 preshared key protects, and when it protects nothing (ZA-OPRAVYANE
rows 57 and 58, the summary probe of 22.10.2026).

Row 57: one PPK line made the whole tree `mechanism_protected`, with RSA signing in
another file -- `elif mechanisms:` came before `elif vulnerable:`, the precedence shape
row 11 fixed for broken post-quantum schemes. A preshared key mixed into IKEv2 protects
the IKE exchange it is configured for, not a signature made somewhere else. The PPK
finding now names the families it `protects` (those used in the files that configure it),
and the summary says `mechanism_protected` only when every quantum-vulnerable family is
among them. Per family, not per occurrence: EC in the IKE file and EC elsewhere is one
family, and that limit is stated.

Row 58: `ppk_required = no` was read as protection. The rule read the key, not its value;
strongSwan falls back to a classical exchange without the PPK when the peer has none. Such
a PPK protects nothing and says it is optional.
"""

from qrp_mcp.scan import scan_directory

IKE = "conn host\n  ike_proposals = aes256-sha256-ecp384\n  ppk_id = mykey\n  ppk_required = yes\n"
OPTIONAL = "conn host\n  ike_proposals = aes256-sha256-ecp384\n  ppk_id = mykey\n  ppk_required = no\n"
SIGN = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        "sig = key.sign(data, padding.PSS(), hashes.SHA256())\n")


def _scan(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def _ppk(result):
    return next(f for f in result["findings"] if f["algorithm_family"] == "PPK (RFC 8784)")


def test_ppk_does_not_cover_rsa_signing_elsewhere(tmp_path):
    result = _scan(tmp_path, {"swanctl.conf": IKE, "sign.py": SIGN})
    assert "RSA" not in _ppk(result)["protects"]
    assert result["summary"]["pqc_readiness"] == "classical_only"


def test_ppk_still_protects_its_own_exchange(tmp_path):
    result = _scan(tmp_path, {"swanctl.conf": IKE})
    assert "EC" in _ppk(result)["protects"]
    assert result["summary"]["pqc_readiness"] == "mechanism_protected"


def test_optional_ppk_is_not_protection(tmp_path):
    result = _scan(tmp_path, {"swanctl.conf": OPTIONAL})
    ppk = _ppk(result)
    assert ppk["protects"] == []
    assert "optional" in ppk["reason"]
    assert result["summary"]["pqc_readiness"] == "classical_only"
