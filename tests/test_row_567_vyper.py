"""Row 567 (crypto-asset probe, 25.11.2026): Vyper contracts (`.vy`) are read.

On 0.53.0 `.vy` was not read (`files_skipped_by_type: {".vy": 1}`), so `ecrecover(h, v, r, s)` and
`ecmul` (BN254) were invisible. Vyper's built-ins (docs/built-in-functions.rst,
https://raw.githubusercontent.com/vyperlang/vyper/master/docs/built-in-functions.rst): `ecadd` and
`ecmul` "Take two points on the Alt-BN128 curve" / "a point on the Alt-BN128 curve", `ecrecover`
"Recover the address associated with the public key from the given elliptic curve signature".
Vyper's comments are `#` and its docstrings are Python's: neither is a use.
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory

VY = '''# @version ^0.4.0

@external
@view
def recover(h: bytes32, v: uint8, r: bytes32, s: bytes32) -> address:
    """
    @notice Uses ecrecover; ecmul is mentioned here only.
    """
    return ecrecover(h, v, r, s)

@external
@view
def mul(p: uint256[2], k: uint256) -> uint256[2]:
    return ecmul(p, k)

@external
@view
def add(a: uint256[2], b: uint256[2]) -> uint256[2]:
    # ecadd below
    return ecadd(a, b)
'''


def test_vyper_is_read(tmp_path):
    (tmp_path / "verify.vy").write_text(VY)
    result = scan_directory(tmp_path)
    assert "verify.vy" in result["files_read"]
    rows = {(r["line"], r["algorithm"]): r for r in result["evidence"]["source_code"]}
    assert rows[(9, "ECDSA")]["evidence_kind"] == "call"
    assert rows[(9, "ECDSA")].get("curve") == "secp256k1"
    assert rows[(14, "Pairing")]["curve"] == "BN254"
    assert rows[(20, "Pairing")]["evidence_kind"] == "call"
    for (line, _), r in rows.items():
        if line in (7, 19):
            assert r["evidence_kind"] == "comment", r
