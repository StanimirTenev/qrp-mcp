"""Rows 564-566 (crypto-asset probe, 25.11.2026): Solidity signature checks through OpenZeppelin.

On 0.53.0 a contract's P-256 check was invisible -- `P256.verify`, `P256.verifyNative`, a raw
staticcall to 0x100 (RIP-7212 P256VERIFY) gave no row, and OpenZeppelin's P-256 was seen only in its
comments; `RSA.pkcs1Sha256(...)` gave none; `SignatureChecker.isValidSignatureNow(...)` and the
using-for spelling `h.recover(sig)` gave none; `ECDSA.recover` gave ECDSA without a curve, though the
EVM's ECDSA is secp256k1 only.

Spellings from OpenZeppelin's sources (contracts/utils/cryptography/{P256,RSA,ECDSA,
SignatureChecker}.sol, https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/
contracts/utils/cryptography/), RIP-7212 (https://raw.githubusercontent.com/ethereum/RIPs/master/
RIPS/rip-7212.md: "PRECOMPILED_ADDRESS in 0x100").
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory

HEAD = ('pragma solidity ^0.8.24;\nimport {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";\n'
        'import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";\ncontract C {\n'
        '    using ECDSA for bytes32;\n')
CASES = [
    ("return P256.verify(h, r, s, qx, qy);", "ECDSA", "P-256"),
    ("return P256.verifyNative(h, r, s, qx, qy);", "ECDSA", "P-256"),
    ("return P256.verifySolidity(h, r, s, qx, qy);", "ECDSA", "P-256"),
    ("(bytes32 x, bytes32 y) = P256.recovery(h, v, r, s);", "ECDSA", "P-256"),
    ("return P256.isValidPublicKey(qx, qy);", "ECDSA", "P-256"),
    ("return WebAuthn.verify(challenge, auth, qx, qy);", "ECDSA", "P-256"),
    ("(ok, out) = address(0x100).staticcall(input);", "ECDSA", "P-256"),
    ("return RSA.pkcs1Sha256(digest, sig, e, n);", "RSA", None),
    ("return RSA.pkcs1Sha256(data, sig, e, n);", "RSA", None),
    ("return SignatureChecker.isValidSignatureNow(signer, h, sig);", "ECDSA", "secp256k1"),
    ("return SignatureChecker.isValidSignatureNowCalldata(signer, h, sig);", "ECDSA", "secp256k1"),
    ("return SignatureChecker.isValidERC1271SignatureNow(signer, h, sig);", "ECDSA", "secp256k1"),
    ("return ECDSA.recover(h, sig);", "ECDSA", "secp256k1"),
    ("return ECDSA.tryRecover(h, sig);", "ECDSA", "secp256k1"),
    ("return ECDSA.recoverCalldata(h, sig);", "ECDSA", "secp256k1"),
    ("return h.recover(sig);", "ECDSA", "secp256k1"),
    ("return MessageHashUtils.toEthSignedMessageHash(h).recover(sig);", "ECDSA", "secp256k1"),
    ("return h.tryRecover(sig);", "ECDSA", "secp256k1"),
]


@pytest.mark.parametrize("code, family, curve", CASES, ids=[c[0][:40] for c in CASES])
def test_the_check_has_a_row(tmp_path, code, family, curve):
    (tmp_path / "C.sol").write_text(HEAD + f"    function f() external view {{\n        {code}\n    }}\n}}\n")
    rows = [r for r in scan_directory(tmp_path)["evidence"]["source_code"]
            if r["line"] == 7 and r["algorithm"] == family]
    assert rows and rows[0]["evidence_kind"] == "call", rows
    if curve:
        assert rows[0].get("curve") == curve, rows[0]


def test_the_signer_contracts_are_named(tmp_path):
    (tmp_path / "A.sol").write_text(
        'pragma solidity ^0.8.24;\nimport {SignerP256} from "@openzeppelin/contracts/utils/cryptography/signers/SignerP256.sol";\n'
        'contract A is SignerP256 {}\ncontract B is SignerRSA {}\ncontract D is SignerWebAuthn {}\n')
    rows = {(r["line"], r["algorithm"]) for r in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert (3, "ECDSA") in rows and (4, "RSA") in rows and (5, "ECDSA") in rows


def test_recover_without_using_ecdsa_is_not_read(tmp_path):
    (tmp_path / "B.sol").write_text("pragma solidity ^0.8.24;\ncontract B {\n"
                                    "    function f() external { x.recover(y); }\n}\n")
    assert "ECDSA" not in scan_directory(tmp_path)["detected_algorithms"]


def test_outside_solidity_the_names_are_not_read(tmp_path):
    (tmp_path / "p.js").write_text("const ok = P256.verify(a, b);\nconst r = RSA.pkcs1Sha256(d);\n")
    algs = {r["algorithm"] for r in scan_directory(tmp_path)["evidence"]["source_code"]
            if r["evidence_kind"] == "call"}
    assert "ECDSA" not in algs
