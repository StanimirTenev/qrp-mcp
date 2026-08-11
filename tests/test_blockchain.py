"""The blockchain detectors: a wallet/contract codebase must not come back empty."""

from __future__ import annotations

from pathlib import Path

from qrp_mcp.scan import scan_directory


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_solidity_ecrecover_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, "contracts/Vault.sol", """
pragma solidity ^0.8.20;
contract Vault {
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
""")
    result = scan_directory(tmp_path)
    assert "ECDSA" in result["detected_algorithms"]
    assert result["summary"]["quantum_vulnerable_count"] >= 1


def test_ethers_wallet_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, "src/sign.ts", "import { ethers } from 'ethers';\nconst w = ethers.Wallet.createRandom();\n")
    result = scan_directory(tmp_path)
    assert "ECDSA" in result["detected_algorithms"]


def test_bitcoin_secp256k1_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, "wallet.js", "const ecc = require('tiny-secp256k1');\n")
    result = scan_directory(tmp_path)
    assert "ECDSA" in result["detected_algorithms"]


def test_solana_ed25519_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, "program/src/lib.rs", "use solana_program::entrypoint;\n")
    result = scan_directory(tmp_path)
    assert "Ed25519" in result["detected_algorithms"]

    ed = next(f for f in result["findings"] if f["algorithm_family"] == "Ed25519")
    assert ed["classification"] == "classical_vulnerable"


def test_bls_and_schnorr_are_classified_as_vulnerable(tmp_path: Path) -> None:
    _write(tmp_path, "consensus.go", "// aggregate via bls12-381\n// verify BIP340 schnorr sigs\n")
    result = scan_directory(tmp_path)

    assert "BLS" in result["detected_algorithms"]
    assert "Schnorr" in result["detected_algorithms"]

    families = {f["algorithm_family"]: f for f in result["findings"]}
    assert families["BLS"]["classification"] == "classical_vulnerable"
    assert families["Schnorr"]["classification"] == "classical_vulnerable"


def test_a_pure_pqc_chain_project_is_not_flagged(tmp_path: Path) -> None:
    """Guard against the detectors firing on any blockchain file regardless of content."""
    _write(tmp_path, "node.rs", "// signatures use ML-DSA-65 only\n")
    result = scan_directory(tmp_path)
    assert result["summary"]["quantum_vulnerable_count"] == 0
