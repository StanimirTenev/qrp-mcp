"""ZA-OPRAVYANE rows 562 and 563 (crypto-asset probe, 25.11.2026): pairing-based cryptography.

A pairing e: G1 x G2 -> GT over BN254 (alt_bn128) or BLS12-381 is the base of the zk-SNARKs
Ethereum verifies (Groth16, PLONK with KZG), of KZG polynomial commitments (EIP-4844 blobs) and of
the EVM's curve precompiles. Its security rests on discrete logarithms in G1, G2 and GT, which
Shor's algorithm computes. On 0.53.0 none of it had a row: py_ecc, snarkjs (library and CLI), gnark,
arkworks, c-kzg and the precompiles 0x06/0x07/0x08/0x0a/0x0b-0x11 were read and gave nothing, so the
scan could not say they are quantum-vulnerable.

A family `Pairing`, classical and quantum-vulnerable, with its own role `proof`: not a signature
(a Groth16 verifier is not replaced by ML-DSA), and no replacement is named. Hashes used inside
circuits (Poseidon, keccak) and hash-based proof systems (STARK/FRI) are not pairings.

Spellings from the libraries' own documents (saved copies in
qrp-kachestvo/roy-2026-11-25-kripto/docs, URLs in tools/urls.tsv):
  py_ecc README        https://raw.githubusercontent.com/ethereum/py_ecc/main/README.md
  snarkjs README       https://raw.githubusercontent.com/iden3/snarkjs/master/README.md
  gnark README         https://raw.githubusercontent.com/Consensys/gnark/master/README.md
  ark-groth16 README   https://raw.githubusercontent.com/arkworks-rs/groth16/master/README.md
  ark-bn254 docs       https://docs.rs/ark-bn254/latest/ark_bn254/
  c-kzg-4844 bindings  https://raw.githubusercontent.com/ethereum/c-kzg-4844/main/bindings/python/README.md
                       https://raw.githubusercontent.com/ethereum/c-kzg-4844/main/bindings/node.js/README.md
  noble-curves README  https://raw.githubusercontent.com/paulmillr/noble-curves/main/README.md
  EIP-196 (0x6, 0x7), EIP-197 (0x8), EIP-4844 (0x0A), EIP-2537 (0x0b-0x11)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qrp_mcp import server
from qrp_mcp.scan import scan_directory


def _rows(result, path):
    return {(r["line"], r["algorithm"]): r for r in result["evidence"]["source_code"]
            if r["path"] == path}


def _scan(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return scan_directory(tmp_path)


CASES = [
    # (file, body, line, curve or None)
    # The import alone (with a call in the file, the call's row covers the import's).
    ("bls.py", "from py_ecc.optimized_bn128 import pairing, G1, G2, multiply\n", 1, "BN254"),
    ("bls2.py", "from py_ecc.optimized_bn128 import pairing, G1, G2, multiply\n"
                "e = pairing(G2, multiply(G1, 5))\n", 2, "BN254"),
    ("bls3.py", "from py_ecc import bn128\n"
                "e = bn128.pairing(bn128.G2, bn128.G1)\n", 2, "BN254"),
    ("kzg.py", "import ckzg\n"
               "ts = ckzg.load_trusted_setup(\"trusted_setup.txt\", 0)\n", 2, "BLS12-381"),
    ("kzg2.py", "import ckzg\n"
                "commitment = ckzg.blob_to_kzg_commitment(blob, ts)\n", 2, "BLS12-381"),
    ("kzg3.py", "import ckzg\n"
                "ok = ckzg.verify_blob_kzg_proof(blob, commitment, proof, ts)\n", 2, "BLS12-381"),
    ("kzg.js", "const { loadTrustedSetup, blobToKzgCommitment } = require(\"c-kzg\");\n"
               "const commitment = blobToKzgCommitment(blob);\n", 2, "BLS12-381"),
    ("kzg2.js", "const { verifyBlobKzgProofBatch } = require(\"c-kzg\");\n"
                "const ok = verifyBlobKzgProofBatch([blob], [commitment], [proof]);\n", 2, "BLS12-381"),
    ("snark.js", "const snarkjs = require(\"snarkjs\");\n"
                 "const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, \"c.wasm\", \"c.zkey\");\n",
     2, None),
    ("snark2.js", "const snarkjs = require(\"snarkjs\");\n"
                  "const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);\n", 2, None),
    ("snark3.js", "const snarkjs = require(\"snarkjs\");\n"
                  "const p2 = await snarkjs.plonk.fullProve(input, \"c.wasm\", \"c.zkey\");\n", 2, None),
    ("noble.js", "import { bn254 } from '@noble/curves/bn254.js';\n"
                 "const Fr = bn254.fields.Fr;\n", 2, "BN254"),
    ("ceremony.sh", "#!/bin/sh\nsnarkjs powersoftau new bn128 14 pot14_0000.ptau -v\n", 2, "BN254"),
    ("setup.sh", "#!/bin/sh\nsnarkjs groth16 setup circuit.r1cs pot14_final.ptau circuit_0000.zkey\n", 2, None),
    ("plonk.sh", "#!/bin/sh\nsnarkjs plonk setup circuit.r1cs pot14_final.ptau circuit_final.zkey\n", 2, None),
    ("gnark.go", "package main\n\nimport (\n\t\"github.com/consensys/gnark-crypto/ecc\"\n"
                 "\t\"github.com/consensys/gnark/backend/groth16\"\n)\n\nfunc run() {\n"
                 "\tpk, vk, _ := groth16.Setup(ccs)\n\t_ = ecc.BN254\n}\n", 9, None),
    ("gnark2.go", "package main\n\nimport (\n\t\"github.com/consensys/gnark-crypto/ecc\"\n"
                  "\t\"github.com/consensys/gnark/frontend\"\n)\n\nfunc run() {\n"
                  "\tccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)\n}\n", 9, "BN254"),
    ("gnark3.go", "package main\n\nimport \"github.com/consensys/gnark/backend/plonk\"\n\nfunc run() {\n"
                  "\tproof, _ := plonk.Prove(ccs, pk, witness)\n}\n", 6, None),
    ("groth.rs", "use ark_bn254::{Bn254, Fr};\nuse ark_groth16::Groth16;\nfn main() {\n"
                 "    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();\n}\n", 4, "BN254"),
    ("groth2.rs", "use ark_bn254::{Bn254, Fr};\nfn main() {}\n", 1, "BN254"),
]


@pytest.mark.parametrize("name, body, line, curve", CASES, ids=[c[0] for c in CASES])
def test_a_pairing_spelling_has_a_row(tmp_path, name, body, line, curve):
    result = _scan(tmp_path, name, body)
    rows = _rows(result, name)
    assert (line, "Pairing") in rows, sorted(rows)
    row = rows[(line, "Pairing")]
    if curve:
        assert row.get("curve") == curve, row
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "Pairing")
    assert finding["classification"] == "classical_vulnerable"


SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Groth16Verifier {
    function add(uint256[4] memory input) internal view returns (uint256[2] memory r) {
        assembly { if iszero(staticcall(gas(), 0x06, input, 0x80, r, 0x40)) { revert(0, 0) } }
    }
    function mul(uint256[3] memory input) internal view returns (uint256[2] memory r) {
        assembly { if iszero(staticcall(gas(), 0x07, input, 0x60, r, 0x40)) { revert(0, 0) } }
    }
    function pairing(uint256[24] memory input) internal view returns (bool) {
        uint256[1] memory out;
        assembly { if iszero(staticcall(gas(), 0x08, input, 768, out, 0x20)) { revert(0, 0) } }
        return out[0] == 1;
    }
    function pointEval(bytes memory input) internal view returns (bool ok) {
        (ok, ) = address(0x0a).staticcall(input);
    }
    function blsPairing(bytes memory input) internal view returns (bool ok) {
        (ok, ) = address(0x0f).staticcall(input);
    }
    function old(uint256[24] memory input) internal view returns (bool ok) {
        assembly { ok := staticcall(sub(gas(), 2000), 8, input, 768, input, 0x20) }
    }
    function g1msm(bytes memory input) internal view returns (bool ok) {
        (ok, ) = address(0x0C).staticcall(input);
    }
    function sha(bytes memory input) internal view returns (bool ok) {
        (ok, ) = address(0x02).staticcall(input);
        uint8 small = 0x08;
    }
}
"""


def test_the_evm_precompiles_are_read_on_the_address(tmp_path):
    result = _scan(tmp_path, "Verifier.sol", SOL)
    rows = _rows(result, "Verifier.sol")
    for line, curve in ((5, "BN254"), (8, "BN254"), (12, "BN254"), (16, "BLS12-381"),
                        (19, "BLS12-381"), (22, "BN254"), (25, "BLS12-381")):
        assert (line, "Pairing") in rows, (line, sorted(rows))
        assert rows[(line, "Pairing")]["curve"] == curve
        assert rows[(line, "Pairing")]["evidence_kind"] == "call"
    # SHA-256 at 0x02, and a byte 0x08 that is no address, are not pairings.
    assert (28, "Pairing") not in rows and (29, "Pairing") not in rows


def test_a_commented_precompile_is_not_a_call(tmp_path):
    body = ("contract A {\n    // staticcall(gas(), 0x08, input, 768, out, 0x20)\n"
            "    /* (ok, ) = address(0x0a).staticcall(input);\n"
            "       staticcall(gas(), 0x07, input, 0x60, r, 0x40) */\n}\n")
    rows = _rows(_scan(tmp_path, "A.sol", body), "A.sol")
    assert not [k for k, r in rows.items() if k[1] == "Pairing" and r["evidence_kind"] == "call"]


def test_a_solidity_comment_is_a_comment(tmp_path):
    """Solidity's comments were read as code until 0.54.0 (`.sol` had no comment syntax)."""
    body = ("/**\n * @dev Verifies a secp256r1 (P-256) signature. RSA is not used here.\n */\n"
            "contract A {\n    uint256 x; // ecrecover is not called\n}\n")
    result = _scan(tmp_path, "A.sol", body)
    assert all(r["evidence_kind"] == "comment" for r in result["evidence"]["source_code"])


@pytest.mark.parametrize("name, body", [
    ("hash.circom.js", "const h = poseidon([1, 2]);\nconst k = keccak256(data);\n"),
    ("stark.rs", "use winterfell::FriOptions;\nlet proof = winterfell::prove::<Air>(trace, opts);\n"),
    ("plonk.py", "# the plonk is a plank of wood\nplonk = 3\n"),
    ("kzg_words.go", "package p\n\nfunc kzgish() {}\n"),
    ("pairing_word.py", "def pairing(a, b):\n    return (a, b)\nx = pairing(1, 2)\n"),
], ids=["poseidon-keccak", "stark-fri", "plonk-word", "kzgish", "pairing-word"])
def test_what_is_not_a_pairing(tmp_path, name, body):
    result = _scan(tmp_path, name, body)
    assert "Pairing" not in result["detected_algorithms"]


def test_a_proof_system_is_its_own_role_not_a_signature(tmp_path):
    """By role: a Groth16 verifier is `proof`, not `signature` -- read as a signature, the output
    would say "replace with ML-DSA" for a SNARK."""
    (tmp_path / "snark.js").write_text(
        "const snarkjs = require(\"snarkjs\");\n"
        "const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);\n")
    result = scan_directory(tmp_path)
    by_role = result["summary"]["by_role"]
    assert "Pairing" not in by_role["signature"]["families"]
    assert by_role["proof"]["families"] == ["Pairing"]
    assert by_role["proof"]["pqc_readiness"] == "classical_only"
    assert result["summary"]["readiness_by_role"]["proof"] == "classical_only"
    remediation = json.dumps([f.get("remediation") for f in result["findings"]
                              if f["algorithm_family"] == "Pairing"])
    assert "ML-DSA" not in remediation


def test_a_scan_without_a_pairing_has_no_proof_part(tmp_path):
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP256R1())\n")
    assert "proof" not in scan_directory(tmp_path)["summary"]["by_role"]


def test_through_the_command_line_and_the_cbom(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "Verifier.sol").write_text(SOL)
    out = tmp_path / "out.json"
    assert server.scan_to_file([str(tree), "--no-config", "--out", str(out)]) in (0, 1)
    result = json.loads(out.read_text())
    assert "Pairing" in result["detected_algorithms"]
    cbom = tmp_path / "cbom.json"
    server.scan_to_file([str(tree), "--no-config", "--out", str(cbom)], cbom=True)
    doc = json.loads(cbom.read_text())
    names = [c.get("name", "") for c in doc.get("components", [])]
    assert any("Pairing" in n for n in names), names
