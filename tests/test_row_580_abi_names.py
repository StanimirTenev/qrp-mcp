"""ZA-OPRAVYANE row 580 (crypto-asset probe, 25.11.2026): a contract's function name is not Kyber.

go-ethereum ships a database of 4-byte function selectors (`signer/fourbyte/4byte.json`), one line
per function: `"4fb7db3f": "KYBER_PROXY()"`. Ten of them name Kyber Network's contracts (a DeFi
exchange). On 0.53.0 the ten lines were read as round-3 Kyber `call` rows, and a scan of go-ethereum's
crypto/ accounts/ p2p/ signer/ summed up key establishment as `hybrid_pre_standard`, from nothing
but those names.

Rule 132 (24.10.2026) makes an algorithm name that is a whole component of an identifier a finding.
The owner's exception (25.11.2026): the name of a contract function -- a 4-byte selector's signature,
an ABI entry's `name` -- is an identifier, never algorithm evidence, whatever family it names. In a
Solidity source a Kyber name is an identifier too: a KEM is not run in a contract. A KEM named by its
own words (`kyber768`, `pqcrystals`, liboqs) is still read.
"""

from __future__ import annotations

import json
from pathlib import Path

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

FOURBYTE = """{
  "29f7fc9e": "KYBER_ETH_ADDRESS()",
  "4fb7db3f": "KYBER_PROXY()",
  "9cf18987": "kyber2UniswapArb(address,uint256)",
  "a2d10ba5": "kyber()",
  "1626ba7e": "isValidSignature(bytes32,bytes)",
  "deadbeef": "rsaVerify(bytes,bytes)"
}
"""
ABI = """[
  {
    "inputs": [],
    "name": "KYBER_PROXY",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  }
]
"""
ABI_COMPACT = ('[{"inputs":[],"name":"KYBER_NETWORK","outputs":[{"internalType":"address",'
               '"name":"","type":"address"}],"stateMutability":"view","type":"function"}]\n')
SOL = """pragma solidity ^0.8.0;
contract Swap {
    address constant KYBER_PROXY = 0x9AAb3f75489902f3a48495025729a0AF77d4b11e;
    function kyber() external view returns (address) { return KYBER_PROXY; }
}
"""


KEX_GO = """package p2p

import "crypto/ecdh"

func Key() (*ecdh.PrivateKey, error) {
\treturn ecdh.X25519().GenerateKey(nil)
}
"""


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


def _kyber_rows(result):
    return [r for r in result["evidence"]["source_code"] if r["algorithm"] == "Kyber"]


def test_selector_and_abi_names_are_identifiers(tmp_path):
    tree = _tree(tmp_path / "t", {"signer/fourbyte/4byte.json": FOURBYTE, "abi/Kyber.json": ABI,
                                  "abi/compact.json": ABI_COMPACT, "contracts/Swap.sol": SOL,
                                  "p2p/kex.go": KEX_GO})
    result = scan_directory(tree)
    rows = _kyber_rows(result)
    assert rows, "the names stay in the evidence, as identifiers"
    assert {r["evidence_kind"] for r in rows} == {"identifier"}, rows
    # Every family, not only Kyber: the RSA name of a selector is no RSA use either.
    rsa = [r for r in result["evidence"]["source_code"]
           if r["algorithm"] == "RSA" and r["path"].endswith("4byte.json")]
    assert all(r["evidence_kind"] == "identifier" for r in rsa)
    summary = result["summary"]
    assert summary["readiness_by_role"]["key_establishment"] != "hybrid_pre_standard"
    assert summary["by_role"]["key_establishment"]["pqc_readiness"] in ("none_found", "classical_only")
    assert not any(f["algorithm_family"] == "Kyber" and not f.get("identifier_only")
                   for f in result["findings"])


def test_through_the_command_line_the_mcp_tool_and_the_cbom(tmp_path):
    # With a classical key exchange beside it, as in go-ethereum's p2p/: the Kyber names made it
    # `hybrid_pre_standard`.
    tree = _tree(tmp_path / "t", {"signer/fourbyte/4byte.json": FOURBYTE, "p2p/kex.go": KEX_GO})
    out = tmp_path / "out.json"
    server.scan_to_file([str(tree), "--no-config", "--out", str(out)])
    cli = json.loads(out.read_text())
    assert cli["summary"]["readiness_by_role"]["key_establishment"] != "hybrid_pre_standard"
    tool = server.scan_repo(str(tree))
    tool = json.loads(tool) if isinstance(tool, str) else tool
    assert tool["summary"]["readiness_by_role"]["key_establishment"] != "hybrid_pre_standard"
    cbom = tmp_path / "cbom.json"
    server.scan_to_file([str(tree), "--no-config", "--out", str(cbom)], cbom=True)
    text = cbom.read_text()
    assert "hybrid_pre_standard" not in text


def test_a_kem_named_by_its_own_words_is_still_read(tmp_path):
    tree = _tree(tmp_path / "t", {
        "kem.c": "#include <oqs/oqs.h>\nOQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);\n",
        "params.json": '{\n  "kem": "kyber768"\n}\n',
        "pq.py": "from pqcrystals import kyber768\npk, sk = kyber768.keypair()\n",
    })
    rows = _kyber_rows(scan_directory(tree))
    used = {r["path"] for r in rows if r["evidence_kind"] not in ("identifier", "comment")}
    assert {"kem.c", "params.json", "pq.py"} <= used, rows
