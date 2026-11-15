"""Rows 460 and 461 (14.11.2026, the same blockchain probe as row 458; both recorded as an
agent's word and reproduced here on 0.44.0 on 15.11). 460: ethers `Wallet.createRandom()` gave
ECDSA with no curve, though ethers signs on secp256k1 only. 461: eth_keys
`keys.PrivateKey(...).sign_msg(...)` gave nothing at all in a file that was read. The
secp256k1 rule's library names now carry the curve, and eth_keys / eth_account are named.
`web3` alone is not given the curve: @solana/web3.js signs with Ed25519.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

ETHERS = ('import { ethers } from "ethers";\n'
          "const w = ethers.Wallet.createRandom();\n")
ETH_KEYS = ("from eth_keys import keys\n"
            'pk = keys.PrivateKey(b"\\x01" * 32)\n'
            'sig = pk.sign_msg(b"hello")\n')


def _ecdsa(result, path):
    return [o for o in result["evidence"]["source_code"]
            if o["path"] == path and o["algorithm"] == "ECDSA"]


def test_ethers_wallet_is_secp256k1(tmp_path):
    (tmp_path / "w.js").write_text(ETHERS)
    rows = _ecdsa(scan_directory(tmp_path), "w.js")
    assert rows and all(o.get("curve") == "secp256k1" and o.get("key_size") == 256 for o in rows)


def test_eth_keys_is_named(tmp_path):
    (tmp_path / "k.py").write_text(ETH_KEYS)
    rows = _ecdsa(scan_directory(tmp_path), "k.py")
    assert rows and rows[0].get("curve") == "secp256k1", rows


def test_web3_alone_gets_no_curve(tmp_path):
    (tmp_path / "s.js").write_text('import { Keypair } from "@solana/web3.js";\n'
                                   "const kp = Keypair.generate();\n")
    assert all(not o.get("curve") for o in _ecdsa(scan_directory(tmp_path), "s.js"))


def test_both_leave_by_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "w.js").write_text(ETHERS)
    (src / "k.py").write_text(ETH_KEYS)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    for result in (json.loads(out.read_text()), getattr(scan_repo, "fn", scan_repo)(str(src))):
        assert _ecdsa(result, "w.js")[0]["curve"] == "secp256k1"
        assert _ecdsa(result, "k.py")[0]["curve"] == "secp256k1"
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        assert any(c["name"] == "ECDSA-secp256k1" for c in b["components"]), [
            c["name"] for c in b["components"]]
