"""ZA-OPRAVYANE row 598 (measurement on OWASP Juice Shop c9f9922, 25.11.2026): the bare word of a
wallet library is not ECDSA.

On 0.53.0 (and popravki-054 5316656) the secp256k1 rule matched `\\bweb3\\b` and `\\bethers\\b`
anywhere: Juice Shop's routes, Angular component names, tags, test titles and 215 i18n strings
saying "web3", and ethers' unit helpers (`ethers.utils.parseUnits`, `formatEther`) -- 317 of 393
occurrences in the tree were ECDSA rows with nothing signed. With libcalls.py, ethers and web3 are
read as libraries: an import plus a key or signing call gives ECDSA secp256k1; the word alone, or the
import alone, gives nothing.
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory

NOT_CRYPTO = {
    "app.routing.ts": "const routes = [{ path: 'web3-sandbox', component: Web3SandboxComponent }]\n",
    "en.json": '{\n  "TITLE_WEB3_SANDBOX": "Web3 Code Sandbox",\n  "NAV_WEB3": "web3 wallet"\n}\n',
    "web3.spec.ts": "describe('web3 sandbox', () => { it('loads web3', () => {}) })\n",
    "faucet.component.ts": ("import { ethers } from 'ethers'\n"
                            "const v = ethers.utils.parseUnits(amount, 'ether')\n"
                            "const s = ethers.utils.formatEther(balance)\n"
                            "const c = new ethers.Contract(address, abi, signer)\n"),
    "server.py": "from web3 import Web3\nw3 = Web3(Web3.HTTPProvider(url))\nn = w3.eth.block_number\n",
}


def test_the_word_or_the_import_alone_is_not_ecdsa(tmp_path):
    for name, body in NOT_CRYPTO.items():
        (tmp_path / name).write_text(body)
    result = scan_directory(tmp_path)
    ecdsa = [(r["path"], r["line"]) for r in result["evidence"]["source_code"] if r["algorithm"] == "ECDSA"]
    assert ecdsa == [], ecdsa
    assert "ECDSA" not in result["detected_algorithms"]


@pytest.mark.parametrize("name, body, line", [
    ("w.js", "import { ethers } from 'ethers'\nconst w = ethers.Wallet.createRandom()\n", 2),
    ("v.js", "const { ethers } = require('ethers')\nconst a = ethers.utils.verifyMessage(m, sig)\n", 2),
    ("s.ts", "import { ethers } from 'ethers'\nconst p = new ethers.BrowserProvider(window.ethereum)\n"
             "const signer = await p.getSigner()\nconst sig = await signer.signMessage('hi')\n", 4),
    ("a.js", "const { Web3 } = require('web3')\nconst web3 = new Web3()\nconst a = web3.eth.accounts.create()\n", 3),
    ("t.py", "from web3 import Web3\nw3 = Web3()\nsigned = w3.eth.account.sign_transaction(tx, key)\n", 3),
], ids=["ethers-wallet", "ethers-verify", "ethers-signer", "web3js-create", "web3py-sign"])
def test_an_import_and_a_signing_or_key_call_is_ecdsa(tmp_path, name, body, line):
    (tmp_path / name).write_text(body)
    rows = [r for r in scan_directory(tmp_path)["evidence"]["source_code"]
            if r["line"] == line and r["algorithm"] == "ECDSA"]
    assert rows and rows[0].get("curve") == "secp256k1", rows
