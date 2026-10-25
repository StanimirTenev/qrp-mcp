"""crypto-js as a declared dependency (ZA-OPRAVYANE row 149).

`"crypto-js": "^4.2.0"` in a package.json gave nothing, while node-forge and jsrsasign
beside it were reported. crypto-js implements no public-key algorithm; it does implement
MD5, SHA-1, DES, TripleDES and RC4 (its own module list: md5.js, sha1.js, tripledes.js,
rc4.js), which the inventory reports wherever they are called.
"""

from pathlib import Path

from qrp_mcp import assets


def test_crypto_js_is_a_dependency_row():
    lines = ['{', '  "name": "x",', '  "dependencies": {', '    "crypto-js": "^4.2.0"', '  }', '}']
    rows = assets.scan_manifest(Path("package.json"), "package.json", lines)
    assert [(r["line"], r["package"]) for r in rows] == [(4, "crypto-js")]
    assert set(rows[0]["families"]) == {"MD5", "SHA1", "DES", "3DES", "RC4"}
