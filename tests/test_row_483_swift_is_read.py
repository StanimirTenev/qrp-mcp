"""ZA-OPRAVYANE row 483: Swift was not read.

Probe `linkedin-postove/2026-11-15/mobile-proba/r/ios/DeviceBinding.swift` (0.45.0):
`kSecAttrKeyTypeECSECPrimeRandom`, 256 bits, `kSecAttrTokenIDSecureEnclave` -> the file was
`type_not_claimed` (`files_skipped_by_type: {".swift": 1}`), 1 of 2 files read.

`.swift` is now a source extension, and Apple's names are rules: the Security framework's EC key
type (`kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeyTypeEC`) and CryptoKit's `P256/P384/P521
.Signing` (ECDSA, the curve from the name), `.KeyAgreement` (ECDH) and `Curve25519.Signing`
(Ed25519, no longer X25519). Not read: the size a Security-framework key gets from
kSecAttrKeySizeInBits on another line; where the key lives (Secure Enclave, row 482);
Objective-C (`.m`) is still not a source type.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, detectors, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/mobile-proba/r/ios/DeviceBinding.swift"
BINDING = """import Security
func bindDevice() -> SecKey? {
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]
    return SecKeyCreateRandomKey(attrs as CFDictionary, nil)
}
"""
KIT = """import CryptoKit
let s = try SecureEnclave.P256.Signing.PrivateKey()
let a = P384.KeyAgreement.PrivateKey()
let e = Curve25519.Signing.PrivateKey()
let x = Curve25519.KeyAgreement.PrivateKey()
"""


@pytest.fixture
def tree(tmp_path):
    if PROBE.is_file():
        assert PROBE.read_text() == BINDING
    t = tmp_path / "repo"
    (t / "ios").mkdir(parents=True)
    (t / "ios/DeviceBinding.swift").write_text(BINDING)
    (t / "ios/Kit.swift").write_text(KIT)
    return t


def _rows(evidence):
    return {(e["path"], e["line"], e["algorithm"]): e for e in evidence["source_code"]}


def _check(result):
    assert result["files_skipped_by_type"] == {}
    assert result["files_scanned"]["source"] == 2
    rows = _rows(result["evidence"])
    assert ("ios/DeviceBinding.swift", 4, "EC") in rows
    assert rows[("ios/Kit.swift", 2, "ECDSA")]["curve"] == "P-256"
    assert rows[("ios/Kit.swift", 3, "ECDH")]["curve"] == "P-384"
    assert ("ios/Kit.swift", 4, "Ed25519") in rows
    assert ("ios/Kit.swift", 4, "X25519") not in rows
    assert ("ios/Kit.swift", 5, "X25519") in rows


def test_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_mcp_tool(tree):
    _check(server.scan_repo(str(tree)))


def test_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        at = {(o["location"], o.get("line")) for c in doc["components"]
              for o in c.get("evidence", {}).get("occurrences") or []}
        assert ("ios/DeviceBinding.swift", 4) in at
        assert ("ios/Kit.swift", 2) in at


@pytest.mark.parametrize("line, said", [
    ("let k = P521.Signing.PrivateKey()", ["ECDSA"]),
    ("let k = P256.KeyAgreement.PrivateKey()", ["ECDH"]),
    ("let k = Curve25519.Signing.PrivateKey()", ["Ed25519"]),
    ("kSecAttrKeyType as String: kSecAttrKeyTypeEC,", ["EC"]),
    # Not a CryptoKit type.
    ("let p256Signing = true", []),
])
def test_apple_rules(line, said):
    names = {d for _, d, _ in detectors.ALGORITHM_PATTERNS}
    assert {"ECDSA named by Apple CryptoKit", "EC named by the Apple Security framework"} <= names
    assert [a for a, d, p in detectors.ALGORITHM_PATTERNS
            if "Apple" in d and p.search(line)] == said
