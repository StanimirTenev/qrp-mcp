"""ZA-OPRAVYANE row 484: an Android Keystore key read with no curve, size or role.

Probe `linkedin-postove/2026-11-15/mobile-proba/r/android/DeviceBinding.kt` (0.46.0):
`KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")` initialised with
`KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)` read EC, `key_size: undetermined`,
`role: undetermined`.

An EC or RSA `getInstance(..., "AndroidKeyStore")` row in a file holding exactly one
`KeyGenParameterSpec.Builder(...)` now takes the purposes written in that builder as its use
(`key_use_in_block`, so `role`), and an EC row the curve from `ECGenParameterSpec("...")` or
`setKeySize(...)` in it; with neither, the Keystore's default EC size, 256 bits (P-256), with
`curve_basis` saying it is a default and where that is written (AOSP
AndroidKeyStoreKeyPairGeneratorSpi.java, `EC_DEFAULT_KEY_SIZE = 256`; the developer
documentation says only "an algorithm-specific default"). Not claimed: where the key lives
(StrongBox or TEE, row 482); a file with two builders is not paired.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/mobile-proba/r/android/DeviceBinding.kt"
BINDING = """import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator

fun bindDevice(alias: String) {
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    kpg.initialize(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)
            .build()
    )
    kpg.generateKeyPair()
}
"""


def _tree(tmp_path, text, name="DeviceBinding.kt"):
    t = tmp_path / "repo"
    t.mkdir(exist_ok=True)
    (t / name).write_text(text)
    return t


def _ec(evidence):
    return [e for e in evidence["source_code"] if e["algorithm"] == "EC" and e["line"] == 6]


def test_the_probe_reads_signature_and_the_default_curve(tmp_path):
    if PROBE.is_file():
        assert PROBE.read_text() == BINDING
    t = _tree(tmp_path, BINDING)
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(t), "--out", str(out)]) == 0
    rows = _ec(json.loads(out.read_text())["evidence"])
    assert len(rows) == 1
    row = rows[0]
    assert row["role"] == "signature"
    assert row["curve"] == "P-256" and row["key_size"] == 256
    assert "default" in row["curve_basis"] and "EC_DEFAULT_KEY_SIZE" in row["curve_basis"]


def test_it_reaches_the_mcp_tool_and_the_cbom(tmp_path):
    t = _tree(tmp_path, BINDING)
    row = _ec(server.scan_repo(str(t))["evidence"])[0]
    assert row["role"] == "signature" and row["curve"] == "P-256"
    for doc in (server.export_cbom(str(t)), cyclonedx.build(scan_directory(t))):
        comp = next(c for c in doc["components"]
                    for o in c.get("evidence", {}).get("occurrences") or []
                    if o["location"] == "DeviceBinding.kt" and o.get("line") == 6)
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert json.loads(props["qrp:role"]) == ["signature"]
        assert "EC_DEFAULT_KEY_SIZE" in json.loads(props["qrp:curve_basis"])[0]
        assert comp["cryptoProperties"]["algorithmProperties"].get("curve") in ("P-256", "secp256r1")


@pytest.mark.parametrize("builder, role, curve", [
    ('KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)\n'
     '            .setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1"))',
     "key_establishment", "P-384"),
    ("KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)"
     "\n            .setKeySize(521)", "signature", "P-521"),
    ("KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY)",
     "undetermined", "P-256"),
])
def test_purpose_and_curve_forms(tmp_path, builder, role, curve):
    text = BINDING.replace("KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)", builder)
    row = _ec(scan_directory(_tree(tmp_path, text))["evidence"])[0]
    assert row["role"] == role
    assert row["curve"] == curve
    assert ("curve_basis" in row) == (curve == "P-256")


def test_two_builders_are_not_paired(tmp_path):
    text = BINDING + ("val other = KeyGenParameterSpec.Builder(\"b\", KeyProperties.PURPOSE_ENCRYPT)"
                      ".build()\n")
    row = _ec(scan_directory(_tree(tmp_path, text))["evidence"])[0]
    assert row["role"] == "undetermined"
    assert "curve" not in row and row["key_size"] == "undetermined"
