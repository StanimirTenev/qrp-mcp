"""ZA-OPRAVYANE row 501 (D5 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8,
MCUboot f30be48, 0.46.0).

MCUboot names its ECDSA P-256 signature `EC256` (`MCUBOOT_SIGN_EC256`, `BOOTUTIL_SIGN_EC256`,
`CONFIG_ESP_SIGN_EC256`; boot/bootutil/src/image_validate.c expects IMAGE_TLV_ECDSA_SIG for it)
and its ECIES-P256 key encryption `ENC_EC256` (docs/encrypted_images.md: "The implemenation of
ECIES-P256 is named ENC_EC256 in the source code"); its signing key is `root-ec-p256.pem`. None of
it was a row, while the RSA and Ed25519 lines beside it were (`CONFIG_ESP_SIGN_RSA=1`,
`CONFIG_ESP_SIGN_KEY_FILE=root-rsa-2048.pem`).

Not claimed: `ec-p256` is read only as the value of a signing-key file setting, not as any
file name; `EC256` alone, without SIGN or ENC before it, stays unread.
"""

import json

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

# boot/espressif/ci_configs/secureboot-sign-ec256.conf:17-19 (the probe's repro ec256.conf).
ESP_CONF = ("CONFIG_ESP_SIGN_KEY_FILE=root-ec-p256.pem\n"
            "CONFIG_ESP_USE_TINYCRYPT=1\n"
            "CONFIG_ESP_SIGN_EC256=1\n")


@pytest.mark.parametrize("name, text, line, family", [
    ("secureboot-sign-ec256.conf", ESP_CONF, 1, "ECDSA"),
    ("secureboot-sign-ec256.conf", ESP_CONF, 3, "ECDSA"),
    # ci/mynewt_targets/ecdsa/syscfg.yml:24
    ("syscfg.yml", "syscfg.vals:\n    BOOTUTIL_SIGN_EC256: 1\n", 2, "ECDSA"),
    # sim/mcuboot-sys/build.rs:243
    ("build.rs", '    } else if sig_ecdsa {\n        conf.conf.define("MCUBOOT_SIGN_EC256", None);\n',
     2, "ECDSA"),
    # samples/zephyr/overlay-ecdsa-p256.conf:3
    ("overlay-ecdsa-p256.conf", 'CONFIG_BOOT_SIGNATURE_KEY_FILE="root-ec-p256.pem"\n', 1, "ECDSA"),
    # boot/mbed/include/mcuboot_config/mcuboot_config.h:34
    ("mcuboot_config.h", "#elif (MCUBOOT_SIGNATURE_ALGORITHM == SIGNATURE_TYPE_EC256)\n", 1, "ECDSA"),
    # boot/zephyr/Kconfig-style encryption switch
    ("prj.conf", "CONFIG_BOOT_ENCRYPT_EC256=y\n", 1, "ECDH"),
    # sim/src/tlv.rs:61, the ECIES-P256 TLV (docs/design.md: IMAGE_TLV_ENC_EC256 0x32)
    ("tlv.rs", "    ENCEC256 = 0x32,\n", 1, "ECDH"),
])
def test_ec256_is_p256(tmp_path, name, text, line, family):
    _check(tmp_path, name, text, line, family, 256, "P-256")


def test_sign_ec384_is_p384(tmp_path):
    # boot/bootutil/src/image_validate.c:66
    _check(tmp_path, "image_validate.c", "     defined(MCUBOOT_SIGN_EC384)    + \\\n", 1, "ECDSA",
           384, "P-384")


def _check(tmp_path, name, text, line, family, size, curve):
    (tmp_path / name).write_text(text)
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["line"] == line and e["algorithm"] == family]
    assert len(rows) == 1, rows
    assert rows[0]["key_size"] == size and rows[0]["curve"] == curve, rows[0]
    assert rows[0]["evidence_kind"] not in ("comment", "ban", "identifier"), rows[0]


@pytest.mark.parametrize("text", [
    "x = EC256\n",                                   # no SIGN or ENC before it
    "CONFIG_DATA_FILE=spec-p256.txt\n",              # not a key-file setting
    "#define EC256_PUBK_LEN 91\n",
])
def test_not_ec256(tmp_path, text):
    (tmp_path / "a.conf").write_text(text)
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] in ("ECDSA", "ECDH", "EC")]
    assert not rows, rows


def test_ec256_reaches_the_three_paths(tmp_path):
    (tmp_path / "secureboot-sign-ec256.conf").write_text(ESP_CONF)
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tmp_path), "--out", str(out)]) == 0
    for evidence in (json.loads(out.read_text())["evidence"],
                     server.scan_repo(str(tmp_path))["evidence"]):
        assert {e["line"] for e in evidence["source_code"] if e["algorithm"] == "ECDSA"} == {1, 3}
    for doc in (server.export_cbom(str(tmp_path)), cyclonedx.build(scan_directory(tmp_path))):
        assert "ECDSA-P-256" in {c["name"] for c in doc["components"]}
