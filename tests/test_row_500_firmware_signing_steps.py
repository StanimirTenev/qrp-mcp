"""ZA-OPRAVYANE row 500 (D4 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8,
U-Boot 6487c50 and MCUboot f30be48, 0.46.0).

The firmware signers had no signing-step pattern: `binman sign -k $1 -a sha256,rsa4096`
(U-Boot tools/iot2050-sign-fw.sh:49), `mkimage -F -k keys -K u-boot.dtb -r image.fit`
(mkimage(1)), `imgtool sign --key root-ec-p256.pem` (MCUboot docs/imgtool.md). Both scans had
`qrp:evidence:ci_signing_commands: 0`. Now each is a signing step, with the key it names, and a
step whose key is not a file the scan read says `key_algorithm: "not determined: key not in the
files read"` -- unless the line itself names the algorithm (`-a sha256,rsa4096`).

Not claimed: a step written as a Python argument list (`[mkimage, '-F', '-k', tmpdir, ...]`,
test/py/tests/test_vboot.py:256) is not read -- signing steps are read in scripts and pipelines
only; `imgtool getpub` is not a signing step.
"""

import json

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.detectors import SIGNING_COMMAND_PATTERNS
from qrp_mcp.scan import scan_directory

SIGN_SH = (
    "#!/bin/sh\n"
    "$TOOLS_DIR/binman/binman sign -i flash-pg1.bin -k $1 -a sha256,rsa4096 fit@380000\n"
    "tools/mkimage -F -k keys -K u-boot.dtb -r image.fit\n"
    "imgtool sign --key root-ec-p256.pem --version 1.0 zephyr.bin signed.bin\n"
    "./scripts/imgtool.py sign -k keys/root-rsa-2048.pem in.bin out.bin\n")


@pytest.mark.parametrize("line, kind", [
    ("binman sign -i flash.bin -k $1 -a sha256,rsa4096 fit@380000", "binman_sign"),
    ("tools/mkimage -F -k keys -K u-boot.dtb -r image.fit", "mkimage_sign"),
    ("mkimage -f fit.its -G key.pem -r image.fit", "mkimage_sign"),
    ("imgtool sign --key root-ec-p256.pem in.bin out.bin", "imgtool_sign"),
    ("python3 scripts/imgtool.py sign -k k.pem in.bin out.bin", "imgtool_sign"),
])
def test_firmware_signing_commands(line, kind):
    assert [k for k, p in SIGNING_COMMAND_PATTERNS if p.search(line)] == [kind]


@pytest.mark.parametrize("line", [
    "imgtool getpub -k root-ec-p256.pem", "imgtool keygen -k k.pem -t ecdsa-p256",
    "mkimage -f fit.its image.fit", "binman build -b sandbox", "imgtool verify -k k.pem s.bin"])
def test_not_firmware_signing(line):
    assert [k for k, p in SIGNING_COMMAND_PATTERNS if p.search(line)] == []


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    (t / "keys").mkdir(parents=True)
    (t / "sign.sh").write_text(SIGN_SH)
    return t


def _check(evidence, with_tree_key=False):
    steps = {s["line"]: s for s in evidence["ci_pipeline"] if s["path"] == "sign.sh"}
    assert {n: s["command_type"] for n, s in steps.items()} == {
        2: "binman_sign", 3: "mkimage_sign", 4: "imgtool_sign", 5: "imgtool_sign"}, steps
    # The key is an argument the script was given; the line names the algorithm.
    assert steps[2]["signing_key"] == {"path": "$1", "in_tree": False}, steps[2]
    assert steps[2]["key_algorithm"] == "RSA-4096, named on the line (sha256,rsa4096)", steps[2]
    for n in (3, 4):
        assert steps[n]["key_algorithm"] == "not determined: key not in the files read", steps[n]
    assert steps[3]["signing_key"] == {"path": "keys", "in_tree": False}
    assert steps[4]["signing_key"] == {"path": "root-ec-p256.pem", "in_tree": False}
    if with_tree_key:
        assert steps[5]["signing_key"]["in_tree"] is True
        assert "key_algorithm" not in steps[5], steps[5]


def test_steps_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text())["evidence"])


def test_steps_in_the_mcp_tool(tree):
    result = server.scan_repo(str(tree))
    _check(result["evidence"])
    reasons = {f["location"]: f["reason"] for f in result["findings"]
               if f["algorithm_family"] == "signing_command"}
    assert reasons["sign.sh:2"] == ("CI/CD signing command detected; key RSA-4096, named on the "
                                    "line (sha256,rsa4096).")
    assert "not visible" in reasons["sign.sh:3"]


def test_steps_reach_the_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        props = {p["name"]: p["value"] for p in doc["properties"]}
        assert props["qrp:evidence:ci_signing_commands"] == "4"
        listed = {s["line"]: s for s in json.loads(props["qrp:evidence:signing_commands"])}
        assert listed[2]["key_algorithm"] == "RSA-4096, named on the line (sha256,rsa4096)"
        assert listed[3]["key_algorithm"] == "not determined: key not in the files read"
        assert listed[4]["signing_key"] == {"path": "root-ec-p256.pem", "in_tree": False}


def test_a_key_in_the_tree_is_not_undetermined(tree):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tree / "keys" / "root-rsa-2048.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    _check(scan_directory(tree)["evidence"], with_tree_key=True)


@pytest.mark.parametrize("line, key", [
    ("cosign sign --key ${{ secrets.COSIGN_KEY }} $IMG", None),
    ('openssl dgst -sign "$(dirname "$0")/k.pem" f', None),
    ("openssl dgst -sign $(KEY) f", None),
    ("openssl dgst -sign ${KEY} f", "${KEY}"),
    ("openssl dgst -sign %KEY% f", "%KEY%"),
    ("binman sign -i f.bin -k $SIGN_KEY -a sha256,rsa2048 fit", "$SIGN_KEY"),
])
def test_a_variable_key_is_named_only_whole(tmp_path, line, key):
    # A fragment of an expression (`${{`, `$(dirname`) is not a key's name.
    (tmp_path / "s.sh").write_text(line + "\n")
    steps = scan_directory(tmp_path)["evidence"]["ci_pipeline"]
    assert len(steps) == 1, steps
    assert steps[0].get("signing_key", {}).get("path") == key, steps[0]
    assert steps[0]["key_algorithm"], steps[0]
