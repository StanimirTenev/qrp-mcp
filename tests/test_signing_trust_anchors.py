"""Signatures and trust anchors (ZA-OPRAVYANE row 34, Ken Camp, 22.10.2026).

The test tree of that day: a C secure-boot verifier calling OpenSSL's RSA_verify, a
release workflow and a shell script that sign with `openssl dgst -sign`, cosign and
sbsign, the RSA signing key in the tree, and an X25519 exchange. On 0.31.0 the verifier
gave nothing (RSA_sign/RSA_verify were not in the RSA rule), sbsign was not recognised,
the shell script was not read as signing, and the openssl step was not linked to the
key it names although the key had been found.

Command lines from the tools' own manuals: sbsign(1), pesign(1), kmodsign(1), evmctl(1)
(Ubuntu manpages, read 22.10.2026) and the kernel's Documentation/admin-guide/
module-signing.rst for scripts/sign-file.
"""

import shutil
from pathlib import Path

import pytest

from qrp_mcp.closure import _identity
from qrp_mcp.detectors import SIGNING_COMMAND_PATTERNS
from qrp_mcp.scan import scan_directory

FIXTURE = Path(__file__).parent / "fixtures" / "signing"


@pytest.fixture
def result(tmp_path):
    shutil.copytree(FIXTURE, tmp_path / "t")
    # The signing key is written at test time, not committed to a public repository.
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    from cryptography.hazmat.primitives import serialization as s
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "t" / "keys").mkdir(exist_ok=True)
    (tmp_path / "t" / "keys" / "fw_signing.pem").write_bytes(key.private_bytes(
        s.Encoding.PEM, s.PrivateFormat.TraditionalOpenSSL, s.NoEncryption()))
    return scan_directory(tmp_path / "t")


@pytest.mark.parametrize("call", [
    "RSA_verify(NID_sha256, img, n, sig, 384, rsa)", "RSA_sign(NID_sha256, m, n, s, &l, r)",
    "RSA_sign_ASN1_OCTET_STRING(0, m, n, s, &l, r)", "RSA_verify_PKCS1_PSS_mgf1(r, h, md, md, em, -2)",
    "RSA_padding_add_PKCS1_PSS(r, em, h, md, -1)", "pad = RSA_PKCS1_PSS_PADDING;",
])
def test_openssl_rsa_signing_calls(tmp_path, call):
    (tmp_path / "v.c").write_text(f"int f(void) {{ return {call}; }}\n", encoding="utf-8")
    found = scan_directory(tmp_path)["evidence"]["source_code"]
    assert [(f["algorithm"], f.get("role")) for f in found] == [("RSA", "signature")]


def test_the_verifier_is_found(result):
    assert ("boot/verify.c", "RSA") in {(f["path"], f["algorithm"])
                                        for f in result["evidence"]["source_code"]}


@pytest.mark.parametrize("line,kind", [
    ("sbsign --key db.key --cert db.crt --output a.efi.signed a.efi", "sbsign"),
    ("pesign -i grubx64.efi -o grubx64.efi.signed -c 'Signing Key' -s", "pesign"),
    ("pesign --in=a.efi --out=b.efi --certificate=k --sign", "pesign"),
    ("kmodsign sha512 signing.key signing.x509 module.ko", "kmodsign"),
    ("evmctl ima_sign --key /etc/keys/privkey_evm.pem /usr/bin/app", "evmctl_sign"),
    ("evmctl sign --imasig --key privkey.pem file", "evmctl_sign"),
    ("scripts/sign-file sha512 kernel-signkey.priv kernel-signkey.x509 module.ko", "kernel_sign_file"),
])
def test_signing_commands(line, kind):
    assert [k for k, p in SIGNING_COMMAND_PATTERNS if p.search(line)] == [kind]


@pytest.mark.parametrize("line", [
    "pesign -i a.efi -S", "evmctl verify file", "apt-get install sbsigntool pesign",
    "kmodsigning is off"])
def test_not_signing(line):
    assert [k for k, p in SIGNING_COMMAND_PATTERNS if p.search(line)] == []


def test_a_shell_script_is_read_as_signing(result):
    steps = {(c["path"], c["command_type"]) for c in result["evidence"]["ci_pipeline"]}
    assert {("ci/release.sh", "openssl_sign"), ("ci/release.sh", "cosign_sign"),
            ("ci/release.sh", "sbsign")} <= steps
    assert ("ci/release.sh", "sbsign") in steps


def test_the_step_is_linked_to_the_key_in_the_tree(result):
    by = {(c["path"], c["command_type"]): c for c in result["evidence"]["ci_pipeline"]}
    for path in (".github/workflows/release.yml", "ci/release.sh"):
        key = by[(path, "openssl_sign")]["signing_key"]
        assert key == {"path": "keys/fw_signing.pem", "in_tree": True, "algorithms": ["RSA"]}
        # A key the step names that is not in the tree is named as such, not guessed.
        assert by[(path, "sbsign")]["signing_key"] == {"path": "keys/db.key", "in_tree": False}
    # The link comes from another file, so it is not part of the step's identity.
    step = by[("ci/release.sh", "openssl_sign")]
    assert _identity("ci_pipeline", step) == _identity(
        "ci_pipeline", {k: v for k, v in step.items() if k != "signing_key"})


@pytest.mark.parametrize("line,key", [
    ("openssl cms -sign -in msg.txt -signer cert.pem -inkey key.pem -out m.p7s", "key.pem"),
    ("openssl smime -sign -in m -signer c.pem -inkey keys/k.pem", "keys/k.pem"),
    ("openssl dgst -sha256 -sign k.pem -out s.sig f.bin", "k.pem"),
])
def test_the_key_argument_not_the_next_flag(tmp_path, line, key):
    (tmp_path / "s.sh").write_text(line + "\n", encoding="utf-8")
    steps = scan_directory(tmp_path)["evidence"]["ci_pipeline"]
    assert [s["signing_key"]["path"] for s in steps] == [key]
