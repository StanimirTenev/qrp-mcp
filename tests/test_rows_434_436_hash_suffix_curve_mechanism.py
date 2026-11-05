"""Rows 434, 435, 436 (05.11.2026).

434 (Daniel Stokes, paramiko 0e9ccb9): the SHA-2 digest length carried in a signature's name was
read as an RSA key size. `self._sign_and_verify_rsa("rsa-sha2-512", SIGNED_RSA_512)` and
`SIGNED_RSA_512 = "87:46:..."` gave `key_size: 512`, so the scan reported RSA-512, weak, and the
CBOM carried `parameterSetIdentifier: "512"`. The culprit was the `RSA_<n>` name form: in an
identifier, a 512 (or 256, 384) after RSA is as likely the hash as the modulus. A size from the
key itself -- `bits=512`, `key_size=512`, `openssl ... rsa:512` -- still counts.

435 (IR 8547 probe): `ec.generate_private_key(ec.SECP256R1())` put `curve: P-256` on the row, and
the finding still said "key size not read", with no EC in `algorithm_key_sizes`. A named NIST
curve now gives its size to the row, the finding and the summary.

436 (supplier-renewals probe): `hsm.sign(batch, mechanism=os.environ["HSM_SIGN_MECH"])` gave no
row at all. A sign/encrypt/derive call whose mechanism or algorithm argument is read from the
environment is now a place in `chosen_outside_files`, and no family is claimed for it.
"""

import json

from qrp_mcp.cyclonedx import build
from qrp_mcp.detectors import key_size_on_line
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import main


# -- row 434 ------------------------------------------------------------------------------

def test_a_digest_length_in_a_signature_name_is_not_a_key_size():
    for line in (
        'self._sign_and_verify_rsa("rsa-sha2-512", SIGNED_RSA_512)',   # paramiko :202
        'SIGNED_RSA_512 = "87:46:8b:75:92:33:78:a0"',                     # paramiko :65
        'SIGNED_RSA_256 = "cc:6:60:e0"',
        '"rsa-sha2-512"', "RSA_SHA512", "sha512WithRSA", "ALG_RSA_512 = 7",
    ):
        assert key_size_on_line(line) is None, line


def test_a_size_from_the_key_itself_still_counts():
    assert key_size_on_line("key = RSAKey.generate(bits=512)") == 512
    assert key_size_on_line("rsa.generate_private_key(public_exponent=65537, key_size=512)") == 512
    assert key_size_on_line("openssl req -newkey rsa:512 -keyout k.pem") == 512
    assert key_size_on_line("openssl genrsa -out k.pem 512") == 512
    # Not a digest length: the name form keeps working for real modulus sizes.
    assert key_size_on_line("KEY_RSA_4096 = 1") == 4096
    assert key_size_on_line("CONFIG_RSA_LEN=2048") == 2048
    assert key_size_on_line('FIT_SIGN_ALG = "rsa2048"') == 2048


def test_paramiko_lines_give_no_rsa_512_on_any_exit(tmp_path):
    (tmp_path / "test_pkey.py").write_text(
        "from paramiko import RSAKey\n"
        'SIGNED_RSA_512 = "87:46:8b:75:92:33:78:a0:22:35:32:39:23:c6:ab:e1"  # noqa\n'
        "class T:\n"
        "    def test_sign_and_verify_rsa_sha2_512(self):\n"
        '        self._sign_and_verify_rsa("rsa-sha2-512", SIGNED_RSA_512)\n'
        "    def test_generate(self):\n"
        "        key = RSAKey.generate(bits=2048)\n")
    result = scan_directory(tmp_path)
    rows = [o for o in result["evidence"]["source_code"] if o["algorithm"] == "RSA"]
    assert rows and all(o.get("key_size") != 512 for o in rows)
    assert result["algorithm_key_sizes"].get("RSA") == 2048
    assert not any(f["raw_value"] == "RSA-512" for f in result["findings"])
    bom = json.dumps(build(result))
    assert '"parameterSetIdentifier": "512"' not in bom


def test_a_512_bit_key_generated_is_still_weak(tmp_path):
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=512)\n")
    result = scan_directory(tmp_path)
    assert result["algorithm_key_sizes"]["RSA"] == 512
    rsa_finding = next(f for f in result["findings"] if f["algorithm_family"] == "RSA")
    assert rsa_finding["weak_key"] is True


# -- row 435 ------------------------------------------------------------------------------

def test_a_curve_on_the_row_reaches_the_finding_and_the_summary(tmp_path):
    (tmp_path / "keys.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        "session_key = ec.generate_private_key(ec.SECP256R1())\n")
    result = scan_directory(tmp_path)
    row = next(o for o in result["evidence"]["source_code"] if o["algorithm"] == "EC")
    assert row["curve"] == "P-256" and row["key_size"] == 256
    assert result["algorithm_key_sizes"].get("EC") == 256
    ec_finding = next(f for f in result["findings"] if f["algorithm_family"] == "EC")
    assert ec_finding["raw_value"] == "EC-256"
    assert ec_finding["weak_key"] is False
    assert "key size not read" not in ec_finding["reason"]


# -- row 436 ------------------------------------------------------------------------------

def test_a_signing_mechanism_from_the_environment_is_a_place(tmp_path):
    (tmp_path / "pay.py").write_text(
        "import os\n"
        "from hsmvendor_client import Session\n"
        "hsm = Session(slot=1)\n"
        "def settle(batch):\n"
        '    sig = hsm.sign(batch, mechanism=os.environ["HSM_SIGN_MECH"])\n'
        "    return sig\n")
    result = scan_directory(tmp_path)
    block = result["chosen_outside_files"]
    assert block["count"] == 1
    place = block["places"][0]
    assert place["line"] == 5 and place["setting"] == "mechanism"
    assert place["read_from"].startswith("os.environ")
    assert "algorithm" not in place
    assert result["findings"] == []


def test_mechanism_outside_a_crypto_call_is_not_a_place(tmp_path):
    (tmp_path / "mail.py").write_text(
        "import os\n"
        'smtp.login(user, password, mechanism=os.environ["SASL_MECH"])\n'
        'auth = Auth(mechanism=os.getenv("AUTH_MECH"))\n')
    assert scan_directory(tmp_path)["chosen_outside_files"]["count"] == 0


def test_the_place_leaves_by_the_cli(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "p.py").write_text(
        "import os\nkey = kms.encrypt(blob, mechanism=os.getenv('KMS_MECH'))\n")
    out = tmp_path / "r.json"
    try:
        main(["scan", str(src), "--out", str(out)])
    except SystemExit:
        pass
    assert json.loads(out.read_text())["chosen_outside_files"]["count"] == 1
