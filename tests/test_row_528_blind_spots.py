"""ZA-OPRAVYANE row 528: the defect batch of the blind-spot audit of 0.48.0
(qrp-kachestvo/slepi-petna-2026-11-17/IZVESHTAI.md, its probes in probes/). Each case is that
audit's probe line, reproduced on e897092 before the fix. The audit row number is in each name.

The owner's decisions (17.11): signing through a KMS, Vault or an agent, whose algorithm is chosen
outside the tree, is a place in `chosen_outside_files`; `.env` is the one new file type, for the
private key it can hold; a JOSE default beside an environment read is a place; the OpenSSL a base
image carries is a README limit, with no code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

ROOT = Path(__file__).resolve().parent.parent
CONTROL = "from cryptography.hazmat.primitives.asymmetric import rsa\n" \
          "ctl = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # control\n"


def _scan(tmp_path: Path, files: dict[str, str | bytes]) -> dict:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            p.write_bytes(body)
        else:
            p.write_text(body)
    return scan_directory(str(tmp_path))


def _rows(result, category="source_code"):
    return [r for r in result["evidence"][category] if isinstance(r, dict)]


def _at(result, path, line, category="source_code"):
    return [r for r in _rows(result, category) if (r["path"], r["line"]) == (path, line)]


def _places(result):
    return {(p["path"], p["line"]): p for p in result["chosen_outside_files"]["places"]}


# -- #18 gpg --detach-sign, -b, --clearsign ------------------------------------------------

SIGN_SH = """#!/bin/sh
openssl genrsa -out ctl.pem 2048 # control
gpg --batch --yes --detach-sign --armor dist/app.tar.gz
gpg -b dist/app.tar.gz
gpg --clearsign RELEASE
gpg -ab dist/app2.tar.gz
gpg --sign dist/app3.tar.gz
gpg --batch --verify dist/app.tar.gz.sig
gpg -c secret.txt
"""
GITLAB = """release:
  script:
    - gpg --batch --detach-sign dist/app.tar.gz
    - gpg --sign dist/app2.tar.gz
"""


def test_18_gpg_detach_and_clear_signing_are_signing_steps(tmp_path):
    result = _scan(tmp_path, {"sign.sh": SIGN_SH, ".gitlab-ci.yml": GITLAB})
    steps = {(s["path"], s["line"]) for s in _rows(result, "ci_pipeline")
             if s.get("command_type") == "gpg_sign"}
    assert {("sign.sh", n) for n in (3, 4, 5, 6, 7)} <= steps, steps
    assert {(".gitlab-ci.yml", 3), (".gitlab-ci.yml", 4)} <= steps
    # Not a signing step: a verify, and symmetric encryption with a passphrase.
    assert ("sign.sh", 8) not in steps and ("sign.sh", 9) not in steps


# -- #17 signing where the key and the algorithm are outside the tree ----------------------

REMOTE = CONTROL + """import os, boto3, requests, paramiko
from google.cloud import kms
sig = boto3.client('kms').sign(KeyId=os.environ['KEY_ARN'], Message=m, MessageType='DIGEST', SigningAlgorithm=ALG)
resp = kms.KeyManagementServiceClient().asymmetric_sign(request={'name': key_version_name, 'digest': {'sha256': d}})
r = requests.post(f'{VAULT}/v1/transit/sign/release-key', json={'input': b64})
agent = paramiko.Agent()
s = agent.get_keys()[0].sign_ssh_data(data)
fixed = boto3.client('kms').sign(KeyId=k, Message=m, SigningAlgorithm='ECDSA_SHA_256')
"""


def test_17_remote_signing_is_a_place(tmp_path):
    result = _scan(tmp_path, {"sign.py": REMOTE})
    places = _places(result)
    for line, where in ((5, "kms"), (6, "kms"), (7, "vault"), (9, "ssh_agent")):
        place = places.get(("sign.py", line))
        assert place, (line, places)
        assert place["key_location"] == where and place["kind"] == "remote_signing"
    # The algorithm is named on the line: a row, not a place.
    assert ("sign.py", 10) not in places
    assert any(r["algorithm"] == "ECDSA" for r in _at(result, "sign.py", 10))


def test_17_a_vault_path_in_prose_is_not_a_place(tmp_path):
    result = _scan(tmp_path, {"notes.py": "# see transit/sign/ in the docs\n"
                                          "PATH = 'transit/sign/'\n"})
    assert result["chosen_outside_files"]["count"] == 0


# -- #9 AWS KMS RSASSA_* signing names --------------------------------------------------------

K2 = """import boto3
kms = boto3.client("kms")
a = kms.sign(KeyId=k, Message=m, SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")
b = kms.sign(KeyId=k, Message=m, SigningAlgorithm="RSASSA_PSS_SHA_384")
c = kms.encrypt(KeyId=k, Plaintext=p, EncryptionAlgorithm="RSAES_OAEP_SHA_256")
"""


def test_9_aws_kms_rsassa_names_give_rsa(tmp_path):
    result = _scan(tmp_path, {"k2.py": K2})
    for line in (3, 4):
        rows = [r for r in _at(result, "k2.py", line) if r["algorithm"] == "RSA"]
        assert rows, line
        assert rows[0]["key_location"] == "kms" and rows[0]["evidence_kind"] != "identifier"
    assert [r for r in _at(result, "k2.py", 5) if r["algorithm"] == "RSA"]  # control


# -- #10 ECC_SECG_P256K1 is secp256k1, not P-256 ---------------------------------------------

def test_10_secg_p256k1_is_secp256k1(tmp_path):
    result = _scan(tmp_path, {"k.py": "import boto3\nkms = boto3.client('kms')\n"
                                      "d = kms.create_key(KeySpec='ECC_SECG_P256K1')\n"
                                      "e = kms.create_key(KeySpec='ECC_NIST_P256')\n"})
    secg = [r for r in _at(result, "k.py", 3) if r["algorithm"] in ("EC", "ECDSA")]
    nist = [r for r in _at(result, "k.py", 4) if r["algorithm"] in ("EC", "ECDSA")]
    assert secg and {r.get("curve") for r in secg} == {"secp256k1"}
    assert nist and {r.get("curve") for r in nist} == {"P-256"}  # control


# -- #11, #39 a real use read as "named but not used" ----------------------------------------

def test_11_gcp_kms_algorithm_enum_is_a_use(tmp_path):
    result = _scan(tmp_path, {"gkms.py": "from google.cloud import kms\n"
                                         "alg = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm"
                                         ".EC_SIGN_P256_SHA256\n"})
    rows = [r for r in _at(result, "gkms.py", 2) if r["algorithm"] in ("EC", "ECDSA")]
    assert rows and all(r["evidence_kind"] != "identifier" for r in rows), rows
    assert not [n for n in result["named_but_not_used_lines"] if n["path"] == "gkms.py"]


SWIFT = """import Security
let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 1024]
let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err)
let ctl = P256.Signing.PrivateKey() // control
"""


def test_39_swift_rsa_key_type_is_a_use_with_its_size(tmp_path):
    result = _scan(tmp_path, {"K.swift": SWIFT})
    rows = [r for r in _at(result, "K.swift", 2) if r["algorithm"] == "RSA"]
    assert rows and rows[0]["evidence_kind"] != "identifier"
    assert rows[0]["key_size"] == 1024
    assert not [n for n in result["named_but_not_used_lines"] if n["family"] == "RSA"]


# -- #38 RSA-1024 on one line reaches weak_count and algorithm_key_sizes ----------------------

@pytest.mark.parametrize("name, body, line", [
    ("rsa.c", "#include <openssl/rsa.h>\nRSA *k = RSA_generate_key(1024, 65537, NULL, NULL);\n", 2),
    ("paramiko_k.py", "import paramiko\nk = paramiko.RSAKey.generate(1024)\n", 2),
    ("ca-csr.json", '{"CN": "ca", "key": {"algo": "rsa", "size": 1024}}\n', 1),
])
def test_38_rsa_1024_on_one_line(tmp_path, name, body, line):
    result = _scan(tmp_path, {name: body})
    rows = [r for r in _at(result, name, line) if r["algorithm"] == "RSA"]
    assert rows and rows[0]["key_size"] == 1024
    assert result["summary"]["weak_count"] >= 1
    assert 1024 in result["algorithm_key_sizes_observed"].get("RSA", [])


def test_38_the_ex_form_keeps_its_size(tmp_path):
    result = _scan(tmp_path, {"g.c": "RSA_generate_key_ex(rsa, 3072, e, NULL);\n"})
    assert [r["key_size"] for r in _at(result, "g.c", 1) if r["algorithm"] == "RSA"] == [3072]


# -- #6 the environment variable's name decides too; Go os.Getenv ------------------------------

ENV_PY = CONTROL + """import os
JWT_ALG = os.getenv("JWT_ALG")
ALG2 = os.environ["JWT_ALG"]
SIGN_ALG = os.environ["SIGN_ALG"]
X = os.getenv('SIGNING_ALGORITHM')
DB = os.getenv("DATABASE_URL")
HOME = os.environ["HOME"]
if os.getenv("KEX_FUZZ_DEBUG"): pass
"""
ENV_GO = """package main
import ("os"; "crypto/rsa"; "crypto/rand")
func f() {
 k, _ := rsa.GenerateKey(rand.Reader, 2048); _ = k
 curve := os.Getenv("TLS_CURVES"); _ = curve
 sigAlg := os.Getenv("SIGNING_ALG"); _ = sigAlg
 port := os.Getenv("PORT"); _ = port
}
"""


def test_6_an_environment_read_is_a_place_by_the_variable_it_reads(tmp_path):
    places = _places(_scan(tmp_path, {"env.py": ENV_PY, "env.go": ENV_GO}))
    for line in (4, 5, 6, 7):
        assert ("env.py", line) in places, (line, places)
    assert ("env.go", 5) in places and ("env.go", 6) in places
    # Negative controls: a database URL, HOME, a port.
    # (env.py:10 is OpenSSH's fuzz-harness debug switch, caught on the positive control.)
    for key in (("env.py", 8), ("env.py", 9), ("env.py", 10), ("env.go", 7)):
        assert key not in places, key


# -- #7 a JOSE default beside an environment read ----------------------------------------------

def test_7_a_jose_default_is_a_place_with_its_default(tmp_path):
    result = _scan(tmp_path, {
        "app.py": "import os\nDEF = os.environ.get('JWT_ALG', 'ES256')\n"
                  "DEF2 = os.environ.get('SIG_ALG', 'RSA-PSS')\n",
        "app.js": "const alg = process.env.JWT_ALG || 'RS256';\n"})
    places = _places(result)
    for key, default, family in ((("app.py", 2), "ES256", "ECDSA"), (("app.js", 1), "RS256", "RSA"),
                                 (("app.py", 3), "RSA-PSS", "RSA")):
        assert key in places, (key, places)
        assert places[key]["default"] == default and places[key]["overridable"] is True
        assert places[key]["default_family"] == family


# -- #31 a private key as a C byte array -------------------------------------------------------

def _c_array_key() -> tuple[str, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    return ("static const unsigned char k[] = {"
            + ",".join(f"0x{b:02x}" for b in der) + "};\n"), der


def test_31_a_private_key_in_a_c_array_is_embedded_key_material(tmp_path):
    text, der = _c_array_key()
    result = _scan(tmp_path, {"key_arr.h": "/* device key */\n" + text})
    keys = [k for k in result["evidence"]["embedded_keys"] if k["path"] == "key_arr.h"]
    assert len(keys) == 1 and keys[0]["line"] == 2
    assert keys[0]["key_algorithm"] == "EC" and keys[0].get("curve") == "P-256"
    assert f"{der[10]:02x},0x{der[11]:02x}" not in str(keys)


def test_31_an_array_that_is_not_a_key_gives_nothing(tmp_path):
    body = "static const unsigned char t[] = {" + ",".join(["0x30"] + ["0x01"] * 60) + "};\n"
    result = _scan(tmp_path, {"table.h": body})
    assert result["evidence"]["embedded_keys"] == []


# -- the one new file type: .env, for the private key it can hold -------------------------------

ENV_PRODUCTION_KEY = None


def _escaped_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pem = ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return pem.strip().replace("\n", "\\n")


def test_env_files_are_read_for_a_private_key(tmp_path):
    result = _scan(tmp_path, {
        "app.py": CONTROL,
        ".env": "JWT_ALG=RS256\nTLS_CIPHERS=ECDHE-RSA-AES128-GCM-SHA256\n",
        ".env.production": f'JWT_PRIVATE_KEY="{_escaped_pem()}"\n'})
    assert {".env", ".env.production"} <= set(result["files_read"])
    not_examined = [p for b in result["coverage"]["not_examined"] for p in b.get("paths", [])]
    assert ".env" not in not_examined and ".env.production" not in not_examined
    keys = [k for k in result["evidence"]["embedded_keys"] if k["path"] == ".env.production"]
    assert len(keys) == 1


# -- the base image's OpenSSL: a README limit only ---------------------------------------------

def test_readme_says_the_base_image_openssl_is_not_read():
    readme = (ROOT / "README.md").read_text()
    section = readme.split("## What it is not", 1)[1].split("\n## ", 1)[0]
    assert "FROM" in section and "OpenSSL" in section
