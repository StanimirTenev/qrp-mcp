"""Row 519 (17.11.2026, Iakovos Ellinas; probe `linkedin-postove/2026-11-17/stai-qrp/proba-ellinas/`).

azure-keyvault-keys `client.sign(SignatureAlgorithm.rs256, digest)` gave no row: the JOSE rule
reads `RS256` upper-case, and the Python SDK's members are lower-case (`rs256`, `ps256`, `es256`,
`es256_k`). They are now read, by the enum's name (`SignatureAlgorithm.`), never as a bare word.
boto3 `kms.sign(..., SigningAlgorithm="ECDSA_SHA_256")` gave ECDSA and nothing said the key is in
a KMS. A row on a KMS SDK call -- boto3's KMS parameters (`SigningAlgorithm=`,
`EncryptionAlgorithm=`, `KeyAgreementAlgorithm=`, `KeySpec=`) in a file that makes a boto3 `kms`
client, or an Azure Key Vault algorithm enum in a file that imports the Key Vault cryptography
client -- now carries `key_location: "kms"`, as a signing step does (row 482); the CBOM says it
on the occurrence (`[key: kms]`).

Not claimed: which key, or that the key is not exportable; Google Cloud KMS and HashiCorp Vault
are not read for this.
"""

import json
import os
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

APP = '''import boto3
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

kms = boto3.client("kms")

def sign_with_kms(key_id, digest):
    return kms.sign(KeyId=key_id, Message=digest, MessageType="DIGEST",
                    SigningAlgorithm="ECDSA_SHA_256")

def sign_with_vault(client: CryptographyClient, digest):
    return client.sign(SignatureAlgorithm.rs256, digest)

def more(client, digest):
    client.sign(SignatureAlgorithm.ps384, digest)
    client.sign(SignatureAlgorithm.es256_k, digest)
'''

# jjwt's io.jsonwebtoken.SignatureAlgorithm signs locally: not a KMS.
LOCAL = '''import io.jsonwebtoken.SignatureAlgorithm;
class T { Object a = SignatureAlgorithm.RS256; }
'''

# A lower-case member without the enum is a word, not an algorithm.
WORDS = "rs256 = 1\nes256 = settings.es256\n"


def _rows(result, path):
    return {(r["line"], r["algorithm"]): r for r in result["evidence"]["source_code"]
            if r["path"] == path}


def test_azure_enum_members_are_read(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    rows = _rows(scan_directory(tmp_path), "app.py")
    assert {(11, "RSA"), (14, "RSA"), (15, "ECDSA")} <= set(rows)


def test_a_kms_sdk_call_says_where_the_key_lives(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "T.java").write_text(LOCAL)
    result = scan_directory(tmp_path)
    rows = _rows(result, "app.py")
    assert rows[(8, "ECDSA")]["key_location"] == "kms"
    assert rows[(11, "RSA")]["key_location"] == "kms"
    assert all("key_location" not in r for r in _rows(result, "T.java").values())
    cbom = build(result)
    contexts = [o["additionalContext"] for c in cbom["components"]
                for o in (c.get("evidence") or {}).get("occurrences", [])
                if o["location"] == "app.py" and o.get("line") == 8]
    assert contexts and all("[key: kms]" in c for c in contexts)


def test_words_are_not_algorithms(tmp_path):
    (tmp_path / "settings.py").write_text(WORDS)
    assert _rows(scan_directory(tmp_path), "settings.py") == {}


def test_the_command_line_carries_it(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "app.py").write_text(APP)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(tmp_path / "t"), "--out", str(out), "--level", "full"],
                   check=True, capture_output=True, env=dict(os.environ))
    rows = _rows(json.loads(out.read_text()), "app.py")
    assert rows[(11, "RSA")]["key_location"] == "kms"
