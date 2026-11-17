"""Row 518 (17.11.2026; a probe of a LinkedIn room on HSM signing, `linkedin-postove/2026-11-17/`).

`Signature.getInstance(System.getenv("SIG_ALG"))` beside a PKCS#11 KeyStore gave nothing at all:
no row, and `chosen_outside_files` 0, so the file read as if it had no cryptography. The
runtime-choice rule wanted a setting's name before the reference, and `getInstance(` is not
one. A JCA `getInstance` of Signature, Cipher, KeyPairGenerator, KeyAgreement or KeyGenerator
whose algorithm is read from the environment is now a place in `chosen_outside_files`, with no
family claimed. (`Cipher.getInstance(System.getenv(...))` was already one, by the word
`cipher`.)

Beside it, python-pkcs11's documented `session.generate_keypair(KeyType.RSA, 3072)` gave RSA
with `key_size: undetermined`, the 3072 on the line. The size is now read.

Not claimed: the function names `new_rsa_key` / `new_ec_key` still give identifier rows; those
are notes by design (low confidence, not a use, no mandate clause), not findings.
"""

import json
import os
import subprocess
import sys

from qrp_mcp.scan import scan_directory

JAVA = """import java.security.KeyStore;
import java.security.Signature;

public class HsmSigner {
    public byte[] sign(byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS11");
        Signature s = Signature.getInstance(System.getenv("SIG_ALG"));
        Cipher c = Cipher.getInstance(System.getenv("CIPHER"));
        KeyStore other = KeyStore.getInstance(System.getenv("STORE_TYPE"));
        return s.sign();
    }
}
"""

PKCS11 = """import pkcs11
from pkcs11 import KeyType


def new_rsa_key(session):
    return session.generate_keypair(KeyType.RSA, 3072, label="rsa-signing")
"""


def _places(result):
    return [(p["path"], p["line"], p["setting"], p["read_from"])
            for p in result["chosen_outside_files"]["places"]]


def test_getinstance_of_the_environment_is_chosen_outside_the_files(tmp_path):
    (tmp_path / "HsmSigner.java").write_text(JAVA)
    result = scan_directory(tmp_path)
    assert _places(result) == [
        ("HsmSigner.java", 7, "Signature.getInstance", 'System.getenv'),
        ("HsmSigner.java", 8, "Cipher", "System.getenv"),  # caught before 0.49.0
    ]
    # No family claimed for the line.
    assert not [r for r in result["evidence"]["source_code"] if r["line"] in (7, 8)]


def test_the_command_line_carries_it(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "HsmSigner.java").write_text(JAVA)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(tmp_path / "t"), "--out", str(out), "--level", "full"],
                   check=True, capture_output=True, env=dict(os.environ))
    assert json.loads(out.read_text())["chosen_outside_files"]["count"] == 2


def test_python_pkcs11_generate_keypair_size_is_read(tmp_path):
    (tmp_path / "hsm_keys.py").write_text(PKCS11)
    result = scan_directory(tmp_path)
    [row] = [r for r in result["evidence"]["source_code"] if r["line"] == 6]
    assert (row["algorithm"], row["key_size"]) == ("RSA", 3072)
