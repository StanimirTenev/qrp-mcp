"""Identifier rows are the weakest evidence the scan keeps (release 3b/3e: a family read from a
component of a name, `generate_rsa_keys`, `RSAUtil`). On rel3e's mini hold-out 20 of the 30 rows
it added were such names -- enum tests, imports of a helper -- and none was wrong enough to drop,
none strong enough to decide anything (rel3-rules review, 26.10.2026).

So they stay visible -- in the evidence at confidence `low`, and their family stays a finding --
and they never move the headline: `pqc_readiness` and `by_role` read as they would without them.
"""

import json

import pytest

from qrp_mcp.scan import scan_directory

ML_KEM = "from pqcrypto.kem.ml_kem_768 import generate_keypair\npk, sk = generate_keypair()\n"
ECDSA_SIGN = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
              "sig = key.sign(data, ec.ECDSA(hashes.SHA256()))\n")
# Identifier-level evidence only: one name with a crypto import beside it, one that stands
# alone (a family beside an operation).
IDENTIFIERS = {"ids.py": "import hashlib\nrsa_key_path = load()\n",
               "gen.py": "def generate_rsa_keys():\n    pass\n",
               "enc.py": "def rsa_encrypt_session_key(k):\n    return k\n"}
NEUTRAL = {"ids.py": "import hashlib\nkey_path = load()\n",
           "gen.py": "def generate_keys():\n    pass\n",
           "enc.py": "def encrypt_session_key(k):\n    return k\n"}


def _scan(tmp_path, files):
    tmp_path.mkdir(exist_ok=True)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def _headline(result):
    summary = result["summary"]
    return summary["pqc_readiness"], json.dumps(summary["by_role"], sort_keys=True)


@pytest.mark.parametrize("real", [{}, {"kem.py": ML_KEM}, {"sig.py": ECDSA_SIGN},
                                  {"kem.py": ML_KEM, "sig.py": ECDSA_SIGN}])
def test_identifier_rows_do_not_move_the_headline(tmp_path, real):
    with_ids = _scan(tmp_path / "a", {**real, **IDENTIFIERS})
    without = _scan(tmp_path / "b", {**real, **NEUTRAL})
    rows = [e for e in with_ids["evidence"]["source_code"] if e["algorithm"] == "RSA"]
    assert rows and all(e["evidence_kind"] == "identifier" for e in rows)
    assert _headline(with_ids) == _headline(without)


def test_identifier_rows_stay_visible_at_low_confidence(tmp_path):
    result = _scan(tmp_path, {"kem.py": ML_KEM, **IDENTIFIERS})
    rows = [e for e in result["evidence"]["source_code"] if e["evidence_kind"] == "identifier"]
    assert {e["path"] for e in rows} == set(IDENTIFIERS)
    assert {e["confidence"] for e in rows} == {"low"}
    # The family is still a finding, and says why the summary does not count it.
    rsa = next(f for f in result["findings"] if f["algorithm_family"] == "RSA")
    assert rsa["identifier_only"] is True
    assert result["summary"]["pqc_readiness"] == "pqc_ready"


def test_a_family_with_a_real_use_is_counted_and_its_identifiers_set_no_role(tmp_path):
    # ECDSA signs; RSA is used for real once, and named by identifiers that read as key
    # establishment (rsa_encrypt_session_key). The identifiers neither add RSA to a role
    # nor take its finding out of the count.
    real = {"sig.py": ECDSA_SIGN,
            "r.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"}
    with_ids = _scan(tmp_path / "a", {**real, **IDENTIFIERS})
    without = _scan(tmp_path / "b", {**real, **NEUTRAL})
    assert _headline(with_ids) == _headline(without)
    rsa = next(f for f in with_ids["findings"] if f["algorithm_family"] == "RSA")
    assert "identifier_only" not in rsa
