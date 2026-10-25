"""M4: the standard CBOM fields a scanner can fill from what it read (release A).

Measured 25.10.2026 (qrp-pokazateli 01-tablo M4): of the named CycloneDX 1.6 fields our
CBOM filled 2 (`parameterSetIdentifier`, `compositions`); `oid`,
`classicalSecurityLevel`, `nistQuantumSecurityLevel`, `cryptoFunctions` and `curve` were
on 0 components. Each is filled here only from a table with a source, and only where the
scan read what the table needs (a single key size, a single parameter set, a curve).
Anything else stays absent: an absent field is a gap a reader can see, a guessed one is
not.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, oids
from qrp_mcp.classifier import _OID_FAMILIES
from qrp_mcp.scan import scan_directory

jsonschema = pytest.importorskip("jsonschema")
SCHEMA_DIR = Path(__file__).parent / "schema"
DNSSEC = Path(__file__).parent / "fixtures" / "dnssec"


@pytest.fixture(scope="module")
def validator():
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    return jsonschema.Draft7Validator(schema, resolver=resolver)


def _cbom(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return cyclonedx.build(scan_directory(tmp_path))


def _crypto(doc: dict, name: str) -> dict:
    component = next(c for c in doc["components"] if c["name"] == name)
    return component["cryptoProperties"]


def _algo(doc: dict, name: str) -> dict:
    return _crypto(doc, name)["algorithmProperties"]


RSA_2048 = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


def test_rsa_2048_carries_oid_levels_and_functions(tmp_path, validator):
    # Release 3b (M4c): the size is its own component, RSA-2048; release 3d: with no sizeless
    # sighting left, no sizeless RSA component beside it.
    doc = _cbom(tmp_path, {"a.py": RSA_2048})
    assert not any(c["name"] == "RSA" for c in doc["components"])
    assert _crypto(doc, "RSA-2048")["oid"] == "1.2.840.113549.1.1.1"
    algo = _algo(doc, "RSA-2048")
    assert algo["parameterSetIdentifier"] == "2048"
    assert algo["classicalSecurityLevel"] == 112          # SP 800-57 Pt 1 r5, Table 2
    assert algo["nistQuantumSecurityLevel"] == 0          # Shor: no category is met
    assert set(algo["cryptoFunctions"]) >= {"keygen", "sign", "verify"}
    assert list(validator.iter_errors(doc)) == []


def test_a_size_outside_the_table_gives_no_classical_level(tmp_path):
    doc = _cbom(tmp_path, {"a.py": RSA_2048.replace("2048", "4096")})
    assert "classicalSecurityLevel" not in _algo(doc, "RSA-4096")


def test_two_sizes_give_no_classical_level(tmp_path):
    doc = _cbom(tmp_path, {"a.py": RSA_2048,
                           "b.py": RSA_2048.replace("2048", "3072")})
    assert not any(c["name"] == "RSA" for c in doc["components"])   # release 3d
    # Each size its own component, each with its own level (release 3b, M4c).
    assert _algo(doc, "RSA-2048")["classicalSecurityLevel"] == 112
    assert _algo(doc, "RSA-3072")["classicalSecurityLevel"] == 128


@pytest.mark.parametrize("line,family,pset,oid,level,functions", [
    ("kem = KeyEncapsulation('ML-KEM-768')", "ML-KEM", "768",
     "2.16.840.1.101.3.4.4.2", 3, {"keygen", "encapsulate", "decapsulate"}),
    ("from pqcrypto.kem import ml_kem_1024", "ML-KEM", "1024",
     "2.16.840.1.101.3.4.4.3", 5, {"encapsulate"}),
    ("sig = Signature('ML-DSA-44')", "ML-DSA", "44",
     "2.16.840.1.101.3.4.3.17", 2, {"sign", "verify"}),
    ("sig = Signature('ML-DSA-65')", "ML-DSA", "65",
     "2.16.840.1.101.3.4.3.18", 3, {"sign"}),
    ("sig = Signature('SLH-DSA-SHA2-128s')", "SLH-DSA", "SHA2-128s",
     "2.16.840.1.101.3.4.3.20", 1, {"sign"}),
    ("sig = Signature('SLH-DSA-SHAKE-256f')", "SLH-DSA", "SHAKE-256f",
     "2.16.840.1.101.3.4.3.31", 5, {"verify"}),
])
def test_a_pqc_parameter_set_read_on_the_line(tmp_path, validator, line, family, pset,
                                              oid, level, functions):
    doc = _cbom(tmp_path, {"a.py": line + "\n"})
    algo = _algo(doc, f"{family}-{pset}")
    assert algo["parameterSetIdentifier"] == pset
    assert algo["nistQuantumSecurityLevel"] == level      # FIPS 203 / 204 / 205
    assert _crypto(doc, f"{family}-{pset}")["oid"] == oid
    assert functions <= set(algo["cryptoFunctions"])
    assert list(validator.iter_errors(doc)) == []


def test_a_pqc_family_without_a_set_gets_no_level_and_no_oid(tmp_path):
    doc = _cbom(tmp_path, {"a.go": 'import "crypto/mlkem"\nvar dk, _ = mlkem.GenerateKey768()\n'})
    algo = _algo(doc, "ML-KEM")
    assert "nistQuantumSecurityLevel" not in algo
    assert "parameterSetIdentifier" not in algo
    assert "oid" not in _crypto(doc, "ML-KEM")


def test_a_set_named_only_in_a_comment_does_not_count(tmp_path):
    doc = _cbom(tmp_path, {"a.py": "# TODO move to ML-KEM-1024\n"
                                   "kem = KeyEncapsulation('ML-KEM-768')\n"})
    assert _algo(doc, "ML-KEM-768")["parameterSetIdentifier"] == "768"
    assert not any(c["name"] == "ML-KEM-1024" for c in doc["components"])


def test_two_sets_are_both_named_and_neither_chosen(tmp_path):
    doc = _cbom(tmp_path, {"a.py": "a = KeyEncapsulation('ML-KEM-768')\n"
                                   "b = KeyEncapsulation('ML-KEM-1024')\n"})
    # Release 3d: no sizeless ML-KEM component, so none to choose a set for.
    assert not any(c["name"] == "ML-KEM" for c in doc["components"])
    # Release 3b (M4c): each set its own component, with its own occurrence and level.
    assert _algo(doc, "ML-KEM-768")["nistQuantumSecurityLevel"] == 3
    assert _algo(doc, "ML-KEM-1024")["nistQuantumSecurityLevel"] == 5


def test_x25519_names_its_curve(tmp_path, validator):
    doc = _cbom(tmp_path, {"a.py": "from cryptography.hazmat.primitives.asymmetric "
                                   "import x25519\nk = x25519.X25519PrivateKey.generate()\n"})
    algo = _algo(doc, "X25519")
    assert algo["curve"] == "Curve25519"
    assert algo["classicalSecurityLevel"] == 128          # SP 800-186
    assert algo["primitive"] == "key-agree"
    assert _crypto(doc, "X25519")["oid"] == "1.3.101.110"
    assert list(validator.iter_errors(doc)) == []


def test_a_curve_read_from_the_file_becomes_the_field(tmp_path, validator):
    shutil.copytree(DNSSEC, tmp_path / "t")
    doc = cyclonedx.build(scan_directory(tmp_path / "t"))
    algo = _algo(doc, "ECDSA-P-256")
    assert algo["curve"] == "P-256"
    assert algo["parameterSetIdentifier"] == "256"
    assert algo["classicalSecurityLevel"] == 128          # SP 800-57 Table 2, f=256-383
    assert "oid" not in _crypto(doc, "ECDSA-P-256")       # ECDSA's OIDs name a hash too
    assert list(validator.iter_errors(doc)) == []


def test_md5_is_a_digest_with_no_invented_level(tmp_path):
    doc = _cbom(tmp_path, {"a.py": "import hashlib\nh = hashlib.md5(b'x')\n"})
    algo = _algo(doc, "MD5")
    assert algo["cryptoFunctions"] == ["digest"]
    assert "classicalSecurityLevel" not in algo and "nistQuantumSecurityLevel" not in algo
    assert _crypto(doc, "MD5")["oid"] == "1.2.840.113549.2.5"


def test_the_oid_tables_agree_with_the_ones_the_scanner_reads():
    for family, oid in cyclonedx._OID_BY_FAMILY.items():
        assert oids.OIDS[oid][0] == (family,), family
    pqc = {oid: family for oid, family, *_ in _OID_FAMILIES}
    for (family, _), oid in cyclonedx._PQC_OID.items():
        assert pqc[oid] == family, oid
