"""Closure of an operation, not of a line (methodology of 18.11.2026,
qrp-kachestvo/obratna-proba/PLAN-operacii.md).

Each file in src/qrp_mcp/data/operations/ is the catalogue of one operation: for each ecosystem,
every documented spelling of that operation, with the page it is documented on and what it
means there. Every spelling with a source is written to a file of its own, scanned, and its
expected finding checked. A failing case here is a gap known before anyone comments on it.

Spellings marked `source = "none"` are listed in the catalogue and not tested: nobody has shown
where they are documented.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import operations
from qrp_mcp.scan import scan_directory

REQUIRED = ("id", "spelling", "source", "file", "expect")
VARIANT_KEYS = {"snippet", "file", "expect"}
EXPECT_KEYS = {"detected", "absent", "rows", "value"}


def _cases():
    for doc in operations.catalogue():
        for eco in doc["ecosystems"]:
            for s in eco["spellings"]:
                if s["source"] != "none":
                    yield pytest.param(doc["operation"], eco["ecosystem"], s,
                                       id=f"{doc['operation']}/{eco['ecosystem']}/{s['id']}")
                    # A variant is the same spelling with its free parts changed -- the variable,
                    # the setting's name, where a receiver comes from. A spelling closed with one
                    # name only was not closed: rows 540 and 546 (24.11.2026) were inside closed
                    # pairs, missed because the catalogue held the argument fixed.
                    for n, variant in enumerate(s.get("variants", []), 1):
                        yield pytest.param(doc["operation"], eco["ecosystem"],
                                           {**s, **variant, "variants": []},
                                           id=f"{doc['operation']}/{eco['ecosystem']}/{s['id']}~v{n}")


# Key material is made when the test runs, never committed: a key in the catalogue would be a
# key in the repository.
_MADE: dict[str, bytes] = {}


def _material(name: str) -> bytes:
    if name.startswith("fixture:"):
        return (Path(__file__).parent / "fixtures" / name.split(":", 1)[1]).read_bytes()
    if name not in _MADE:
        _MADE.update(_make_material())
    return _MADE[name]


def _make_material() -> dict[str, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
    from cryptography.x509.oid import NameOID

    E, P = serialization.Encoding, serialization.PrivateFormat
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    none = serialization.NoEncryption()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "closure.example")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(rsa_key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(rsa_key, hashes.SHA256()))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(name)
           .sign(ec_key, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name)
           .last_update(now).next_update(now + datetime.timedelta(days=30))
           .sign(rsa_key, hashes.SHA256()))
    pub = rsa_key.public_key()
    ssh_blob = ed_key.public_key().public_bytes(E.OpenSSH, serialization.PublicFormat.OpenSSH)
    import base64
    b64 = base64.b64encode(base64.b64decode(ssh_blob.split()[1])).decode()
    ssh2 = ("---- BEGIN SSH2 PUBLIC KEY ----\n"
            + "".join(b64[i:i + 70] + "\n" for i in range(0, len(b64), 70))
            + "---- END SSH2 PUBLIC KEY ----\n").encode()
    # keysize/PKI: the sizes the catalogue reads back (keysize.toml).
    from cryptography.hazmat.primitives.asymmetric import dsa
    rsa1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ec384 = ec.generate_private_key(ec.SECP384R1())
    ec521 = ec.generate_private_key(ec.SECP521R1())
    dsa1024 = dsa.generate_private_key(key_size=1024)
    cert1024 = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(rsa1024.public_key()).serial_number(2)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .sign(rsa1024, hashes.SHA256()))
    cert384 = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(ec384.public_key()).serial_number(3)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
               .sign(ec384, hashes.SHA384()))
    csr384 = x509.CertificateSigningRequestBuilder().subject_name(name).sign(ec384, hashes.SHA384())
    n1024 = rsa1024.public_key().public_numbers().n.to_bytes(128, "big")
    SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
    return {
        "RSA1024_PKCS8_PEM": rsa1024.private_bytes(E.PEM, P.PKCS8, none),
        "RSA1024_SPKI_PEM": rsa1024.public_key().public_bytes(E.PEM, SPKI),
        "RSA1024_OPENSSH_PUBLIC": rsa1024.public_key().public_bytes(
            E.OpenSSH, serialization.PublicFormat.OpenSSH) + b" closure@example\n",
        "RSA1024_JWK_N": base64.urlsafe_b64encode(n1024).rstrip(b"="),
        "EC384_PKCS8_PEM": ec384.private_bytes(E.PEM, P.PKCS8, none),
        "EC384_OPENSSH_PUBLIC": ec384.public_key().public_bytes(
            E.OpenSSH, serialization.PublicFormat.OpenSSH) + b" closure@example\n",
        "EC521_SPKI_PEM": ec521.public_key().public_bytes(E.PEM, SPKI),
        "DSA1024_PKCS8_PEM": dsa1024.private_bytes(E.PEM, P.PKCS8, none),
        "CERT_RSA1024_PEM": cert1024.public_bytes(E.PEM),
        "CERT_RSA1024_DER": cert1024.public_bytes(E.DER),
        "CERT_EC384_PEM": cert384.public_bytes(E.PEM),
        "CSR_EC384_PEM": csr384.public_bytes(E.PEM),
        "RSA2048_PKCS1_PEM": rsa_key.private_bytes(E.PEM, P.TraditionalOpenSSL, none),
        "RSA2048_PKCS8_PEM": rsa_key.private_bytes(E.PEM, P.PKCS8, none),
        "RSA2048_PKCS8_ENCRYPTED_PEM": rsa_key.private_bytes(
            E.PEM, P.PKCS8, serialization.BestAvailableEncryption(b"closure")),
        "RSA2048_PKCS8_DER": rsa_key.private_bytes(E.DER, P.PKCS8, none),
        "RSA2048_SPKI_PEM": pub.public_bytes(E.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        "RSA2048_PKCS1_PUBLIC_PEM": pub.public_bytes(E.PEM, serialization.PublicFormat.PKCS1),
        "EC256_SEC1_PEM": ec_key.private_bytes(E.PEM, P.TraditionalOpenSSL, none),
        "ED25519_OPENSSH_PRIVATE": ed_key.private_bytes(E.PEM, P.OpenSSH, none),
        "ED25519_SSH2_PUBLIC": ssh2,
        "CERT_RSA2048_PEM": cert.public_bytes(E.PEM),
        "CERT_RSA2048_DER": cert.public_bytes(E.DER),
        "CSR_EC256_PEM": csr.public_bytes(E.PEM),
        "CSR_EC256_NEW_PEM": csr.public_bytes(E.PEM).replace(b"CERTIFICATE REQUEST",
                                                              b"NEW CERTIFICATE REQUEST"),
        "CRL_RSA_PEM": crl.public_bytes(E.PEM),
        "CERT_RSA2048_CMS_PEM": pkcs7.serialize_certificates([cert], E.PEM).replace(b"PKCS7",
                                                                                  b"CMS"),
        "CERT_RSA2048_PKCS7_PEM": pkcs7.serialize_certificates([cert], E.PEM),
        "CERT_RSA2048_PKCS7_DER": pkcs7.serialize_certificates([cert], E.DER),
        "RSA2048_PKCS12": pkcs12.serialize_key_and_certificates(
            b"closure", rsa_key, cert, None, serialization.BestAvailableEncryption(b"closure")),
    }


def _write(directory: Path, spelling: dict) -> None:
    path = directory / spelling["file"]
    path.parent.mkdir(parents=True, exist_ok=True)
    if "material" in spelling:
        data = _material(spelling["material"])
        if "relabel" in spelling:
            # A refresh candidate (tools/catalogue_refresh.py): real material under the PEM
            # label the page names, so that what is tried is a file the scanner would meet.
            import re
            data = re.sub(rb"(-----(?:BEGIN|END) )[A-Z0-9 ]+(-----)",
                          lambda m: m.group(1) + spelling["relabel"].encode() + m.group(2), data)
        path.write_bytes(data)
        return
    text = spelling["snippet"]
    while "{{" in text:
        start = text.index("{{")
        end = text.index("}}", start)
        key = text[start + 2:end]
        filler, _, indent = key.partition("|")
        block = _material(filler).decode()
        if indent:
            # YAML block scalar: each line of the material indented; JSON: one escaped string.
            block = (json.dumps(block)[1:-1] if indent == "json"
                     else "".join(" " * int(indent) + line + "\n"
                                  for line in block.strip().splitlines()))
        text = text[:start] + block + text[end + 2:]
    path.write_text(text, encoding="utf-8")


def _at(result: dict, dotted: str):
    value = result
    for part in dotted.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def _check(result: dict, expect: dict) -> list[str]:
    if "any" in expect:
        # A refresh entry that tries one name in several real forms (a switch and a path):
        # read if any form is.
        tried = [_check(result, e) for e in expect["any"]]
        return [] if not all(tried) else ["none of: " + " | ".join("; ".join(m) for m in tried)]
    missing = []
    detected = set(result["detected_algorithms"])
    for family in expect.get("detected", []):
        if family not in detected:
            missing.append(f"{family} not in detected_algorithms {sorted(detected)}")
    for family in expect.get("absent", []):
        if family in detected:
            missing.append(f"{family} detected, should not be")
    for row in expect.get("rows", []):
        items = _at(result, row["at"]) or []
        found = any(all(item.get(k) == v for k, v in row["match"].items()) for item in items)
        if row.get("absent"):
            # A spelling that must not be read as a use: a removal, a revoked key, a hybrid's half.
            if found:
                missing.append(f"a row in {row['at']} with {row['match']}, should be none")
        elif not found:
            missing.append(f"no row in {row['at']} with {row['match']}")
    for check in expect.get("value", []):
        got = _at(result, check["at"])
        if "is" in check and got != check["is"]:
            missing.append(f"{check['at']} is {got!r}, expected {check['is']!r}")
        if "is_not" in check and got == check["is_not"]:
            missing.append(f"{check['at']} is {got!r}, must not be")
    return missing


@pytest.mark.parametrize("operation, ecosystem, spelling", list(_cases()))
def test_the_spelling_is_closed(tmp_path, operation, ecosystem, spelling):
    _write(tmp_path, spelling)
    missing = _check(scan_directory(tmp_path), spelling["expect"])
    assert not missing, f"{spelling['spelling']!r}: " + "; ".join(missing)


def test_every_catalogue_entry_is_complete():
    seen = set()
    docs = operations.catalogue()
    assert docs, "no catalogue files found"
    for doc in docs:
        assert doc["operation"] and doc["catalogue_version"]
        for eco in doc["ecosystems"]:
            assert eco["ecosystem"] not in ("multi", "none", "other"), "a residual cell is no family"
            for s in eco["spellings"]:
                assert all(k in s for k in REQUIRED), s
                assert ("snippet" in s) != ("material" in s), s["id"]
                assert set(s["expect"]) <= EXPECT_KEYS and s["expect"], s["id"]
                for variant in s.get("variants", []):
                    assert "snippet" in variant and set(variant) <= VARIANT_KEYS, s["id"]
                    assert "snippet" in s, f"{s['id']}: variants change a snippet"
                if s["source"] != "none":
                    assert s["source"].startswith("https://") and s.get("quote"), s["id"]
                key = (doc["operation"], eco["ecosystem"], s["id"])
                assert key not in seen, key
                seen.add(key)


def test_one_spelling_per_family_through_the_command_line(tmp_path):
    """The way the harness runs it: `qrp-mcp scan` in a subprocess, read back as JSON."""
    first = {}
    for case in _cases():
        first.setdefault(case.values[:2], case.values[2])
    for n, ((operation, ecosystem), spelling) in enumerate(first.items()):
        tree = tmp_path / f"t{n}"
        tree.mkdir()
        _write(tree, spelling)
        out = tmp_path / f"t{n}.json"
        subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree), "--out",
                        str(out), "--no-config", "--level", "full"],
                       check=True, capture_output=True)
        result = json.loads(out.read_text())
        assert not _check(result, spelling["expect"]), (operation, ecosystem, spelling["id"])
