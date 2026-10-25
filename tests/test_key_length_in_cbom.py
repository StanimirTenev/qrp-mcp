"""Release 3d: the key length of each algorithm asset in the CBOM (CISA M-23-02 item 4, M4c).

Measured 25.10.2026 on the eight CBOM targets of kragg-2 01-tablo-relALL: 66 of our 157
algorithm components carried a key length (0.42; cdxgen 0.56, hyperion 0.50). Three causes,
each fixed here without stating a number the files do not give:
- a family's own, sizeless component stayed even where every sighting named its size;
- families whose name fixes the number (MD5's digest, Ed25519's key) carried none;
- a TLS group or SSH key exchange offered alone carried no size, though its name gives one.
A number the name does not give stays absent: rsa-sha2-256 names a hash, not a modulus.
"""

from __future__ import annotations

from pathlib import Path

from qrp_mcp import cyclonedx, detectors
from qrp_mcp.scan import scan_directory


def _doc(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    return cyclonedx.build(scan_directory(tmp_path))


def _algos(doc: dict) -> dict[str, dict]:
    return {c["name"]: c for c in doc["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "algorithm"}


def _pset(component: dict) -> str | None:
    return component["cryptoProperties"]["algorithmProperties"].get("parameterSetIdentifier")


def _referenced(doc: dict) -> set[str]:
    refs: set[str] = set()
    for c in doc["components"]:
        cp = c.get("cryptoProperties", {})
        refs.add((cp.get("relatedCryptoMaterialProperties") or {}).get("algorithmRef"))
        cert = cp.get("certificateProperties") or {}
        refs.update({cert.get("signatureAlgorithmRef"), cert.get("subjectPublicKeyRef")})
    for d in doc.get("dependencies", []):
        refs.update(d.get("dependsOn", []))
    return refs


RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\n"


def test_no_sizeless_family_component_where_every_sighting_names_its_size(tmp_path):
    doc = _doc(tmp_path, {"a.py": RSA + "k = rsa.generate_private_key(65537, key_size=2048)\n"})
    algos = _algos(doc)
    assert "RSA" not in algos and _pset(algos["RSA-2048"]) == "2048"


def test_the_sizeless_family_component_stays_for_a_sizeless_sighting(tmp_path):
    doc = _doc(tmp_path, {"a.py": RSA + "k = rsa.generate_private_key(65537, key_size=2048)\n",
                          "b.py": RSA + "k = rsa.generate_private_key(65537, key_size=n)\n"})
    algos = _algos(doc)
    assert _pset(algos["RSA-2048"]) == "2048"
    assert _pset(algos["RSA"]) is None
    assert [o["location"] for o in algos["RSA"]["evidence"]["occurrences"]] == ["b.py"]


def test_nothing_is_orphaned(tmp_path):
    """Every top-level asset has an occurrence or is referenced by one that has."""
    doc = _doc(tmp_path, {"a.py": RSA + "k = rsa.generate_private_key(65537, key_size=4096)\n",
                          "sshd_config": "KexAlgorithms mlkem768x25519-sha256\n"})
    referenced = _referenced(doc)
    for c in doc["components"]:
        if c["type"] == "cryptographic-asset":
            assert c.get("evidence", {}).get("occurrences") or c["bom-ref"] in referenced, c


def test_fixed_sizes_come_from_the_name(tmp_path):
    doc = _doc(tmp_path, {"a.py": "import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'x')\n"
                          "from cryptography.hazmat.primitives.asymmetric import x25519, ed25519\n"
                          "a = x25519.X25519PrivateKey.generate()\n"
                          "b = ed25519.Ed25519PrivateKey.generate()\n"})
    algos = _algos(doc)
    assert {n: _pset(algos[n]) for n in ("MD5", "SHA1", "X25519", "Ed25519")} == {
        "MD5": "128", "SHA1": "160", "X25519": "256", "Ed25519": "256"}


def test_a_group_offered_alone_carries_its_size(tmp_path):
    doc = _doc(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519MLKEM768:prime256v1;\n",
                          "sshd_config": "KexAlgorithms mlkem768x25519-sha256,"
                                         "diffie-hellman-group14-sha256\n"})
    sized = {c["name"]: _pset(c) for c in _algos(doc).values() if "offered alone" in c["name"]}
    assert sized.get("prime256v1 (TLS group offered alone)") == "256"
    assert all(v is not None for v in sized.values()), sized


def test_group_names():
    assert [cyclonedx._group_size(n) for n in (
        "secp384r1", "P-521", "x25519", "X448", "ffdhe3072", "brainpoolP512r1",
        "curve25519-sha256@libssh.org", "ecdh-sha2-nistp384", "diffie-hellman-group1-sha1",
        "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256",
        "rsa-sha2-256")] == ["384", "521", "256", "448", "3072", "512", "256", "384", "1024",
                             "4096", None, None]


def test_key_sizes_named_on_the_line():
    assert detectors.key_size_on_line("rsa-key-size = 4096") == 4096
    assert detectors.key_size_on_line("context.certbot(['--rsa-key-size', '4096'])") == 4096
    assert detectors.key_size_on_line('self.values["rsa_key_size"] = 2048') == 2048
    assert detectors.key_size_on_line('KeyPairGenerator.getInstance("RSA").initialize(3072);') == 3072
    assert detectors.key_size_on_line("dsa.generate_private_key(key_size=2048)", "DSA") == 2048
    # rsa-specific forms are not read for DSA or DH
    assert detectors.key_size_on_line("genrsa 4096 # dh", "DH") is None
    # ISO/IEC 9796 is a padding scheme, not a 9796-bit modulus
    assert detectors.key_size_on_line("#define CKM_RSA_9796\t\t\t(2UL)") is None
    assert detectors.key_size_on_line("rsa_sign(bits=128)") is None


def test_sntrup761_is_a_parameter_set(tmp_path):
    doc = _doc(tmp_path, {"sshd_config": "KexAlgorithms sntrup761x25519-sha512\n"})
    assert _pset(_algos(doc)["NTRU-sntrup761"]) == "sntrup761"


def test_an_identifier_in_a_go_raw_string_is_text(tmp_path):
    """kragg-2 rel3b mini hold-out, the FALSE row: smallstep-cli's help text names
    `intermediate_rsa_ca.crt` inside a backtick string that opens lines earlier."""
    go = ('package main\n\nimport "crypto/rsa"\n\nvar _ = rsa.PublicKey{}\n\n'
          'var help = `\nUsage:\n'
          "  step certificate create 'My RSA Intermediate' intermediate_rsa_ca.crt\n"
          '`\n\nfunc f() { intermediate_rsa_ca := 1; _ = intermediate_rsa_ca }\n')
    (tmp_path / "create.go").write_text(go, encoding="utf-8")
    rows = [r for r in scan_directory(tmp_path)["evidence"]["source_code"]
            if r.get("evidence_kind") == "identifier"]
    assert [r["line"] for r in rows] == [12]


def test_go_raw_spans():
    spans, inside = detectors._go_raw_spans('x := "`" + `a', False, False)
    assert inside and spans == [(11, 13)]
    assert detectors._go_raw_spans("still inside ` y := 1", True, False) == ([(0, 14)], False)
    assert detectors._go_raw_spans("// a ` in a comment", False, False) == ([], False)


def _cert(public_key, signer):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(public_key).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30)).sign(signer, hashes.SHA256()))


def test_a_self_signature_has_the_subject_keys_size(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP384R1())
    (tmp_path / "ec.crt").write_bytes(
        _cert(key.public_key(), key).public_bytes(serialization.Encoding.PEM))
    doc = cyclonedx.build(scan_directory(tmp_path))
    algos = _algos(doc)
    assert {"EC-P-384", "ECDSA-P-384"} <= set(algos) and not {"EC", "ECDSA"} & set(algos)
    cert = next(c for c in doc["components"]
                if c["cryptoProperties"].get("assetType") == "certificate")
    assert cert["cryptoProperties"]["certificateProperties"][
        "signatureAlgorithmRef"] == "crypto:ecdsa-p-384"


def test_an_issuers_signature_keeps_the_sizeless_family(tmp_path):
    """The issuer's RSA key is not in the file: its size is unknown, so RSA stays sizeless."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "ec.crt").write_bytes(
        _cert(subject.public_key(), issuer).public_bytes(serialization.Encoding.PEM))
    doc = cyclonedx.build(scan_directory(tmp_path))
    algos = _algos(doc)
    assert _pset(algos["RSA"]) is None and "RSA-2048" not in algos
    cert = next(c for c in doc["components"]
                if c["cryptoProperties"].get("assetType") == "certificate")
    assert cert["cryptoProperties"]["certificateProperties"][
        "signatureAlgorithmRef"] == "crypto:rsa"
