"""Release 3b: algorithm names from their registries, and identifiers that carry a family.

The rules before this release learned the shapes they were shown and missed every held-out
OpenSSH kind. These tests pin the general readings (registry.py): a registry's name anywhere
it is a whole token, the command lines that name an algorithm, PEM labels, identifiers in a
file that holds crypto -- with the guards that keep post-quantum schemes out of DSA and DH.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp import confidence, cyclonedx, detectors, registry
from qrp_mcp.scan import scan_directory


def _rows(line: str, name: str = "a.sh", lines: list[str] | None = None) -> list[dict]:
    return detectors.scan_source_file(Path(name), name, lines=lines or [line])


def _uses(line: str, name: str = "a.sh") -> set[str]:
    return {f["algorithm"] for f in _rows(line, name)
            if f["evidence_kind"] not in ("comment", "ban")}


def test_the_table_names_its_sources():
    t = registry.table()
    assert {"iana-ssh", "iana-tls", "iana-jose", "iana-cose", "openssh", "openssl"} <= set(
        t["sources"])
    for key, source in t["sources"].items():
        assert source["url"] and source["retrieved"], key
    assert len(t["names"]) > 200


@pytest.mark.parametrize("line,name,family", [
    # SSH (RFC 4253, 8332, 5656; OpenSSH PROTOCOL.certkeys / PROTOCOL.u2f)
    ('HOSTKEYS="rsa-sha2-512 ssh-ed25519"', "a.sh", "RSA"),
    ("algs = ['ssh-rsa-cert-v01@openssh.com']", "a.py", "RSA"),
    ("PubkeyAcceptedAlgorithms sk-ecdsa-sha2-nistp256@openssh.com", "sshd_config", "ECDSA"),
    ('#define KEX_GROUP_EXCHANGE "diffie-hellman-group-exchange-sha256"', "a.h", "DH"),
    ("Ciphers arcfour256", "ssh_config", "RC4"),
    # A wildcard over registry names in an algorithm list or a shell case: one family.
    ("\tecdh-sha2-*) kex=1 ;;", "a.sh", "ECDH"),
    # TLS SignatureScheme and Supported Groups
    ("SignatureAlgorithms = rsa_pss_rsae_sha256:ed25519", "openssl.cnf", "RSA"),
    ("x = ['ecdsa_secp384r1_sha384']", "a.py", "ECDSA"),
    ("ssl_ecdh_curve ffdhe3072;", "nginx.conf", "DH"),
    # JOSE / COSE, quoted whole
    ('{"alg": "ECDH-ES+A256KW"}', "a.json", "ECDH"),
    ('{"crv": "P-384"}', "a.json", "EC"),
    # OpenSSL and ssh-keygen command lines
    ("$OPENSSL_BIN rsa -in k.pem -noout", "a.sh", "RSA"),
    ('subprocess.run(["openssl", "dhparam", "-out", p, "2048"])', "a.py", "DH"),
    ("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256", "a.sh", "EC"),
    ("ssh-keygen -q -t dsa -f k", "a.sh", "DSA"),
    # PEM labels written or looked for, not the armour line
    ('if grep -q "BEGIN EC PRIVATE KEY" "$f"; then', "a.sh", "EC"),
    ('block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}', "a.go", "RSA"),
])
def test_registry_names_are_read(line, name, family):
    assert family in _uses(line, name), line


@pytest.mark.parametrize("line,name,family,fields", [
    ("KexAlgorithms diffie-hellman-group14-sha256", "sshd_config", "DH", {"key_size": 2048}),
    ("x = 'ecdh-sha2-nistp384'", "a.py", "ECDH", {"curve": "P-384", "key_size": 384}),
    ("openssl req -new -newkey rsa:3072 -nodes", "a.sh", "RSA", {"key_size": 3072}),
    ("ssh-keygen -t ecdsa -b 521 -f k", "a.sh", "ECDSA", {"curve": "P-521", "key_size": 521}),
    ("openssl dhparam -out dh.pem 4096", "a.sh", "DH", {"key_size": 4096}),
    ('{"alg": "ES384"}', "a.json", "ECDSA", {"curve": "P-384", "key_size": 384}),
])
def test_the_size_or_curve_the_name_implies_travels(line, name, family, fields):
    row = next(f for f in _rows(line, name) if f["algorithm"] == family)
    assert {k: row.get(k) for k in fields} == fields, row


@pytest.mark.parametrize("line,name,not_family", [
    ("x = 'ssh-mldsa-65'", "a.py", "DSA"), ("SignatureAlgorithms = mldsa44", "a.cnf", "DSA"),
    ("x = 'slhdsa_sha2_128s'", "a.py", "DSA"), ('{"alg": "ML-DSA-44"}', "a.json", "DSA"),
    ('{"alg": "EdDSA"}', "a.json", "DSA"), ('{"alg": "WalnutDSA"}', "a.json", "DSA"),
    ("KexAlgorithms mlkem768-sha256", "sshd_config", "DH"),
    ('{"alg": "ECDH-ES"}', "a.json", "DH"),
    ("KexAlgorithms mlkem768x25519-sha256", "sshd_config", "DH"),
])
def test_post_quantum_names_are_not_their_classical_namesakes(line, name, not_family):
    assert not_family not in _uses(line, name), line


def test_comments_and_bans_keep_their_reading():
    kinds = {f["algorithm"]: f["evidence_kind"]
             for f in _rows("KexAlgorithms -diffie-hellman-group14-sha1", "sshd_config")}
    assert kinds["DH"] == "ban"
    rows = _rows("# we used to offer rsa_pkcs1_sha1 here", "a.sh")
    assert all(f["evidence_kind"] == "comment" for f in rows)
    assert "RSA" not in _uses('log("the rsa_pkcs1_sha1 scheme is not offered by default")', "a.c")


def test_the_pem_armour_line_is_the_key_readers():
    assert "RSA" not in _uses("-----BEGIN RSA PRIVATE KEY-----", "a.py")


def test_a_checksum_tool_stays_a_word():
    # Row 143: `sha1sum file.tar` is a tool's name; so is BSD's `| md5`.
    assert not _uses("sha1sum file.tar") and not _uses("(date; echo $i) | md5 >> out")


C_WITH_CRYPTO = ["#include <openssl/evp.h>", "int t = KEY_RSA_CERT;",
                 "if ((r = rsa_hash_id_from_ident(alg)) != -1)", "min = MAXIMUM(DH_GRP_MIN, min);"]


def test_identifiers_are_read_in_a_file_with_crypto():
    rows = _rows("", "k.c", lines=C_WITH_CRYPTO)
    found = {(f["line"], f["algorithm"]) for f in rows if f["evidence_kind"] == "identifier"}
    assert {(2, "RSA"), (3, "RSA"), (4, "DH")} <= found
    item = next(f for f in rows if f["line"] == 2)
    assert confidence.assess("source_code", item)[0] == "low"


def test_identifiers_alone_are_not_crypto():
    lines = ["int t = KEY_RSA_CERT;", "void rsa_logo_draw(void);"]
    assert not _rows("", "k.c", lines=lines)


@pytest.mark.parametrize("code,not_family", [
    ("ml_dsa_sign(sk, m); slh_dsa_verify(pk, m); EdDSA_sign(k);", "DSA"),
    ("mlkem768_dh_free(x); ECDH_compute_key(a);", "DH"),
    # rel3-rules merge: the identifier block read libcrux's ML-DSA XOF as DSA, which the
    # pattern rules had stopped doing (rel3-config-rust e4bc5d8). An ML-DSA, SLH-DSA or
    # FN-DSA component, or the XOF, says the DSA is the post-quantum one.
    ("let x: DsaXof = DsaXof::new(); impl libcrux_ml_dsa_DsaXof for S {}", "DSA"),
    ("ml_dsa_dsa_key_free(k); SlhDsaKey k; fn_dsa_key_t k;", "DSA"),
    # The DH of a hybrid KEM's key is its elliptic half, not finite-field DH.
    ("mlkem768_dh_key_free(x); KyberDhKey k; x25519_dh_key k;", "DH"),
    ("arc4random_buf(p, n);", "RC4"),
    ("int test_md5_is_refused(void);", "MD5"),
    ("x = RC4 + RSA", "RSA"),
])
def test_identifier_guards(code, not_family):
    assert not_family not in {f for f, _, _ in registry.identifiers(code)}, code


def test_a_registry_size_reaches_its_own_cbom_component(tmp_path):
    (tmp_path / "sshd_config").write_text("KexAlgorithms diffie-hellman-group14-sha256\n")
    doc = cyclonedx.build(scan_directory(tmp_path))
    dh = next(c for c in doc["components"] if c["name"] == "DH-2048")
    assert dh["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "2048"
    assert dh["evidence"]["occurrences"][0]["location"] == "sshd_config"
    # Release 3d: the one sighting names its size, so there is no sizeless DH component.
    assert not any(c["bom-ref"] == "crypto:dh" for c in doc["components"])


def test_the_identifier_hint_never_hides_a_family():
    """registry._HINT is a speed filter: every name _carried() reads a family from matches it.
    Every family word of components.FAMILY in snake, camel and glued forms."""
    import itertools

    from qrp_mcp import components
    names = {pre + w + post for k in components.FAMILY for w in (k, k.lower(), k.capitalize())
             for pre, post in itertools.product(["", "x_", "get", "X", "2", "ab", "AB"],
                                                ["", "_key", "Key", "2", "KEY", "x"])}
    hidden = [n for n in names if registry._carried(n) and not registry._HINT.search(n)]
    assert not hidden, hidden[:10]
