"""Release 3e: recall in Python, Go, Java and JavaScript from the libraries' own API tables.

The DEV-2 tuning corpus (qrp-pokazateli kragg-3/dev-korpus-2, 14 repositories) showed where a
plain substring matcher still found what the scan did not. The kinds that were inventory are
pinned here, each by the vocabulary of the API or specification that defines it, not by the
lines the corpus happened to hold: XML-DSig / XML-Enc algorithm URIs, pyOpenSSL key types,
the DH-parameter calls of Python's ssl, pyOpenSSL and Node's tls, cloud key specs, COSE
constants, SSH key-exchange messages, and identifiers reached through a member access or
carrying a key word of their own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp import detectors, registry


def _rows(lines: list[str], name: str) -> list[dict]:
    return detectors.scan_source_file(Path(name), name, lines=lines)


def _uses(line: str, name: str) -> set[str]:
    return {f["algorithm"] for f in _rows([line], name) if f["evidence_kind"] not in ("comment", "ban")}


# --- identifiers -------------------------------------------------------------------------------

def test_an_identifier_after_a_member_access_is_read():
    # KeyUtils.RSA_ALGORITHM (Apache MINA SSHD), WrappingAlgorithm.RSA_OAEP_SHA1_MGF1 (AWS
    # Encryption SDK), crypto.TYPE_DSA: the name after the dot is the identifier.
    lines = ["import java.security.KeyPairGenerator;",
             "KeyPairGenerator g = KeyPairGenerator.getInstance(KeyUtils.RSA_ALGORITHM);"]
    assert (2, "RSA") in {(f["line"], f["algorithm"]) for f in _rows(lines, "T.java")}


def test_a_dotted_setting_name_in_configuration_is_not_a_member_access():
    # granichni g053: a flag's key in a registry of flags.
    rows = detectors.scan_source_file(Path("flags.yaml"), "flags.yaml", cipher_exclusions=True,
                                      lines=["# crypto flags", "  - key: transport.rsa_enabled",
                                             "    curve: ssh-ed25519"])
    assert (2, "RSA") not in {(f["line"], f["algorithm"]) for f in rows}


@pytest.mark.parametrize("line", [
    "public_key, private_key = generate_rsa_keys()",
    "SOME_RSA_KEYRING = TestKeyringCreator._create_raw_rsa_keyring()",
    "self.mock_wrapping_key.wrapping_algorithm = WrappingAlgorithm.RSA_OAEP_SHA1_MGF1",
])
def test_an_identifier_with_a_key_word_stands_alone(line):
    # No crypto import and no other finding in the file: the identifier names an operation
    # (GENERATE, CREATE) or a scheme (OAEP) beside a public-key family, enough on its own.
    rows = _rows([line], "test_x.py")
    assert ("RSA", "identifier") in [(f["algorithm"], f["evidence_kind"]) for f in rows]


@pytest.mark.parametrize("line", [
    "void rsa_logo_draw(void);",          # no operation
    "rsa_key = load(path)",               # a name without an operation
    "int t = KEY_RSA_CERT;",
    "ec_key = make_ec_key()",             # EC is two letters: needs the file's crypto context
    "md5_key = cache_key(x)",             # a hash, not a public-key family
    "dh_group_key = lookup(g)",           # DH likewise
])
def test_an_identifier_without_context_stays_silent(line):
    assert not _rows([line], "x.py")


def test_the_close_of_a_triple_quoted_value_opens_no_docstring():
    # mitmproxy certs.py: `DEFAULT_DHPARAM = b"""` ... `"""`. The closing delimiter stands
    # alone on its line and was read as a docstring's opener, so every line after it until the
    # next triple quote was a comment, and the two states stayed swapped to the end of the file.
    lines = ['DEFAULT_DHPARAM = b"""', "-----BEGIN DH PARAMETERS-----", '"""', "",
             "def make():", "    return rsa.generate_private_key(65537, 2048)",
             '    """not code: rsa.generate_private_key"""']
    rows = {(f["line"], f["algorithm"], f["evidence_kind"]) for f in _rows(lines, "certs.py")}
    assert (6, "RSA", "call") in rows
    assert (7, "RSA", "comment") in rows


# --- XML-DSig / XML-Enc (W3C xmldsig-core1 §6, xmlenc-core1 §5, RFC 6931, RFC 9231) -----------

@pytest.mark.parametrize("uri,family", [
    ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RSA"),
    ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RSA"),
    ("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", "RSA"),
    ("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "RSA"),
    ("http://www.w3.org/2001/04/xmlenc#rsa-1_5", "RSA"),
    ("http://www.w3.org/2009/xmlenc11#rsa-oaep", "RSA"),
    ("http://www.w3.org/2000/09/xmldsig#RSAKeyValue", "RSA"),
    ("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "DSA"),
    ("http://www.w3.org/2009/xmldsig11#dsa-sha256", "DSA"),
    ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ECDSA"),
    ("http://www.w3.org/2009/xmlenc11#ECDH-ES", "ECDH"),
    ("http://www.w3.org/2001/04/xmlenc#dh", "DH"),
    ("http://www.w3.org/2009/xmlenc11#dh-es", "DH"),
    ("http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519", "EdDSA"),
])
def test_xml_signature_and_encryption_uris(uri, family):
    assert family in _uses(f'Algorithm="{uri}">', "md.py")
    assert family in _uses(f"<SignatureMethod Algorithm='{uri}'/>", "md.xml")


@pytest.mark.parametrize("line,family", [
    ("sign_alg = ds.SIG_RSA_SHA256", "RSA"),                      # pysaml2 saml2.xmldsig
    ("ds.SIG_DSA_SHA1,", "DSA"),
    ("alg = xmldsig.SIG_ECDSA_SHA384", "ECDSA"),
    ("m = SignatureMethod.RSA_SHA256", "RSA"),                    # JSR 105, signxml
    ("m = SignatureMethod.ECDSA_SHA512", "ECDSA"),
    ("m = SignatureMethod.DSA_SHA1", "DSA"),
    ("ctx.sign(node, xmlsec.constants.TransformRsaSha256)", "RSA"),   # python-xmlsec
    ("enc = xmlsec.constants.TransformRsaOaep", "RSA"),
    ("ctx.sign(node, xmlsec.constants.TransformEcdsaSha256)", "ECDSA"),
    ("ctx.sign(node, xmlsec.constants.TransformDsaSha1)", "DSA"),
])
def test_xml_signature_library_constants(line, family):
    assert family in _uses(line, "sig.py")


# --- pyOpenSSL and the DH-parameter calls --------------------------------------------------------

@pytest.mark.parametrize("line,family", [
    ("k.generate_key(crypto.TYPE_RSA, key_length)", "RSA"),       # OpenSSL.crypto.TYPE_*
    ("k.generate_key(OpenSSL.crypto.TYPE_DSA, 2048)", "DSA"),
    ("if key.type() == crypto.TYPE_EC:", "EC"),
    ("ctx.load_dh_params('dhparam.pem')", "DH"),                  # ssl.SSLContext
    ("ctx.load_tmp_dh(dhparam_file)", "DH"),                      # OpenSSL.SSL.Context
    ("ctx.set_tmp_ecdh(crypto.get_elliptic_curve('prime256v1'))", "ECDH"),
])
def test_python_tls_key_and_dh_calls(line, family):
    assert family in _uses(line, "tls.py")


@pytest.mark.parametrize("line", [
    "  dhparam: fs.readFileSync('dh.pem'),",                    # tls.createSecureContext
    "const opts = { key, cert, dhparam: params };",
])
def test_node_tls_dhparam_option(line):
    assert "DH" in _uses(line, "server.js")


def test_a_dhparam_name_in_a_crypto_file_is_dh():
    lines = ["from OpenSSL import SSL", "dh = cls.load_dhparam(dhparam_file)"]
    assert (2, "DH") in {(f["line"], f["algorithm"]) for f in _rows(lines, "certs.py")}


def test_a_dhparam_word_outside_code_is_not_a_call():
    assert "DH" not in _uses("# see the dhparam: section of the docs", "a.py")


# --- key specs and key requests --------------------------------------------------------------------

@pytest.mark.parametrize("line,family", [
    ('key_type="RSA2048",', "RSA"),
    ('assert cert.key_type == "RSA4096"', "RSA"),
    ('"keyType": "ECCPRIME256V1"', "EC"),
    ('key_type = "ECCSECP384R1"', "EC"),
    # AWS KMS KeySpec, ACM KeyAlgorithm, Google Cloud KMS CryptoKeyVersionAlgorithm.
    ('KeySpec="ECC_NIST_P256"', "EC"),
    ('spec = "ECC_SECG_P256K1"', "ECDSA"),
    ('KeyAlgorithm: "EC_prime256v1"', "EC"),
    ('algorithm = "EC_SIGN_P384_SHA384"', "ECDSA"),
    ('algorithm = "RSA_SIGN_PSS_2048_SHA256"', "RSA"),
    ('algorithm = "RSA_DECRYPT_OAEP_3072_SHA256"', "RSA"),
    ('algorithm = "RSA_SIGN_PKCS1_4096_SHA512"', "RSA"),
    # cfssl's key request (csr.KeyRequest: "algo" and "size").
    ('"key": {"algo": "rsa", "size": 2048},', "RSA"),
    ('KeyAlgo:       "rsa",', "RSA"),
    ('KeyAlgo: "ecdsa",', "ECDSA"),
])
def test_key_specs(line, family):
    assert family in _uses(line, "spec.py")


@pytest.mark.parametrize("line", [
    '"algo": "aes"', 'x = "RSA20"', 'name = "PRSA2048X"', 'algo = "sha256"',
    # A fixture's file name, and a Cloud KMS name in a sentence (granichni g039, g064).
    '"rsa1024-leaf.der",',
    "guarantee. RSA_SIGN_PKCS1_2048_SHA256 is refused by the organisation policy",
])
def test_key_spec_lookalikes(line):
    assert not ({"RSA", "EC", "ECDSA"} & _uses(line, "spec.py"))


# --- COSE constants and SSH key-exchange messages ------------------------------------------------

@pytest.mark.parametrize("line,family", [
    ("case webauthncose.AlgES256:", "ECDSA"),                    # go-webauthn webauthncose
    ("case webauthncose.AlgRS256, webauthncose.AlgPS256:", "RSA"),
    ("case webauthncose.AlgEdDSA:", "EdDSA"),
    ("case webauthncose.AlgEd25519:", "EdDSA"),
])
def test_cose_algorithm_constants(line, family):
    assert family in _uses(line, "metadata.go")


@pytest.mark.parametrize("line,family", [
    ("packet[p] = MESSAGE.KEXDH_REPLY;", "DH"),                  # RFC 4253 §8
    ("case SSH_MSG_KEXDH_INIT:", "DH"),
    ("send(SSH_MSG_KEX_DH_GEX_REQUEST)", "DH"),                  # RFC 4419
    ("case MESSAGE.KEX_ECDH_REPLY:", "ECDH"),                    # RFC 5656 §7.1
    ("case SSH_MSG_KEX_ECDH_INIT:", "ECDH"),
])
def test_ssh_key_exchange_messages(line, family):
    assert family in _uses(line, "kex.js")


def test_every_new_pattern_keeps_a_prefilter_literal():
    # One pattern without a literal and the gate passes every line (detectors._ANY_LITERAL).
    assert all(f[3] for f in detectors._FILTERED_PATTERNS
               if f[1].startswith(tuple(registry_descriptions())))


def registry_descriptions() -> tuple[str, ...]:
    return tuple(d for _, d, _ in detectors.ALGORITHM_PATTERNS if "(release 3e)" in d)


def test_release_3e_patterns_are_there():
    assert len(registry_descriptions()) >= 6
    assert registry.stands_alone("generate_rsa_keys") and not registry.stands_alone("rsa_logo_draw")
