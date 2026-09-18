"""Gaps found by comparing against CryptoScan, CBOMkit-hyperion and CBOMkit-theia
(see ~/zadachi/qrp-kachestvo/sravnenie-1/REZULTAT.md, items 1, 2 and 5).

The rules knew library calls and curve names; they did not know the names the
protocols themselves use. OpenSSH's default algorithm list was reported in full
except for RSA.
"""
from __future__ import annotations

from qrp_mcp.scan import scan_directory


def families(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return set(scan_directory(str(tmp_path))["detected_algorithms"])


def findings(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return {f["algorithm_family"]: f for f in scan_directory(str(tmp_path))["findings"]}


# --- 1. the names protocols use -------------------------------------------------

def test_ssh_host_key_algorithm_names(tmp_path):
    fam = families(tmp_path, "sshd_config",
                   "HostKeyAlgorithms ssh-rsa,rsa-sha2-512,rsa-sha2-256,ssh-ed25519\n")
    assert {"RSA", "Ed25519"} <= fam


def test_openssh_default_proposal_line(tmp_path):
    # myproposal.h:61-62 — every other family on that list was reported.
    fam = families(tmp_path, "myproposal.h",
                   '#define KEX_DEFAULT_PK_ALG \\\n'
                   '\t"rsa-sha2-512-cert-v01@openssh.com,"\\\n'
                   '\t"ssh-ed25519-cert-v01@openssh.com,"\n')
    assert "RSA" in fam


def test_key_type_names_in_code(tmp_path):
    # vault path_keys.go — ecdsa-p256, ed25519, ml-dsa were found, rsa-2048 was not.
    fam = families(tmp_path, "path_keys.go",
                   'case "rsa-2048":\n\tfallthrough\ncase "ecdsa-p256":\n\tfallthrough\n'
                   'case "ed25519":\n')
    assert {"RSA", "ECDSA", "Ed25519"} <= fam


def test_aws_style_key_spec(tmp_path):
    fam = families(tmp_path, "main.tf", 'customer_master_key_spec = "RSA_4096"\n')
    assert "RSA" in fam


def test_ssh_dss_name(tmp_path):
    assert "DSA" in families(tmp_path, "ssh_config", "HostKeyAlgorithms ssh-dss\n")


# --- 2. cipher suite names ------------------------------------------------------

def test_apache_cipher_suite_line(tmp_path):
    fam = families(tmp_path, "options-ssl-apache.conf",
                   "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:"
                   "DHE-DSS-AES128-GCM-SHA256:DES-CBC3-SHA\n")
    assert {"ECDH", "RSA", "DH", "DSA", "DES"} <= fam


def test_openssl_header_suite_constant(tmp_path):
    fam = families(tmp_path, "ssl3.h",
                   '#define SSL3_TXT_DHE_DSS_DES_40_CBC_SHA "EXP-DHE-DSS-DES-CBC-SHA"\n')
    assert {"DH", "DSA", "DES"} <= fam


def test_excluded_suite_component_is_still_not_a_use(tmp_path):
    # Our advantage over CryptoScan: "!MD5" is a ban, not a use.
    fam = families(tmp_path, "nginx.conf",
                   "ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!kRSA;\n")
    assert "MD5" not in fam and "DES" not in fam and "RSA" not in fam


# --- 5. key size ----------------------------------------------------------------

def test_weak_rsa_key_size_in_python(tmp_path):
    f = findings(tmp_path, "gen.py",
                 "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n")
    assert f["RSA"]["weak_key"] is True


def test_strong_rsa_key_size_is_not_weak(tmp_path):
    f = findings(tmp_path, "gen.py",
                 "k = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n")
    assert f["RSA"]["weak_key"] is False


def test_key_size_from_openssl_command_and_go(tmp_path):
    f = findings(tmp_path, "build.sh", "openssl req -newkey rsa:1024 -nodes\n")
    assert f["RSA"]["weak_key"] is True


# --- false positives the corpora caught in the first version of this rule ---------

def test_hyphenated_prose_is_not_a_cipher_suite(tmp_path):
    # bitcoin_fr.ts: "Remplacer-par-des-frais" read as DES.
    assert "DES" not in families(tmp_path, "bitcoin_fr.ts",
                                 "<translation>Activer Remplacer-par-des-frais</translation>\n")


def test_pqc_parameter_names_are_not_classical_dsa(tmp_path):
    # vault path_keys.go: "slh-dsa-sha2-128s" read as DSA; "ML-DSA-65" likewise.
    fam = families(tmp_path, "path_keys.go",
                   '"slh-dsa-sha2-128s", "slh-dsa-shake128f",\n// ML-DSA-65 only\n')
    assert "DSA" not in fam and {"SLH-DSA", "ML-DSA"} <= fam


def test_iana_suite_name_is_read(tmp_path):
    fam = families(tmp_path, "tls.go", "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\n")
    assert {"ECDH", "RSA"} <= fam


def test_key_sizes_are_visible_in_the_result(tmp_path):
    (tmp_path / "gen.py").write_text("k = rsa.generate_private_key(65537, key_size=1024)\n")
    assert scan_directory(str(tmp_path))["algorithm_key_sizes"] == {"RSA": 1024}
