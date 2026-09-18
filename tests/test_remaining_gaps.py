"""The gaps left open in 0.8.1, named in its release notes.

7  — private keys are recognised by extension, so a key in a file with none is missed
      (CBOMkit-theia finds 45 such files in OpenSSH).
11 — 3DES is reported under DES, so a report cannot tell them apart.
10 — a few C idioms are not read.
"""
from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def families(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return set(scan_directory(str(tmp_path))["detected_algorithms"])


# --- 7. a key is a key whatever the file is called --------------------------------

def test_private_key_in_a_file_without_an_extension(tmp_path):
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\n-----END RSA PRIVATE KEY-----\n")
    r = scan_directory(str(tmp_path))
    assert r["evidence"]["embedded_keys"], "key material not reported"
    assert "RSA" in r["detected_algorithms"]


def test_openssh_key_format_without_an_extension(tmp_path):
    (tmp_path / "id_ed25519").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\n"
        "-----END OPENSSH PRIVATE KEY-----\n")
    assert scan_directory(str(tmp_path))["evidence"]["embedded_keys"]


def test_key_with_an_unclaimed_extension(tmp_path):
    (tmp_path / "rsa_openssh.prv").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\nMIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\n-----END RSA PRIVATE KEY-----\n")
    assert scan_directory(str(tmp_path))["evidence"]["embedded_keys"]


def test_a_large_file_is_not_opened_looking_for_keys(tmp_path):
    # The check exists to catch small key files, not to read every blob in the tree.
    big = tmp_path / "blob.dat"
    big.write_text("x" * 200_000)
    r = scan_directory(str(tmp_path))
    assert r["files_skipped_by_type"].get(".dat") == 1


# --- 11. 3DES is not DES ----------------------------------------------------------

def test_triple_des_is_its_own_family(tmp_path):
    fam = families(tmp_path, "c.py", "cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))\n")
    assert "3DES" in fam and "DES" not in fam


def test_single_des_is_still_des(tmp_path):
    assert "DES" in families(tmp_path, "c.c", "DES_set_key(&k, &sched);\n")


def test_des_ede3_suite_component_is_3des(tmp_path):
    fam = families(tmp_path, "ssl.h", '#define X "EXP-DHE-DSS-DES-CBC3-SHA"\n')
    assert "3DES" in fam


# --- 10. the C idioms that were left ----------------------------------------------

def test_openssl_low_level_rsa_accessors(tmp_path):
    fam = families(tmp_path, "ssh-rsa.c", "const BIGNUM *n; RSA_get0_key(rsa, &n, NULL, NULL);\n")
    assert "RSA" in fam


def test_evp_pkey_get_rsa(tmp_path):
    fam = families(tmp_path, "x.c", "RSA *r = EVP_PKEY_get1_RSA(pkey);\n")
    assert "RSA" in fam


def test_bare_nist_curve_names(tmp_path):
    fam = families(tmp_path, "sshkey.c", 'if (strcmp(name, "nistp256") == 0)\n')
    assert "EC" in fam


# The 3DES split first shipped with \b boundaries, which silently dropped every
# real-world spelling where the word is glued to an identifier: OpenSSL's
# OPT_3DES_WRAP, Vault's DESEDE3CBC, Go's NewTripleDESCipher. Measured on the
# corpora: 109 occurrences lost in openssl, 17 in vault, 1 in test-repo.
@pytest.mark.parametrize(
    "line",
    [
        "    OPT_3DES_WRAP,",
        "def enc_3des(key, iv, data):",
        "case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):",
        "block, err = des.NewTripleDESCipher(key)",
        '"Use legacy encryption algorithm 3DES_CBC for keys and certs"',
    ],
)
def test_triple_des_glued_to_identifier(tmp_path, line):
    f = tmp_path / "a.c"
    f.write_text(line + "\n")
    result = scan_directory(tmp_path)
    assert "3DES" in result["detected_algorithms"], line


def test_documentation_example_is_not_key_material(tmp_path):
    """OpenSSL's doc/man3/PEM_read.pod shows the markers with the body elided.

    A header with no base64 body is documentation, not a key.
    """
    (tmp_path / "PEM_read.pod").write_text(
        "by begin/end markers each on their own line.  For example:\n"
        "\n"
        " -----BEGIN PRIVATE KEY-----\n"
        " MIICdg....\n"
        " ... bhTQ==\n"
        " -----END PRIVATE KEY-----\n"
    )
    result = scan_directory(tmp_path)
    assert result["evidence"]["embedded_keys"] == []


def test_two_key_triple_des_is_not_also_single_des(tmp_path):
    """OpenSSL's EVP_des_ede* is two-key triple DES: no '3' in the name.

    It must land in 3DES alone; the single-DES lookahead has to exclude the
    whole ede family, not only ede3.
    """
    (tmp_path / "evp.h").write_text(
        "const EVP_CIPHER *EVP_des_ede(void);\n"
        "const EVP_CIPHER *EVP_des_ede_cbc(void);\n")
    result = scan_directory(tmp_path)
    assert "3DES" in result["detected_algorithms"]
    assert "DES" not in result["detected_algorithms"]


def test_triple_des_suite_is_not_also_single_des(tmp_path):
    """DES-CBC3-SHA decomposes to DES + CBC3; only the 3DES reading is right.

    Measured on certbot: 4 cipher-list lines carried both families.
    """
    (tmp_path / "ssl.conf").write_text(
        "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA\n")
    result = scan_directory(tmp_path)
    assert "3DES" in result["detected_algorithms"]
    assert "DES" not in result["detected_algorithms"]


def test_single_des_suite_is_still_des(tmp_path):
    (tmp_path / "ssl.conf").write_text("SSLCipherSuite EDH-RSA-DES-CBC-SHA\n")
    result = scan_directory(tmp_path)
    assert "DES" in result["detected_algorithms"]
    assert "3DES" not in result["detected_algorithms"]


def test_openssl3_des_ede3_name_is_triple_des(tmp_path):
    (tmp_path / "a.c").write_text('cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);\n')
    result = scan_directory(tmp_path)
    assert "3DES" in result["detected_algorithms"]
    assert "DES" not in result["detected_algorithms"]
