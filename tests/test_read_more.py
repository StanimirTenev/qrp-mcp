"""Reading more of the tree, and not paying for it in noise.

Measured on the corpora: we read 61% of files. The types below carry real
cryptography; documentation (.txt/.md/.pod/.rst) carries mentions of it and stays
out, which is a scope statement rather than a silent skip.
"""
from __future__ import annotations

from qrp_mcp.scan import scan_directory


def families(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return set(scan_directory(str(tmp_path))["detected_algorithms"])


def test_c_include_fragment_is_read(tmp_path):
    # openssl/crypto/ml_dsa/asm/*.inc — the implementations themselves.
    assert "ML-DSA" in families(tmp_path, "mldsa_macros.inc", "#define ML_DSA_Q 8380417\n")


def test_perl_test_recipe_is_read(tmp_path):
    # openssl/test/recipes/*.t — tests are code; we do not skip tests silently.
    assert "ML-KEM" in families(tmp_path, "03-test_evp_extra_ml_kem.t",
                                "plan skip_all => 'ML-KEM is not supported'\n")


def test_hcl_configuration_is_read(tmp_path):
    assert "X25519" in families(tmp_path, "agent.hcl", 'dh_type = "curve25519"\n')


def test_json_configuration_is_read(tmp_path):
    fam = families(tmp_path, "config.hcl.json",
                   '"cluster_cipher_suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"\n')
    assert {"ECDH", "RSA"} <= fam


def test_build_files_are_read(tmp_path):
    (tmp_path / "Makefile").write_text("SRCS = ssh-ed25519.o ssh-rsa.o\n")
    (tmp_path / "CMakeLists.cmake").write_text("list(APPEND SRC src/secp256k1.c)\n")
    fam = set(scan_directory(str(tmp_path))["detected_algorithms"])
    assert {"Ed25519", "RSA", "ECDSA"} <= fam


def test_ssh_known_hosts_and_authorized_keys(tmp_path):
    (tmp_path / "known_hosts").write_text("host ecdsa-sha2-nistp384 AAAAE2VjZHNh\n")
    (tmp_path / "authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2E user@host\n")
    fam = set(scan_directory(str(tmp_path))["detected_algorithms"])
    assert {"ECDSA", "RSA"} <= fam


def test_documentation_stays_out_of_scope(tmp_path):
    # certbot/docs/cli-help.txt and CHANGELOG.md name algorithms in prose; a mention
    # in documentation is not a deployment, and counting it would inflate the number.
    (tmp_path / "CHANGELOG.md").write_text("* Added `DHE-RSA-CHACHA20-POLY1305` to the list\n")
    (tmp_path / "cli-help.txt").write_text("--key-type {rsa,ecdsa}\n")
    r = scan_directory(str(tmp_path))
    assert r["detected_algorithms"] == []
    assert set(r["files_skipped_by_type"]) == {".md", ".txt"}


def test_hex_test_vectors_do_not_spell_algorithms(tmp_path):
    # openssh/regress/.../nistkats-44.json: "ed448" occurs inside a hex message.
    fam = families(tmp_path, "kats.json",
                   '"message": "0998114c84f84080e7eebb47d248980faed448c9d28f1abb6dbab3dd59a5cfd2c7cff"\n')
    assert "Ed448" not in fam


def test_base64_blob_does_not_spell_algorithms(tmp_path):
    fam = families(tmp_path, "blob.json",
                   '"key": "TUlJQ2RRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NBbDh3Z2dKYkFnRUFBb0dCQU1kES"\n')
    assert "DES" not in fam
