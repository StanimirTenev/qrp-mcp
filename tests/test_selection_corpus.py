"""Which files the scanner opens, pinned as a contract.

There was a corpus test for what the scanner recognises and none for where it
looks, so a whole class of gap could only surface by running the tool on a real
tree -- which is how it surfaced: nginx.conf and sshd_config were not read at
all, and the RFC 10024 hybrid vocabulary lives in exactly those files.

This fixture is one file of each kind a real estate contains. It asserts which
bucket each lands in, so coverage is a decision rather than an emergent property
of a chain of elif branches.
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory

TREE = {
    # source
    "app/wallet.py": 'from ecdsa import SigningKey, SECP256k1\n',
    "app/contract.sol": 'function verify() { ecrecover(h, v, r, s); }\n',
    # C and C++ headers: found by scanning real trees. Reading .c but not .h
    # under-reads a C codebase by roughly half its files.
    "src/crypto.h": 'RSA *RSA_new(void);\n',
    "src/key.hpp": '#include <openssl/ecdsa.h>\n',
    # PowerShell: our own Windows agent reads RSA and ECDSA public keys out of
    # X.509 certificates in a .ps1, and this scanner would not open the file.
    "agent/collect.ps1": (
        '[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]'
        '::GetRSAPublicKey($c)\n'
    ),
    # configuration -- where cryptographic choices are made rather than written
    "etc/nginx.conf": 'ssl_ecdh_curve X25519MLKEM768;\n',
    "etc/sshd_config": 'KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n',
    "etc/openssl.cnf": 'default_md = sha256\n',
    "app/settings.toml": 'signing = "Ed25519"\n',
    # a YAML that is not a manifest: it used to be read and then dropped
    "docs/values.yaml": 'image: nginx\nreplicas: 2\n',
    # infrastructure
    "infra/main.tf": 'resource "aws_kms_key" "k" { customer_master_key_spec = "RSA_4096" }\n',
    "infra/cert.yaml": (
        "apiVersion: cert-manager.io/v1\nkind: Certificate\n"
        "spec:\n  privateKey:\n    algorithm: ECDSA\n"
    ),
    # CI
    "Jenkinsfile": 'sh "cosign sign --key k image"\n',
    # never opened: not a file class this tool claims to read
    "README.md": "# docs\n",
    "logo.png": "binary\n",
}


def _build(tmp_path):
    for rel, text in TREE.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return scan_directory(str(tmp_path))


def test_every_file_class_lands_in_its_bucket(tmp_path):
    counted = _build(tmp_path)["files_scanned"]
    assert counted == {"source": 5, "ci_config": 1, "iac": 2, "config": 5, "certificate": 0}


def test_configuration_files_are_read_at_all(tmp_path):
    """The gap that started this file: a hybrid group in a config was invisible."""
    families = {f["algorithm_family"] for f in _build(tmp_path)["findings"]}
    assert {"ML-KEM", "X25519"} <= families


def test_a_yaml_that_is_not_a_manifest_is_still_counted(tmp_path):
    """It used to be opened, matched against nothing, and left no trace anywhere."""
    result = _build(tmp_path)
    assert result["files_scanned"]["config"] >= 1
    assert "docs/values.yaml" not in result["unreadable_files"]


def test_nothing_opened_disappears(tmp_path):
    """Read, counted, or listed as unreadable. There is no fourth outcome.

    A file that is opened and then falls off the end of the loop is the failure
    this scanner exists to make impossible: it produces no findings and no mark,
    so its silence is indistinguishable from a clean result.
    """
    _build(tmp_path)
    (tmp_path / "etc" / "locked.conf").write_text("ssl_ciphers HIGH;\n")
    (tmp_path / "etc" / "locked.conf").chmod(0o000)
    result = scan_directory(str(tmp_path))

    considered = sum(result["files_scanned"].values()) + len(result["unreadable_files"])
    # Everything in TREE the scanner claims, plus the one it cannot open. README.md
    # and logo.png are not claimed, so they are neither counted nor listed.
    claimed = set(TREE) - {"README.md", "logo.png"}
    assert considered == len(claimed) + 1
    assert "etc/locked.conf" in result["unreadable_files"]


def test_files_the_scanner_does_not_claim_are_not_counted_as_scanned(tmp_path):
    """Coverage must not be inflated by files nobody promised to read."""
    result = _build(tmp_path)
    assert sum(result["files_scanned"].values()) == 13
    assert result["unreadable_files"] == []


# --- the denominator -------------------------------------------------------
# files_scanned says how much was read. On its own it does not say how much
# there was, and a coverage figure without a base is the shape of claim this
# scanner exists to refuse -- so the tree is counted too.
def test_the_three_outcomes_account_for_every_file_present(tmp_path):
    _build(tmp_path)
    (tmp_path / "etc" / "locked.conf").write_text("ssl_ciphers HIGH;\n")
    (tmp_path / "etc" / "locked.conf").chmod(0o000)
    result = scan_directory(str(tmp_path))

    counted = sum(result["files_scanned"].values())
    unread = len(result["unreadable_files"])
    skipped = sum(result["files_skipped_by_type"].values())
    assert counted + unread + skipped == result["files_present"]
    assert result["files_present"] == len(TREE) + 1


def test_skipped_types_are_named_not_merely_counted(tmp_path):
    """So the reader can ask what is in them, rather than assume it is nothing."""
    skipped = _build(tmp_path)["files_skipped_by_type"]
    assert skipped == {".md": 1, ".png": 1}


def test_excluded_directories_stay_out_of_the_denominator(tmp_path):
    """Vendored and build trees would drown the figure without saying anything."""
    _build(tmp_path)
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    for i in range(20):
        (vendored / f"f{i}.js").write_text("const crypto = require('crypto')\n")
    result = scan_directory(str(tmp_path))
    assert result["files_present"] == len(TREE)


def test_c_headers_are_source_not_skipped(tmp_path):
    """Reading .c but not .h reports part of a C tree as if it were all of it."""
    result = _build(tmp_path)
    assert ".h" not in result["files_skipped_by_type"]
    assert ".hpp" not in result["files_skipped_by_type"]


def test_powershell_is_source_not_skipped(tmp_path):
    """.sh was already claimed, so omitting .ps1 was an oversight, not a boundary."""
    result = _build(tmp_path)
    assert ".ps1" not in result["files_skipped_by_type"]


def test_generated_caches_stay_out_of_the_denominator(tmp_path):
    """A cache is generated, like node_modules. Counting it pads the one number
    this scanner exists to state honestly."""
    before = _build(tmp_path)["files_present"]
    for rel in (".pytest_cache/v/cache/nodeids", ".mypy_cache/x.json",
                ".ruff_cache/content"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("generated\n", encoding="utf-8")
    assert scan_directory(str(tmp_path))["files_present"] == before


# --- certificates and keys --------------------------------------------------
# Scanning five well-known repositories put a number on this gap: 1,284 public
# keys, 1,059 private keys and 652 certificates sat in files the scanner never
# opened, so embedded_key_findings was 0 in every one of them.
CERTIFICATE_TREE = {
    "tls/server.pem": (
        "-----BEGIN CERTIFICATE-----\n"
        # Minimal DER carrying the rsaEncryption identifier 1.2.840.113549.1.1.1.
        "MAoGCCqGSIb3DQEBAQ==\n"
        "-----END CERTIFICATE-----\n"
    ),
    "tls/server.key": (
        "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n-----END RSA PRIVATE KEY-----\n"
    ),
    "tls/params.pem": (
        "-----BEGIN DH PARAMETERS-----\nMAA=\n-----END DH PARAMETERS-----\n"
    ),
    "ssh/id_ed25519.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host\n",
    "ssh/id_ecdsa.pub": "ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host\n",
}


def _build_certs(tmp_path):
    for rel, text in CERTIFICATE_TREE.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return scan_directory(str(tmp_path))


def test_certificate_and_key_files_are_opened(tmp_path):
    result = _build_certs(tmp_path)
    assert result["files_scanned"]["certificate"] == len(CERTIFICATE_TREE)
    for ext in (".pem", ".key", ".pub"):
        assert ext not in result["files_skipped_by_type"]


def test_private_key_material_is_reported(tmp_path):
    """The pattern for this existed and no path ever opened such a file."""
    keys = _build_certs(tmp_path)["evidence"]["embedded_keys"]
    assert [k["type"] for k in keys] == ["RSA PRIVATE KEY"]


def test_algorithms_come_from_labels_and_ssh_key_types(tmp_path):
    families = {f["algorithm_family"] for f in _build_certs(tmp_path)["findings"]}
    assert {"RSA", "DH", "Ed25519", "ECDSA"} <= families


def test_the_three_outcomes_still_account_for_every_file(tmp_path):
    result = _build_certs(tmp_path)
    counted = sum(result["files_scanned"].values())
    unread = len(result["unreadable_files"])
    skipped = sum(result["files_skipped_by_type"].values())
    assert counted + unread + skipped == result["files_present"]


def test_malformed_certificates_yield_nothing_rather_than_nonsense(tmp_path):
    """OpenSSL's corpus is deliberately full of broken certificates. A file that
    cannot be understood must leave the scan as nothing found, not as an
    exception and not as an invented algorithm."""
    (tmp_path / "broken.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n!!!!\n")
    (tmp_path / "garbage.der").write_bytes(bytes(range(256)) * 4)
    (tmp_path / "empty.crt").write_bytes(b"")
    result = scan_directory(str(tmp_path))
    assert result["files_scanned"]["certificate"] == 3
    assert result["findings"] == []
