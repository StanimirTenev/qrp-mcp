"""Gaps 3, 4, 6 and 8 from the tool comparison.

Rules knew the OpenSSL 1.x API and two hash idioms; the modern provider API and the
common hash idioms went unseen, and the CBOM claimed a complete component list on
the strength of having read every file.
"""
from __future__ import annotations

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory


def families(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return set(scan_directory(str(tmp_path))["detected_algorithms"])


# --- 3. OpenSSL 3 names the algorithm in a string --------------------------------

def test_evp_pkey_q_keygen(tmp_path):
    # demos/pkey/EVP_PKEY_RSA_keygen.c:115 - the file name says RSA and we found nothing.
    fam = families(tmp_path, "EVP_PKEY_RSA_keygen.c",
                   'pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", (size_t)bits);\n')
    assert "RSA" in fam


def test_evp_pkey_ctx_new_from_name(tmp_path):
    fam = families(tmp_path, "acvp_test.c",
                   'ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);\n')
    assert "RSA" in fam


def test_evp_pkey_ctx_is_a_rsa_pss(tmp_path):
    fam = families(tmp_path, "req.c", 'if (EVP_PKEY_CTX_is_a(genctx, "RSA-PSS"))\n')
    assert "RSA" in fam


def test_evp_q_keygen_named_curve(tmp_path):
    fam = families(tmp_path, "lms_test.c",
                   'EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256");\n')
    assert "EC" in fam


def test_evp_fetch_names_a_digest(tmp_path):
    fam = families(tmp_path, "sign.c", 'md = EVP_MD_fetch(libctx, "SHA1", propq);\n')
    assert "SHA1" in fam


def test_an_unknown_fetch_name_does_not_invent_a_family(tmp_path):
    fam = families(tmp_path, "x.c", 'EVP_MD_fetch(libctx, "SHA2-256", propq);\n')
    assert fam == set()


# --- 4. the hash idioms people actually write ------------------------------------

def test_pyca_hashes_objects(tmp_path):
    fam = families(tmp_path, "d.py",
                   "h_md5 = hashes.Hash(hashes.MD5())\nh_sha1 = hashes.Hash(hashes.SHA1())\n")
    assert {"MD5", "SHA1"} <= fam


def test_hashlib_new(tmp_path):
    fam = families(tmp_path, "account.py", "hasher = hashlib.new('md5', data)\n")
    assert "MD5" in fam


def test_bsd_style_c_calls_and_headers(tmp_path):
    fam = families(tmp_path, "digest-libc.c", "#include <sha1.h>\nSHA1Init(&ctx);\nMD5Init(&m);\n")
    assert {"MD5", "SHA1"} <= fam


def test_go_usage_without_the_import_line(tmp_path):
    fam = families(tmp_path, "sum.go", "sum := sha1.Sum(data)\nh := md5.New()\n")
    assert {"MD5", "SHA1"} <= fam


# --- 6, 8. the document does not claim more than the scan knows -------------------

def test_aggregate_is_not_complete_without_a_control(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    doc = cyclonedx.build(scan_directory(str(tmp_path)))
    # Every file was read, but nothing licenses a claim that every asset was found.
    assert doc["compositions"][0]["aggregate"] == "unknown"


def test_claimed_types_names_the_certificate_extensions_we_read(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    claimed = scan_directory(str(tmp_path))["coverage"]["instrument"]["claimed_types"]
    assert ".pem" in claimed.get("certificate", []) and ".der" in claimed["certificate"]


def test_ruleset_counts_the_rules_that_are_not_line_patterns(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    ruleset = scan_directory(str(tmp_path))["coverage"]["instrument"]["ruleset"]
    assert ruleset.get("certificate_oid_names") and ruleset.get("pem_labels")
