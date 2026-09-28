"""The role of an RSA or EC occurrence, read from its own line, and what it does to the
suggested replacement. Undetermined is the honest answer wherever the line does not say."""

import json
import subprocess
import sys

import pytest

from qrp_mcp.remediation import role_of, suggest


def _r(excerpt, algorithm="RSA", description="RSA usage"):
    return role_of({"algorithm": algorithm, "excerpt": excerpt, "description": description})


@pytest.mark.parametrize("line", [
    "alg=jose.RS256", "_test_it('', 'RS512')", 'return "rsa-sha2-256";',
    "ssh-rsa AAAAB3NzaC1yc2E", "jose.JWS.sign(payload=p, key=KEY)",
    "Signature.getInstance(\"SHA256withRSA\")", "1.2.840.113549.1.1.11",
    "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA;", "#define CKM_RSA_PKCS_PSS",
])
def test_rsa_signature_lines(line):
    assert _r(line) == "signature"


@pytest.mark.parametrize("line", [
    "cipher = PKCS1_OAEP.new(key)", "RSA_public_encrypt(len, in, out, rsa, pad)",
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "1.2.840.113549.1.1.7", "alg = 'RSA-OAEP-256'",
])
def test_rsa_key_establishment_lines(line):
    assert _r(line) == "key_establishment"


@pytest.mark.parametrize("line", [
    # a key made here is used elsewhere
    "k = rsa.generate_private_key(65537, 2048)", "-----BEGIN RSA PRIVATE KEY-----",
    "1.2.840.113549.1.1.1",
    # both roles on one line
    "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA;", "sign then encrypt with rsa",
    # words that contain the signal and are not it
    "signal(SIGTERM) RSA", "assign_rsa(k)",
])
def test_rsa_undetermined_lines(line):
    assert _r(line) == "undetermined"


def test_a_cipher_list_cut_at_the_excerpt_limit_is_undetermined():
    line = ("ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES128-GCM-SHA256:" * 4)[:200]
    assert len(line) == 200
    assert _r(line) == "undetermined"
    assert _r(line[:120]) == "signature"


def test_ec_lines():
    assert _r("do_kex(\"ecdh-sha2-nistp256\");", "EC") == "key_establishment"
    assert _r("\"ecdsa-sha2-nistp256,\" \\", "EC") == "signature"
    assert _r("key = ec.generate_private_key(ec.SECP256R1())", "EC") == "undetermined"


def test_other_families_are_not_asked():
    assert _r("ECDSA_sign(...)", "ECDSA") is None


def _finding(fam="RSA"):
    return {"classification": "classical_vulnerable", "algorithm_family": fam}


def test_only_signature_lines_drop_the_key_establishment_path():
    out = suggest(_finding(), {"signature": 3, "key_establishment": 0, "undetermined": 0})
    assert [o["for"].split()[0] for o in out["options"]] == ["signatures", "firmware"]
    assert out["roles_seen"] == {"signature": 3, "key_establishment": 0, "undetermined": 0}
    assert out["options"][0]["lines_with_this_role"] == 3


def test_an_undetermined_line_keeps_every_path():
    out = suggest(_finding(), {"signature": 3, "key_establishment": 0, "undetermined": 1})
    assert len(out["options"]) == 3
    kem = [o for o in out["options"] if o["for"].startswith("key establishment")][0]
    assert kem["lines_with_this_role"] == 0 and kem["lines_undetermined"] == 1


def test_without_roles_the_suggestion_is_as_before():
    out = suggest(_finding())
    assert len(out["options"]) == 3 and "roles_seen" not in out


def _scan(tmp_path, *extra):
    (tmp_path / "a.py").write_text(
        "import jwt\njwt.encode(p, k, algorithm='RS256')\n"
        "# RS256 in a comment\n"
        "k = rsa.generate_private_key(65537, 2048)\n")
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tmp_path),
                    "--out", str(out), *extra], check=True, capture_output=True)
    return json.loads(out.read_text())


def test_scan_marks_occurrences_and_counts_code_only(tmp_path):
    d = _scan(tmp_path)
    rsa = [o for o in d["evidence"]["source_code"] if o["algorithm"] == "RSA"]
    assert {o["role"] for o in rsa} == {"signature", "undetermined"}
    finding = [f for f in d["findings"] if f.get("algorithm_family") == "RSA"][0]
    seen = finding["replacement"]["roles_seen"]
    comments = [o for o in rsa if o.get("evidence_kind") == "comment"]
    assert sum(seen.values()) == len(rsa) - len(comments)


def test_the_role_survives_masking(tmp_path):
    full = _scan(tmp_path, "--level", "full")
    masked = _scan(tmp_path, "--level", "masked")
    key = lambda d: sorted((o["line"], o["role"]) for o in d["evidence"]["source_code"] if "role" in o)
    assert key(full) == key(masked) and key(full)


def test_the_role_stays_out_of_the_cbom(tmp_path):
    (tmp_path / "a.py").write_text("jwt.encode(p, k, algorithm='RS256')\n")
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tmp_path)],
                       check=True, capture_output=True, text=True)
    keys = []

    def walk(node):
        if isinstance(node, dict):
            keys.extend(node)
            if str(node.get("name", "")).startswith("qrp:"):
                keys.append(node["name"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(json.loads(r.stdout))
    assert keys and not [k for k in keys if "role" in k.lower()]


def test_the_role_is_not_part_of_closure_identity():
    from qrp_mcp.closure import _identity
    a = {"path": "a.py", "line": 1, "algorithm": "RSA", "excerpt": "x", "role": "signature"}
    b = {**a, "role": "undetermined"}
    assert _identity("source_code", a) == _identity("source_code", b)


def test_the_mcp_tool_carries_the_role(tmp_path):
    from qrp_mcp.server import scan_repo
    (tmp_path / "a.py").write_text("jwt.encode(p, k, algorithm='RS256')\n")
    d = scan_repo(str(tmp_path))
    assert [o["role"] for o in d["evidence"]["source_code"] if o["algorithm"] == "RSA"] == ["signature"]


# 0.23: the TLS-name defects found on Vault and OpenSSL in the 0.21 measurement.
@pytest.mark.parametrize("line", [
    "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",           # IANA spelling, underscores
    '{ 0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },',
    "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256   ECDH-RSA-CAMELLIA128-SHA256",  # fixed ECDH
    "#define TLS_CT_RSA_FIXED_ECDH 65",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
])
def test_rsa_that_signs_in_a_tls_name_is_signature(line):
    assert _r(line) == "signature"


def test_rsa_key_transport_suites_stay_key_establishment():
    assert _r("TLS_RSA_WITH_RC4_128_SHA") == "key_establishment"


@pytest.mark.parametrize("line", [
    "{ OSSL_ACTION_GET, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,",
    "if (pkey->type != EVP_PKEY_RSA && pkey->type != EVP_PKEY_RSA_PSS) {",
    "EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,",
])
def test_a_table_of_both_uses_is_undetermined(line):
    assert _r(line) == "undetermined"


# 0.24: the two systematic misses of the 0.23 measurement (curl, Mbed TLS).
@pytest.mark.parametrize("line", [
    '{ 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",', '"RSA-PSK-AES128-CBC-SHA" },',
])
def test_rsa_psk_is_key_establishment(line):
    assert _r(line) == "key_establishment"


@pytest.mark.parametrize("line", [
    '"$P_CLI debug_level=4 groups=secp256r1,secp384r1" \\',
    "--priority=NORMAL:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1",
    '-s "selected_group: secp384r1" \\',
    "#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1     0x0017",
    'run_test "TLS 1.3: O->m: psk_ephemeral group(secp256r1) check, good"',
    '"$O_NEXT_CLI -msg -debug -groups P-256:P-384 -no_middlebox"',
    'SSL_CTX_set1_groups_list(cctx, "secp384r1:secp256r1")',
    "Groups = ?X448:?secp521r1",
])
def test_a_tls_group_is_key_establishment(line):
    assert _r(line, "EC") == "key_establishment"


@pytest.mark.parametrize("line", [
    "group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);",
    "mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);",
    "const EC_GROUP *group = EC_KEY_get0_group(ec_key);",
])
def test_the_curves_mathematical_group_says_nothing_about_the_role(line):
    assert _r(line, "EC") == "undetermined"


# 0.25: raw RSA signature operations in C, and the group spellings of s2n-tls and wolfSSL.
@pytest.mark.parametrize("line", [
    "ret = RSA_public_decrypt(siglen, sig, buf, rsa, pad);", "if (rsa_type == RSA_PRIVATE_ENCRYPT",
])
def test_raw_rsa_signature_operations_are_signature(line):
    assert _r(line) == "signature"


def test_raw_rsa_encryption_operations_stay_key_establishment():
    assert _r("RSA_private_decrypt(len, in, out, rsa, RSA_PKCS1_OAEP_PADDING)") == "key_establishment"
    assert _r("case RSA_PUBLIC_ENCRYPT:") == "key_establishment"
    assert _r("if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PUBLIC_DECRYPT)") == "undetermined"


@pytest.mark.parametrize("line", [
    "group: Some(Group::secp384r1),", '"group.supported.secp256r1": 2,',
    "s2n_kem_group_is_available(&s2n_secp384r1_mlkem_1024)", 'GroupInformation::new("secp256r1", 23),',
    'KXGroup::Secp256R1 => "P-256",', "ExpectIntEQ(ctx->group[0], WOLFSSL_ECC_SECP384R1);",
    "groups[count++] = WOLFSSL_ECC_SECP256R1;",
    "conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;",
])
def test_other_tls_group_spellings_are_key_establishment(line):
    assert _r(line, "EC") == "key_establishment"


@pytest.mark.parametrize("line", [
    "UniquePtr<EC_POINT> p1(EC_POINT_new(group()));",
    "ASSERT_TRUE(EC_POINT_mul(group(), point2.get(), forty_two.get(), nullptr,",
    "ASSERT_TRUE(EC_POINT_add(group(), p.get(), p.get(), pub2, nullptr));",
])
def test_a_cpp_group_accessor_is_not_a_tls_group(line):
    # BoringSSL, 0.25 measurement: seven lines like these were called key establishment.
    assert _r(line, "EC") == "undetermined"
