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
