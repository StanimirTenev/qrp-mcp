"""ZA-OPRAVYANE row 480: checking an old signature read the same as making a new one.

Probe `linkedin-postove/2026-11-15/verify-proba/` (0.45.0): `public_key.verify(...PSS...)` in
`archive_verify.py` and `key.sign(...)` in `issue_record.py` gave the same row -- RSA,
signature, deprecated after 2030, "due" -- with nothing to tell them apart.

The call a line makes on the key (`.sign(`, `.verify(`, `.encrypt(`, `.decrypt(`) is now
`operation` on the RSA or EC occurrence, in the scan JSON, the MCP tools, SARIF and the CBOM
(`qrp:operation`). Under `--mandate nist-ir-8547` a verify-only or decrypt-only line says that
IR 8547 calls such processing of already protected information "legacy use" (section 4.1),
and is counted apart in the block. Not claimed: that the signature it checks is old; nor any
exemption -- Tables 2 and 4 give these schemes no legacy-use status, so the dates and the
gate stand.
"""

import json
from datetime import date

import pytest

from qrp_mcp import cyclonedx, mandates, remediation, server
from qrp_mcp.scan import scan_directory

FILES = {
    "archive_verify.py": (
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
        "from cryptography.hazmat.primitives import hashes, serialization\n"
        "def check(record, signature, pem):\n"
        "    public_key = serialization.load_pem_public_key(pem)\n"
        "    public_key.verify(signature, record, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),"
        " salt_length=32), hashes.SHA256())\n"),
    "issue_record.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "def issue(record):\n"
        "    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        "    return key.sign(record, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), "
        "salt_length=32), hashes.SHA256())\n"),
    "unwrap.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
        "plain = rsa_private.decrypt(ct, padding.OAEP(mgf=padding.MGF1(h), algorithm=h, "
        "label=None))\n"),
}
AS_OF = "2026-11-15"


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    for name, text in FILES.items():
        (t / name).write_text(text)
    return t


def _rsa(evidence, path, line):
    return [e for e in evidence["source_code"]
            if e["path"] == path and e["line"] == line and e["algorithm"] == "RSA"]


@pytest.mark.parametrize("excerpt, said", [
    ("public_key.verify(sig, data, padding.PSS(m, s), h)", "verify"),
    ("return key.sign(data, padding.PSS(m, s), h)", "sign"),
    ("ct = pub.encrypt(k, padding.OAEP(m, a, None))", "encrypt"),
    ("pt = priv.decrypt(ct, padding.OAEP(m, a, None))", "decrypt"),
    ("err := rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, nil)", "verify"),
    ("sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, digest)", "sign"),
    ("s.initVerify(publicKey); // RSA", "verify"),
    # Not a call on a key: no operation.
    ("requests.get(url, verify=False)  # RSA client cert", None),
    ("ssl_verify_client on; ssl_certificate rsa.crt;", None),
    ("ctx.verify_mode = ssl.CERT_REQUIRED  # RSA", None),
    ("from cryptography.hazmat.primitives.asymmetric import rsa, padding", None),
    ("key = rsa.generate_private_key(public_exponent=65537, key_size=3072)", None),
    # Both on one line: neither is said.
    ("assert pub.verify(key.sign(m, p, h), m, p, h) is None", None),
])
def test_operation_from_the_call(excerpt, said):
    assert remediation.operation_of({"algorithm": "RSA", "excerpt": excerpt}) == said


def test_verify_and_sign_differ_in_the_scan_json_and_the_mandate(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--mandate", "nist-ir-8547", "--as-of", AS_OF,
                                "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    ev = r["evidence"]
    verify = _rsa(ev, "archive_verify.py", 5)
    sign = _rsa(ev, "issue_record.py", 5)
    gen = _rsa(ev, "issue_record.py", 4)
    decrypt = _rsa(ev, "unwrap.py", 2)
    assert verify and sign and gen and decrypt
    assert {e.get("operation") for e in verify} == {"verify"}
    assert {e.get("operation") for e in sign} == {"sign"}
    assert all("operation" not in e for e in gen)
    v = verify[0]["mandates"]["nist-ir-8547"]
    s = sign[0]["mandates"]["nist-ir-8547"]
    assert v["operation"] == "verify" and "legacy use" in v["legacy_use"]
    assert "not established" in v["legacy_use"]
    assert "legacy_use" not in s
    # No exemption: the dates are the same for both.
    for key in ("deprecated_after", "disallowed_after", "deadline", "status"):
        assert v[key] == s[key], key
    d = decrypt[0]
    assert d["operation"] == "decrypt" and d["hndl_exposed"] is True
    assert "legacy use" in d["mandates"]["nist-ir-8547"]["legacy_use"]
    block = r["mandates"]["nist-ir-8547"]
    assert block["verify_or_decrypt_only"] == 2


def test_verify_only_still_trips_the_gate(tree):
    t = tree
    for name in ("issue_record.py", "unwrap.py"):
        (t / name).unlink()
    r = scan_directory(t)
    assert mandates.apply(r, ["nist-ir-8547"], date.fromisoformat(AS_OF), lead_months=50)


def test_operation_reaches_the_mcp_tool_sarif_and_the_cbom(tree, tmp_path):
    r = server.scan_repo(str(tree))
    assert {e.get("operation") for e in _rsa(r["evidence"], "archive_verify.py", 5)} == {
        "verify"}
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--format", "sarif", "--out", str(out)]) == 0
    sarif = json.loads(out.read_text())
    ops = {res["properties"].get("operation") for run in sarif["runs"]
           for res in run["results"]
           if res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(
               "archive_verify.py")}
    assert "verify" in ops
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        got = {}
        for c in doc["components"]:
            props = {p["name"]: p["value"] for p in c.get("properties", [])}
            if "qrp:operation" in props:
                said = json.loads(props["qrp:operation"])
                assert len(said) == len(c["evidence"]["occurrences"])
                for o, op in zip(c["evidence"]["occurrences"], said):
                    got[(c["name"], o["location"], o.get("line"))] = op
        assert got[("RSA", "archive_verify.py", 5)] == "verify"
        assert got[("RSA", "issue_record.py", 5)] == "sign"
        assert got[("RSA", "unwrap.py", 2)] == "decrypt"
        # The key generated on its own line is its own component (RSA-3072); no call read.
        assert got[("RSA-3072", "issue_record.py", 4)] == "not read"
