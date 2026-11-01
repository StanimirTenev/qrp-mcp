"""ZA-OPRAVYANE rows 179, 181 and 182 (31.10-01.11.2026).

179: `dh.generate_parameters(generator=2, key_size=512)` was read as DH-512 and reported
`weak_key: false`, severity high, while RSA-1024 in the same file was critical: the weak-key
check covered RSA only, and the classifier never parsed a size for any other family.

181: where no size is read for an asymmetric occurrence, say so -- `undetermined` -- instead
of leaving the field out, in the scan JSON and in the CBOM.

182: the classical status carries its source and version: NIST SP 800-131A Rev. 2 (March
2019), Tables 2, 4 and 5, and, for a size at or below one publicly broken, the record
(795 bits, ePrint 2020/697). A demonstrated break and a policy minimum are different
statuses.

The CBOM is checked through the command people run (`qrp-mcp cbom`) and through the MCP
tool, because a reader of only the CBOM gets nothing from a field that stops at the JSON.
"""

from __future__ import annotations

import json
import subprocess
import sys

from qrp_mcp.classifier import classify_algorithm, classical_status
from qrp_mcp.scan import scan_directory

DH512_PY = ("from cryptography.hazmat.primitives.asymmetric import dh, rsa\n"
            "params = dh.generate_parameters(generator=2, key_size=512)\n"
            "weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n")
DH512_JAVA = ("import java.security.KeyPairGenerator;\n"
              "class Dh512 { void f() throws Exception {\n"
              "  KeyPairGenerator g = KeyPairGenerator.getInstance(\"DH\"); g.initialize(512);\n"
              "}}\n")
UNSIZED_JAVA = ("import java.security.KeyPairGenerator;\n"
                "class K { void f() throws Exception {\n"
                "  KeyPairGenerator g = KeyPairGenerator.getInstance(\"DSA\");\n"
                "}}\n")


def _cli_cbom(tree, tmp_path):
    out = tmp_path / "cbom.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _props(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def _by_name(doc):
    return {c["name"]: c for c in doc["components"]}


# -- row 179 ---------------------------------------------------------------------------

def test_dh_512_is_a_weak_key_like_rsa_1024(tmp_path):
    (tmp_path / "dh512.py").write_text(DH512_PY)
    f = {x["algorithm_family"]: x for x in scan_directory(tmp_path)["findings"]}
    assert f["RSA"]["weak_key"] is True and f["RSA"]["severity"] == "critical"
    assert f["DH"]["weak_key"] is True, f["DH"]
    assert f["DH"]["severity"] == "critical"
    assert "SP 800-131A Rev. 2" in f["DH"]["reason"]


def _classify(value):
    return classify_algorithm(value, "signature", source="test", location="test")


def test_dsa_and_ec_below_the_minimum_and_strong_sizes_are_not_weak():
    assert _classify("DSA-1024").weak_key is True
    assert _classify("ECDSA-192").weak_key is True
    for strong in ("DH-2048", "DSA-3072", "ECDSA-256", "RSA-2048", "DH"):
        assert _classify(strong).weak_key is False, strong


# -- row 182: the status and its source ------------------------------------------------

def test_status_tells_a_public_break_from_a_policy_minimum():
    broken = classical_status("DH", 512)
    assert broken["status"] == "broken_in_public"
    assert "2020/697" in broken["source"] and "795" in broken["source"]
    below = classical_status("RSA", 1024)
    assert below["status"] == "disallowed"
    assert "NIST SP 800-131A Rev. 2" in below["source"] and "Table 2" in below["source"]
    assert classical_status("RSA", 3072)["status"] == "acceptable"
    # p alone is not the whole condition for DH and DSA: q and conformance are not read.
    met = classical_status("DH", 2048)
    assert met["status"] == "meets_minimum_length" and "len(q)" in met["source"]
    assert classical_status("ECDSA", 192)["status"] == "disallowed"
    assert classical_status("RSA", None)["status"] == "undetermined"
    assert classical_status("ML-KEM", 768) is None


def test_finding_carries_the_status(tmp_path):
    (tmp_path / "dh512.py").write_text(DH512_PY)
    f = {x["algorithm_family"]: x for x in scan_directory(tmp_path)["findings"]}
    assert f["DH"]["classical_status"]["status"] == "broken_in_public"
    assert f["RSA"]["classical_status"]["status"] == "disallowed"


# -- row 181: undetermined, said ----------------------------------------------------------

def test_unsized_occurrence_says_undetermined_in_the_scan_json(tmp_path):
    (tmp_path / "K.java").write_text(UNSIZED_JAVA)
    result = scan_directory(tmp_path)
    rows = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "DSA"]
    assert rows and all(e["key_size"] == "undetermined" for e in rows)
    f = {x["algorithm_family"]: x for x in result["findings"]}
    assert f["DSA"]["classical_status"]["status"] == "undetermined"


def test_cbom_states_size_and_status_on_every_classical_component(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "dh512.py").write_text(DH512_PY)
    (tree / "K.java").write_text(UNSIZED_JAVA)
    comps = _by_name(_cli_cbom(tree, tmp_path))
    dh = _props(comps["DH-512"])
    assert dh["qrp:key_size"] == "512"
    assert dh["qrp:classical_status"] == "broken_in_public"
    assert "2020/697" in dh["qrp:classical_status_source"]
    rsa = _props(comps["RSA-1024"])
    assert rsa["qrp:key_size"] == "1024" and rsa["qrp:classical_status"] == "disallowed"
    assert "NIST SP 800-131A Rev. 2" in rsa["qrp:classical_status_source"]
    dsa = _props(comps["DSA"])
    assert dsa["qrp:key_size"] == "undetermined"
    assert dsa["qrp:classical_status"] == "undetermined"


def test_cbom_through_the_mcp_tool_at_the_default_level(tmp_path):
    from qrp_mcp.server import export_cbom
    (tmp_path / "K.java").write_text(UNSIZED_JAVA)
    (tmp_path / "dh512.py").write_text(DH512_PY)
    comps = _by_name(export_cbom(str(tmp_path)))
    assert _props(comps["DSA"])["qrp:key_size"] == "undetermined"
    assert _props(comps["DH-512"])["qrp:classical_status"] == "broken_in_public"


def test_fixed_size_and_post_quantum_components_get_no_classical_size(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.py").write_text("from x import ml_kem, x25519\n"
                               "k = ml_kem.MLKEM768()\n"
                               "p = x25519.X25519PrivateKey.generate()\n")
    comps = _by_name(_cli_cbom(tree, tmp_path))
    for name, c in comps.items():
        if name.startswith(("ML-KEM", "X25519")):
            assert "qrp:classical_status" not in _props(c), name
            assert _props(c).get("qrp:key_size") != "undetermined", name
