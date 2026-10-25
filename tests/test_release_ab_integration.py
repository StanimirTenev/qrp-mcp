"""Release B's detection rules under release A's outputs (the relA + relB-detect merge).

* The tree-wide `.properties` join reads only files the scan reads: one the owner's
  `.qrp.toml` excludes sets nothing.
* A joined getProperty finding is suppressed by `qrp:ignore` on its line and baselined
  like any other.
* `non_security_use` (row 147) is said in the CBOM occurrence and the SARIF properties;
  the age recipient's `hndl` reaches SARIF; a Go signature's `reference` kind reaches
  SARIF and is an occurrence closure follows when its line moves.
"""

import json

import pytest

from qrp_mcp import baseline, closure, cyclonedx, server
from qrp_mcp.scan import scan_directory

JAVA = ('class H {\n'
        '  void f(java.util.Properties props) {\n'
        '    String a = props.getProperty("hashAlg1", "SHA512");\n'
        '  }\n'
        '}\n')
PROPS = "hashAlg1=MD5\n"
AGE = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
GO = ("package main\n\nfunc other(k *ecdsa.PrivateKey) error {\n\treturn nil\n}\n")


def _md5_lines(result):
    return [(e["path"], e["line"]) for e in result["evidence"]["source_code"]
            if e["algorithm"] == "MD5"]


def test_properties_excluded_by_config_set_nothing(tmp_path):
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf" / "app.properties").write_text(PROPS)
    (tmp_path / "H.java").write_text(JAVA)
    assert ("H.java", 3) in _md5_lines(scan_directory(str(tmp_path)))
    (tmp_path / ".qrp.toml").write_text('exclude = ["conf/"]\n')
    result = scan_directory(str(tmp_path))
    assert _md5_lines(result) == []
    reasons = {e["reason"]: e for e in result["coverage"]["not_examined"]}
    assert reasons["excluded_by_config"]["paths"] == ["conf/app.properties"]


def test_joined_property_finding_is_suppressed_and_baselined(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.properties").write_text(PROPS)
    (tree / "H.java").write_text(JAVA.replace(
        '"SHA512");', '"SHA512");  // qrp:ignore MD5 test vectors only'))
    result = scan_directory(str(tree))
    held = [e for e in result["suppressed"]["evidence"]["source_code"]
            if e["algorithm"] == "MD5"]
    assert [(e["path"], e["line"]) for e in held] == [("H.java", 3)]

    (tree / "H.java").write_text(JAVA)
    file = tmp_path / "baseline.json"
    file.write_text(json.dumps(baseline.document(scan_directory(str(tree)))))
    again = scan_directory(str(tree), baseline=str(file))
    md5 = [e for e in again["evidence"]["source_code"] if e["algorithm"] == "MD5"]
    assert md5 and all(e["baseline_state"] == "baselined" for e in md5)


def test_non_security_use_is_said_in_the_cbom(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\n"
                                   "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()\n"
                                   "pw = hashlib.md5(password).hexdigest()\n")
    doc = cyclonedx.build(scan_directory(str(tmp_path)))
    md5 = next(c for c in doc["components"] if c["name"] == "MD5")
    contexts = {o["line"]: o["additionalContext"] for o in md5["evidence"]["occurrences"]}
    assert contexts[2].startswith("[non_security_use] ")
    assert not contexts[3].startswith("[")


@pytest.fixture
def sarif_results(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "a.py").write_text("import hashlib\n"
                               "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()\n")
    (tree / ".sops.yaml").write_text("creation_rules:\n  - age: " + AGE)
    (tree / "a.go").write_text(GO)
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--format", "sarif", "--out", str(out)]) == 0
    return json.loads(out.read_text())["runs"][0]["results"]


def test_relb_kinds_and_roles_reach_sarif(sarif_results):
    by = {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], r["ruleId"]):
          r["properties"] for r in sarif_results}
    assert by[("a.py", "qrp/MD5")]["role"] == "non_security_use"
    assert by[(".sops.yaml", "qrp/X25519")]["hndl"] is True
    assert by[("a.go", "qrp/ECDSA")]["evidence_kind"] == "reference"


def _pinned(result, commit):
    return {**result, "excerpt_level": "full",
            "coverage": {**result["coverage"],
                         "instrument": {"version": "x", "source_commit": {
                             "pinned": True, "commit": "tool", "dirty": False},
                             "ruleset": {}, "claimed_types": {}, "excluded_dirs": []},
                         "corpus": {"target": "/repo", "pinned_at": {
                             "pinned": True, "kind": "git", "commit": commit, "dirty": False}}}}


def test_go_reference_moving_down_is_still_open(tmp_path):
    (tmp_path / "a.go").write_text(GO)
    before = scan_directory(str(tmp_path))
    (tmp_path / "a.go").write_text(GO.replace("package main\n", "package main\n\n// x\n"))
    after = scan_directory(str(tmp_path))
    out = closure.prove_closure(_pinned(before, "a"), _pinned(after, "b"))
    assert out["comparability"]["verdict"] == "comparable"
    c = out["closure"]
    assert c["closed"] == [] and c["new"] == []
    assert c["still_open_moved_lines"] >= 1
