"""ZA-OPRAVYANE row 165 (Daniel Stokes): the version a manifest pins was lost. Two trees that
differ only in `cryptography==42.0.5` vs `45.0.4` -- a classical default against a hybrid one --
scanned the same, and the CBOM's library component had no version. Now the dependency row has
`version` where the manifest pins one, and the CBOM library component
carries it, or every pinned version where manifests disagree. A range is not a version.
"""

import json

from qrp_mcp import server
from qrp_mcp.scan import scan_directory


def _dep(result, package):
    return [d for d in result["evidence"]["dependencies"] if d["package"] == package]


def _cbom(tree, tmp_path):
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(tree), "--out", str(out)], cbom=True) == 0
    return {c["name"]: c for c in json.loads(out.read_text())["components"]
            if c["type"] == "library"}


def test_requirements_pin_reaches_the_row_and_the_cbom(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "requirements.txt").write_text("cryptography==45.0.4\nparamiko>=3.0\n")
    r = scan_directory(t)
    assert _dep(r, "cryptography")[0]["version"] == "45.0.4"
    para = _dep(r, "paramiko")[0]
    assert "version" not in para
    libs = _cbom(t, tmp_path)
    assert libs["cryptography"]["version"] == "45.0.4"
    assert "version" not in libs["paramiko"]


def test_pyproject_exact_request_is_a_version(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "pyproject.toml").write_text('[project]\nname = "x"\n'
                                      'dependencies = ["cryptography==42.0.5"]\n')
    assert _dep(scan_directory(t), "cryptography")[0]["version"] == "42.0.5"


def test_disagreeing_pins_are_all_named(tmp_path):
    t = tmp_path / "repo"
    (t / "a").mkdir(parents=True)
    (t / "b").mkdir()
    (t / "a" / "requirements.txt").write_text("cryptography==42.0.5\n")
    (t / "b" / "requirements.txt").write_text("cryptography==45.0.4\n")
    lib = _cbom(t, tmp_path)["cryptography"]
    assert "version" not in lib
    props = {p["name"]: p["value"] for p in lib["properties"]}
    assert props["qrp:versions_pinned"] == "42.0.5, 45.0.4"
