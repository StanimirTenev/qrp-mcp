"""ZA-OPRAVYANE row 180 (31.10.2026): `KeyPairGenerator.getInstance("DH"); g.initialize(512);`
on one line gave a DH finding with no key size. The size rules already read `.initialize(N)`
for RSA, DSA and DH, but the JCA `getInstance` branch built its row without asking them."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name,size", [("DH", 512), ("DSA", 1024), ("RSA", 1024),
                                       ("DiffieHellman", 2048)])
def test_initialize_on_the_getinstance_line_sets_the_size(tmp_path, name, size):
    (tmp_path / "K.java").write_text(
        "class K { void f() throws Exception {\n"
        f"  java.security.KeyPairGenerator g = java.security.KeyPairGenerator"
        f".getInstance(\"{name}\"); g.initialize({size});\n"
        "}}\n")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["line"] == 2 and e.get("evidence_kind") != "comment"]
    assert rows and all(e.get("key_size") == size for e in rows), rows


def test_the_size_reaches_the_cbom(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "Dh512.java").write_text(
        "import java.security.KeyPairGenerator;\n"
        "class Dh512 { void f() throws Exception {\n"
        "  KeyPairGenerator g = KeyPairGenerator.getInstance(\"DH\"); g.initialize(512);\n"
        "}}\n")
    out = tmp_path / "c.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    names = {c["name"] for c in json.loads(out.read_text())["components"]}
    assert "DH-512" in names and "DH" not in names
