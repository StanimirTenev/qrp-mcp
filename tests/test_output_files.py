"""The two documents that used to exist only as tool replies, written to files by the
command people run: the CBOM, and the verdict of a closure. Tested through a subprocess,
because a check that main() never reaches passes every unit test."""

import hashlib
import json
import subprocess
import sys


def _run(*args):
    return subprocess.run([sys.executable, "-m", "qrp_mcp.server", *args],
                          capture_output=True, text=True)


def _tree(tmp_path):
    src = tmp_path / "tree"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (src / "b.py").write_text("from Crypto.PublicKey import RSA\nRSA.generate(2048)\n")
    return src


def test_cbom_command_writes_a_cyclonedx_document(tmp_path):
    src = _tree(tmp_path)
    out = tmp_path / "cbom.json"
    r = _run("cbom", str(src), "--out", str(out))
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["components"]
    # The digest printed is of the exact bytes written.
    assert f"sha256 {hashlib.sha256(out.read_bytes()).hexdigest()}" in r.stderr
    # Masked by default: the document built to be sent.
    assert "(masked)" in r.stderr


def test_cbom_command_to_standard_output_and_other_level(tmp_path):
    src = _tree(tmp_path)
    r = _run("cbom", str(src), "--level", "full")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["bomFormat"] == "CycloneDX"


def test_cbom_written_inside_the_tree_is_left_out_of_it(tmp_path):
    src = _tree(tmp_path)
    out = src / "cbom.json"
    for _ in range(2):
        assert _run("cbom", str(src), "--out", str(out)).returncode == 0
    doc = json.loads(out.read_text())
    assert "cbom.json" not in json.dumps(doc.get("components", []))


def test_scan_lists_the_files_it_read(tmp_path):
    src = _tree(tmp_path)
    out = tmp_path / "s.json"
    assert _run("scan", str(src), "--out", str(out)).returncode == 0
    assert json.loads(out.read_text())["files_read"] == ["a.py", "b.py"]


def test_the_list_of_read_files_stays_out_of_the_cbom(tmp_path):
    src = _tree(tmp_path)
    r = _run("cbom", str(src))
    names = []

    def walk(node):
        if isinstance(node, dict):
            names.extend(str(k) for k in node)
            if "name" in node:
                names.append(str(node["name"]))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(json.loads(r.stdout))
    assert names and not [n for n in names if "files_read" in n]


def test_closure_command_writes_the_verdict_naming_its_inputs(tmp_path):
    src = _tree(tmp_path)
    before, after, verdict = tmp_path / "1.json", tmp_path / "2.json", tmp_path / "v.json"
    assert _run("scan", str(src), "--out", str(before)).returncode == 0
    (src / "b.py").unlink()
    assert _run("scan", str(src), "--out", str(after)).returncode == 0
    r = _run("closure", str(before), str(after), "--out", str(verdict))
    assert r.returncode == 0, r.stderr
    v = json.loads(verdict.read_text())
    assert v["inputs"]["before"]["sha256"] == hashlib.sha256(before.read_bytes()).hexdigest()
    assert v["inputs"]["after"]["sha256"] == hashlib.sha256(after.read_bytes()).hexdigest()
    assert "comparability" in v and "statement" in v


def test_closure_command_to_standard_output_and_missing_input(tmp_path):
    src = _tree(tmp_path)
    s = tmp_path / "s.json"
    assert _run("scan", str(src), "--out", str(s)).returncode == 0
    r = _run("closure", str(s), str(s))
    assert r.returncode == 0 and json.loads(r.stdout)["inputs"]["before"]["path"] == str(s)
    r = _run("closure", str(s), str(tmp_path / "nope.json"))
    assert r.returncode == 2 and "no scan result" in r.stderr
