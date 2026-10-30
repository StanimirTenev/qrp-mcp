"""ZA-OPRAVYANE row 178 (Mark McGovern): the integrity of the file and the repeatability of the
result are two claims. Two scans of one tree printed different SHA-256s because the file holds
its read times. The file's digest stays; beside it, a fingerprint of the normalised findings,
with its rules in the output, is the same on every run and at every --level, and moves when a
finding does. It reaches all three outputs: `scan --out` (JSON and SARIF), the MCP tool, the CBOM.
"""

import json

from qrp_mcp import server

APP = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


def _tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "a.py").write_text(APP)
    return t


def _scan(tree, out, *args):
    assert server.scan_to_file([str(tree), "--out", str(out), *args]) == 0
    return json.loads(out.read_text())


def test_two_runs_same_fingerprint_different_file(tmp_path, capsys, monkeypatch):
    t = _tree(tmp_path)
    a = _scan(t, tmp_path / "a.json")
    first = capsys.readouterr().err
    # A different read window, as a later run has.
    from qrp_mcp import scan
    monkeypatch.setattr(scan, "_now", lambda: "2030-01-01T00:00:00+00:00")
    b = _scan(t, tmp_path / "b.json")
    second = capsys.readouterr().err
    assert a["findings_fingerprint"]["sha256"] == b["findings_fingerprint"]["sha256"]
    assert (tmp_path / "a.json").read_bytes() != (tmp_path / "b.json").read_bytes()
    fp = a["findings_fingerprint"]["sha256"]
    assert f"findings sha256 {fp}" in first and f"findings sha256 {fp}" in second
    assert a["findings_fingerprint"]["rules"] and a["findings_fingerprint"]["format"]


def test_same_at_every_level(tmp_path):
    t = _tree(tmp_path)
    prints = {_scan(t, tmp_path / f"{lv}.json", "--level", lv)["findings_fingerprint"]["sha256"]
              for lv in ("full", "masked", "trimmed")}
    assert len(prints) == 1


def test_moves_when_a_finding_does(tmp_path):
    t = _tree(tmp_path)
    before = _scan(t, tmp_path / "1.json")["findings_fingerprint"]["sha256"]
    (t / "b.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    after = _scan(t, tmp_path / "2.json")["findings_fingerprint"]["sha256"]
    assert before != after


def test_reaches_sarif_mcp_and_cbom(tmp_path):
    t = _tree(tmp_path)
    fp = _scan(t, tmp_path / "s.json")["findings_fingerprint"]["sha256"]
    sarif = _scan(t, tmp_path / "s.sarif", "--format", "sarif")
    assert sarif["runs"][0]["properties"]["findings_fingerprint"]["sha256"] == fp
    tool = server.scan_repo(str(t))
    assert tool["findings_fingerprint"]["sha256"] == fp
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    props = {p["name"]: p["value"] for p in json.loads(out.read_text())["properties"]}
    assert props["qrp:findings_fingerprint:sha256"] == fp
