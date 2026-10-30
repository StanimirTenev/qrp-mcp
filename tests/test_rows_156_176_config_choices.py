"""ZA-OPRAVYANE rows 156 and 176 (Peter van Walsem).

156: `crypto.yaml` with `algorithm: RSA` and `key_size: 2048` on the next line gave RSA with no
size (`algorithm_key_sizes: {}`); Terraform's `tls_private_key` writes `rsa_bits` the same way.
The size beside the algorithm in the same block is now read.

156 + 176: a module taking its TLS cipher list from an environment variable was read and gave
nothing, and nothing said the choice had moved out of the files. A cryptographic setting whose
value is read from the environment or a CI variable is now listed in `chosen_outside_files`,
and counted in the CBOM; no algorithm is claimed for it.
"""

import json

from qrp_mcp import server
from qrp_mcp.scan import scan_directory


def _tree(tmp_path, files):
    t = tmp_path / "repo"
    t.mkdir()
    for name, text in files.items():
        (t / name).parent.mkdir(parents=True, exist_ok=True)
        (t / name).write_text(text)
    return t


def test_key_size_beside_the_algorithm(tmp_path):
    r = scan_directory(_tree(tmp_path, {
        "crypto.yaml": "signature:\n  algorithm: RSA\n  key_size: 2048\n  hash: SHA256\n",
        "main.tf": 'resource "tls_private_key" "k" {\n  algorithm = "RSA"\n  rsa_bits  = 4096\n}\n'}))
    assert r["algorithm_key_sizes_observed"]["RSA"] == [2048, 4096]
    rows = {e["path"]: e for e in r["evidence"]["iac"] if e["algorithm"] == "RSA"}
    assert rows["crypto.yaml"]["key_size"] == 2048 and rows["main.tf"]["key_size"] == 4096


def test_a_size_in_another_block_is_not_joined(tmp_path):
    r = scan_directory(_tree(tmp_path, {
        "crypto.yaml": "signature:\n  algorithm: RSA\ncache:\n  size: 1024\n"}))
    assert r["algorithm_key_sizes"] == {}


KEX = ('import os, ssl\ndef ctx():\n    c = ssl.create_default_context()\n'
       '    c.set_ciphers(os.environ.get("TLS_CIPHERS", "DEFAULT"))\n    return c\n')
WORKFLOW = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n"
            "      JWT_ALGORITHM: ${{ vars.JWT_ALGORITHM }}\n      PATH_EXTRA: ${{ vars.P }}\n")


def test_choice_from_the_environment_is_said(tmp_path):
    t = _tree(tmp_path, {"kex.py": KEX, ".github/workflows/ci.yml": WORKFLOW})
    r = scan_directory(t)
    block = r["chosen_outside_files"]
    places = {(p["path"], p["line"]) for p in block["places"]}
    assert places == {("kex.py", 4), (".github/workflows/ci.yml", 6)}
    assert block["count"] == 2 and "not in the files" in block["meaning"]
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    props = {p["name"]: p["value"] for p in json.loads(out.read_text())["properties"]}
    assert props["qrp:chosen_outside_files:count"] == "2"


def test_a_literal_choice_is_not_outside(tmp_path):
    r = scan_directory(_tree(tmp_path, {"kex.py": KEX.replace(
        'os.environ.get("TLS_CIPHERS", "DEFAULT")', '"ECDHE+AESGCM"'),
        "notes.py": "# set TLS_CIPHERS in os.environ before start\n"}))
    assert r["chosen_outside_files"]["count"] == 0


def test_the_quoted_line_follows_the_level(tmp_path):
    t = _tree(tmp_path, {"kex.py": KEX})
    for level, check in (("masked", lambda x: "TLS_CIPHERS" not in x),
                         ("trimmed", lambda x: x is None)):
        out = tmp_path / f"{level}.json"
        assert server.scan_to_file([str(t), "--out", str(out), "--level", level]) == 0
        place = json.loads(out.read_text())["chosen_outside_files"]["places"][0]
        assert check(place.get("excerpt")), (level, place)
    masked = server.scan_repo(str(t))["chosen_outside_files"]["places"][0]["excerpt"]
    assert "TLS_CIPHERS" not in masked
