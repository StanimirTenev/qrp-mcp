"""Row 490 (15.11.2026, Bogomil Atanasov; probe `linkedin-postove/2026-11-15/dos-proba/`).

Two nginx `server` blocks -- 443 with X25519MLKEM768 and an ML-DSA-65 certificate, 8443 with X25519
and an ECDSA P-256 one -- gave their algorithms for the whole tree, so nothing said which port pays
an ML-KEM encapsulation and an ML-DSA signature on every handshake. `tls_listeners` now lists each
nginx server block that listens with `ssl` (or `quic`): its ports, its server names, the groups and
the certificates set in it, with the family of each, in the scan JSON, the MCP tools and the CBOM
(`qrp:tls_listeners`). Server names are masked below `--level full`, as owners are.

Not claimed: what a connection negotiates (tls_termination.statement); `include` is not followed;
a setting outside the block is reported as set outside it, not resolved through nginx's
inheritance.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo
from test_row_491_algorithm_named_in_a_path import PQ_CONF


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args: list[str]) -> None:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True, env=dict(os.environ))


def _scans(root: Path, tmp_path: Path, level: str = "full") -> list[dict]:
    out = tmp_path / f"s-{level}.json"
    _cli(["scan", str(root), "--out", str(out), "--level", level])
    found = [json.loads(out.read_text()), scan_repo(str(root), level=level)]
    return found + ([scan_directory(root)] if level == "full" else [])


def _cboms(root: Path, tmp_path: Path, level: str = "full") -> list[dict]:
    out = tmp_path / f"c-{level}.json"
    _cli(["cbom", str(root), "--out", str(out), "--level", level])
    found = [json.loads(out.read_text()), export_cbom(str(root), level=level)]
    return found + ([build(scan_directory(root))] if level == "full" else [])


def _short(listener: dict) -> tuple:
    return (listener["line"], [p["port"] for p in listener["listen"]],
            [g["name"] for g in listener["groups"]["groups"]],
            [(a["family"], a.get("parameter_set") or a.get("key_size"), a["named_in_a_path"])
             for c in listener["certificates"] if c["setting"] == "ssl_certificate"
             for a in c["algorithms"]])


def test_each_server_block_carries_its_own_groups_and_certificate(tmp_path):
    root = _tree(tmp_path / "r", {"conf.d/pq.conf": PQ_CONF})
    for result in _scans(root, tmp_path):
        block = result["tls_listeners"]
        assert block["count"] == 2
        pq, classic = block["places"]
        assert _short(pq) == (2, ["443"], ["X25519MLKEM768"], [("ML-DSA", "65", True)])
        assert _short(classic) == (11, ["8443"], ["X25519"], [("ECDSA", 256, True)])
        assert pq["server_name"] == ["pq.example.test"]
        assert pq["groups"]["groups"][0] == {"name": "X25519MLKEM768",
                                             "families": ["X25519", "ML-KEM-768"],
                                             "post_quantum": True}
        assert classic["groups"]["groups"][0]["post_quantum"] is False
        assert pq["groups"]["line"] == 6 and pq["groups"]["set"] == "in this block"
        assert [c["line"] for c in pq["certificates"]] == [7, 8]
        assert all(c["file_read"] == [] for c in pq["certificates"])


def test_the_cbom_carries_the_listeners(tmp_path):
    root = _tree(tmp_path / "r", {"conf.d/pq.conf": PQ_CONF})
    for doc in _cboms(root, tmp_path):
        props = {p["name"]: p["value"] for p in doc["properties"]}
        listeners = json.loads(props["qrp:tls_listeners"])
        assert [(x["location"], x["line"], x["ports"], x["groups"], x["certificates"])
                for x in listeners] == [
            ("conf.d/pq.conf", 2, ["443"], ["X25519MLKEM768 (X25519 + ML-KEM-768)"],
             ["ML-DSA-65 (named in a path)"]),
            ("conf.d/pq.conf", 11, ["8443"], ["X25519 (X25519)"],
             ["ECDSA 256 (named in a path)"])]


def test_server_names_are_masked_below_full(tmp_path):
    root = _tree(tmp_path / "r", {"conf.d/pq.conf": PQ_CONF})
    for level in ("masked", "trimmed"):
        for result in _scans(root, tmp_path, level):
            names = [n for x in result["tls_listeners"]["places"] for n in x["server_name"]]
            assert names and not any("example" in n for n in names), names
        for doc in _cboms(root, tmp_path, level):
            text = json.dumps(doc)
            assert "pq.example.test" not in text and "classic.example.test" not in text


def test_a_parsed_certificate_and_a_setting_outside_the_block(tmp_path):
    files = {"nginx.conf": ("ssl_ecdh_curve X25519MLKEM768:X25519;\n"
                            "server {\n    listen 443 ssl;\n"
                            "    ssl_certificate certs/srv.crt;\n}\n"
                            "server {\n    listen 80;\n}\n")}
    root = _tree(tmp_path / "p", files)
    (root / "certs").mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(root / "k.pem"),
                    "-out", str(root / "certs" / "srv.crt"), "-days", "1", "-subj", "/CN=x"],
                   check=True, capture_output=True)
    (root / "k.pem").unlink()
    result = scan_directory(root)
    (listener,) = result["tls_listeners"]["places"]       # port 80 is not a TLS listener
    assert listener["groups"]["line"] == 1
    assert listener["groups"]["set"].startswith("in this file, outside the server block")
    (cert,) = listener["certificates"]
    assert cert["file_read"] == ["certs/srv.crt"]
    assert {(a["family"], a["named_in_a_path"]) for a in cert["algorithms"]} == {
        ("EC", False), ("ECDSA", False)}


def test_no_group_set_is_said(tmp_path):
    root = _tree(tmp_path / "n", {"nginx.conf": "server {\n    listen 443 ssl;\n}\n"})
    (listener,) = scan_directory(root)["tls_listeners"]["places"]
    assert listener["groups"]["line"] is None and listener["groups"]["groups"] == []
    assert listener["groups"]["set"].startswith("not in this file")
    assert listener["certificates"] == []


def test_a_tree_without_an_nginx_tls_listener_has_none(tmp_path):
    root = _tree(tmp_path / "e", {"nginx.conf": "server {\n    listen 80;\n}\n",
                                  "a.py": "listen = 'ssl'\n"})
    assert scan_directory(root)["tls_listeners"] is None
