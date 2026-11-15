"""Row 491 (15.11.2026; probe `linkedin-postove/2026-11-15/dos-proba/`).

`ssl_certificate /etc/nginx/certs/mldsa65_srv.crt;` gave an ML-DSA row at `medium`, the level of a
directive that names the algorithm, although the only thing that names ML-DSA is the file's name
(the certificate is not in the tree). A family read from the path of a certificate or key file a
TLS setting loads now carries `named_in_a_path: true` and is one step lower, with the reason in
`confidence_basis`. The parameter set the name carries (`65`) was already on the row and stays.

Not changed: the finding, its family and the CBOM component (ML-DSA-65, ECDSA-P-256 still there).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

# The probe's file (dos-proba/r/conf.d/pq.conf), as written there.
PQ_CONF = """limit_conn_zone $binary_remote_addr zone=perip:10m;
server {
    listen 443 ssl;
    server_name pq.example.test;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768;
    ssl_certificate     /etc/nginx/certs/mldsa65_srv.crt;
    ssl_certificate_key /etc/nginx/certs/mldsa65_srv.key;
    limit_conn perip 20;
}
server {
    listen 8443 ssl;
    server_name classic.example.test;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519;
    ssl_certificate     /etc/nginx/certs/ecdsa_p256.crt;
    ssl_certificate_key /etc/nginx/certs/ecdsa_p256.key;
}
"""
BASIS = "family read from the name of a file the line loads, not from the file"


def _tree(root: Path) -> Path:
    (root / "conf.d").mkdir(parents=True)
    (root / "conf.d" / "pq.conf").write_text(PQ_CONF)
    return root


def _cli(args: list[str]) -> None:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True, env=dict(os.environ))


def _scans(root: Path, tmp_path: Path) -> list[dict]:
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out)])
    return [json.loads(out.read_text()), scan_repo(str(root)), scan_directory(root)]


def _rows(result: dict) -> dict[int, list[dict]]:
    rows: dict[int, list[dict]] = {}
    for e in result["evidence"]["source_code"]:
        rows.setdefault(e["line"], []).append(e)
    return rows


def test_a_family_named_only_by_a_certificate_path_is_marked_and_lower(tmp_path):
    for result in _scans(_tree(tmp_path / "r"), tmp_path):
        rows = _rows(result)
        for line, family in ((7, "ML-DSA"), (8, "ML-DSA"), (16, "ECDSA"), (17, "ECDSA")):
            (row,) = [r for r in rows[line] if r["algorithm"] == family]
            assert row.get("named_in_a_path") is True, row
            assert row["confidence"] == "low", row
            assert row["confidence_basis"].endswith(BASIS), row
        # The parameter set and the curve's size come from the name, as before.
        assert {r.get("parameter_set") for r in rows[7]} == {"65"}
        assert {r.get("key_size") for r in rows[16]} == {256}
        # The group setting names its algorithm itself: unchanged.
        assert all("named_in_a_path" not in r and r["confidence"] == "medium" for r in rows[6])


def test_the_findings_and_the_cbom_components_stay(tmp_path):
    root = _tree(tmp_path / "r")
    result = scan_directory(root)
    assert {f["algorithm_family"] for f in result["findings"]} == {
        "ECDH", "ECDSA", "ML-DSA", "ML-KEM", "X25519"}
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    for doc in (json.loads(out.read_text()), export_cbom(str(root)), build(result)):
        refs = {c["bom-ref"] for c in doc["components"]}
        assert {"crypto:ml-dsa-65", "crypto:ecdsa-p-256"} <= refs
        (mldsa,) = [c for c in doc["components"] if c["bom-ref"] == "crypto:ml-dsa-65"]
        props = {p["name"]: p["value"] for p in mldsa["properties"]}
        assert json.loads(props["qrp:confidence"]) == ["low", "low"]


def test_a_haproxy_bind_line_keeps_a_family_its_settings_name(tmp_path):
    # `crt` names the file; `ciphers` on the same line names its families itself.
    root = tmp_path / "h"
    root.mkdir()
    (root / "haproxy.cfg").write_text(
        "frontend f\n    bind :443 ssl crt /etc/ssl/ecdsa.pem ciphers ECDHE-RSA-AES128-GCM-SHA256\n")
    rows = _rows(scan_directory(root))[2]
    (ecdsa,) = [r for r in rows if r["algorithm"] == "ECDSA"]
    assert ecdsa.get("named_in_a_path") is True and ecdsa["confidence"] == "medium"
    others = [r for r in rows if r["algorithm"] != "ECDSA"]
    assert {r["algorithm"] for r in others} == {"ECDH", "RSA"}
    assert all("named_in_a_path" not in r and r["confidence"] == "high" for r in others)
