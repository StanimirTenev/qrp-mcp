"""ZA-OPRAVYANE row 200 (LinkedIn, 04.11.2026; fixture from the room's probe `g-tls`).

(b) nginx names its certificate and key (`ssl_certificate`, `ssl_certificate_key`) at paths
outside the tree. Nothing read says what signs, yet `by_role.signature` said `none_found`:
the unread certificate read as an absent one. The places are now listed in
`tls_termination.authentication_not_read` and the signature part reads `not_established`.

(a) The headline is one word for both roles. Beside it, `summary.readiness_by_role` gives
the two parts' values side by side, and says when they differ."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "row-200"

SITE = ("server {\n"
        "    listen 443 ssl;\n"
        "    server_name bank.example;\n"
        "    ssl_protocols TLSv1.3;\n"
        "    ssl_ecdh_curve X25519MLKEM768:X25519;\n"
        "    ssl_certificate     /etc/nginx/certs/site.crt;\n"
        "    ssl_certificate_key /etc/nginx/certs/site.key;\n"
        "}\n")


def _tree(tmp_path: Path, with_certs: bool) -> Path:
    tree = tmp_path / "t"
    (tree / "nginx").mkdir(parents=True)
    (tree / "nginx" / "site.conf").write_text(SITE)
    if with_certs:
        shutil.copytree(FIXTURE / "certs", tree / "certs")
    return tree


def test_certificate_outside_the_tree_is_not_none_found(tmp_path):
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path, with_certs=False))
    signature = result["summary"]["by_role"]["signature"]
    assert signature["pqc_readiness"] == "not_established", signature
    assert any("nginx/site.conf:6" in b for b in signature["because"]), signature
    places = result["tls_termination"]["authentication_not_read"]["places"]
    assert [(p["path"], p["line"]) for p in places] == [("nginx/site.conf", 6),
                                                       ("nginx/site.conf", 7)]


def test_certificate_in_the_tree_keeps_its_reading(tmp_path):
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path, with_certs=True))
    assert result["summary"]["by_role"]["signature"]["pqc_readiness"] == "classical_only"
    # The certificate is in the tree and read; its key is not (the fixture carries none):
    # the key is listed, and a part that already reads classical is left as it is.
    places = result["tls_termination"]["authentication_not_read"]["places"]
    assert [(p["path"], p["line"]) for p in places] == [("nginx/site.conf", 7)]


def test_no_certificate_named_stays_none_found(tmp_path):
    from qrp_mcp.scan import scan_directory
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "site.conf").write_text(SITE.replace("    ssl_certificate     /etc/nginx/certs/site.crt;\n", "")
                                    .replace("    ssl_certificate_key /etc/nginx/certs/site.key;\n", ""))
    result = scan_directory(tree)
    assert result["summary"]["by_role"]["signature"]["pqc_readiness"] == "none_found"


def test_headline_carries_the_split(tmp_path):
    from qrp_mcp.scan import scan_directory
    summary = scan_directory(_tree(tmp_path, with_certs=True))["summary"]
    assert summary["pqc_readiness"] == "hybrid_partial"
    split = summary["readiness_by_role"]
    assert split["key_establishment"] == "hybrid_partial"
    assert split["signature"] == "classical_only"
    assert split["roles_differ"] is True


def test_through_the_cli_and_the_mcp_tool(tmp_path):
    from qrp_mcp.server import scan_repo
    tree = _tree(tmp_path, with_certs=False)
    out = tmp_path / "r.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree), "--out",
                        str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for summary in (json.loads(out.read_text())["summary"], scan_repo(str(tree))["summary"]):
        assert summary["by_role"]["signature"]["pqc_readiness"] == "not_established"
        assert summary["readiness_by_role"]["signature"] == "not_established"
