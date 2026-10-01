"""A TLS line in a file is what was configured, not what a connection negotiated.

Raised in public on 2026-10-01 (G. Ivanov, NATO): a CDN in front of an origin can
negotiate X25519MLKEM768 while the origin's own configuration is classical, so a
domain shows post-quantum traffic nobody in the organisation migrated. The reverse
holds as well: a post-quantum group configured here says nothing about a classical
terminator in front of it. This scanner reads files, so on that case it reports the
origin as classical -- right about the file, silent about the wire. It must say so
wherever it read TLS configuration, and only there.
"""

import json
import subprocess
import sys

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_configured_group_carries_the_termination_statement(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519:prime256v1;\n"})
    block = scan_directory(tree)["tls_termination"]
    assert block["configured_in"] == [
        {"path": "nginx.conf", "line": 1, "basis": "configured_group"}]
    text = block["statement"]
    assert "not connections" in text
    assert "outside the files read" in text
    assert "either direction" in text


def test_pinned_protocol_version_carries_it_too(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3;\n"})
    block = scan_directory(tree)["tls_termination"]
    assert {"path": "nginx.conf", "line": 1, "basis": "configured_protocol"} in block["configured_in"]


def test_no_tls_configuration_no_statement(tmp_path):
    tree = _tree(tmp_path, {"a.py": "from Crypto.PublicKey import RSA\nRSA.generate(2048)\n"})
    assert scan_directory(tree)["tls_termination"] is None


def test_ssh_configuration_is_not_tls(tmp_path):
    tree = _tree(tmp_path, {"sshd_config": "KexAlgorithms curve25519-sha256\n"})
    assert scan_directory(tree)["tls_termination"] is None


def test_a_commented_out_group_configures_nothing(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": "# ssl_ecdh_curve X25519:prime256v1;\n"})
    assert scan_directory(tree)["tls_termination"] is None


def test_it_reaches_the_command_people_run(tmp_path):
    (tmp_path / "t").mkdir()
    tree = _tree(tmp_path / "t", {"nginx.conf": "ssl_ecdh_curve X25519:prime256v1;\n"})
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["tls_termination"]["configured_in"]


def test_it_reaches_the_tool_at_the_default_level(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519:prime256v1;\n"})
    assert _tool(scan_repo)(str(tree))["tls_termination"]["configured_in"]


def test_it_stays_out_of_the_cbom(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519:prime256v1;\n"})
    assert "outside the files read" not in json.dumps(_tool(export_cbom)(str(tree)))
