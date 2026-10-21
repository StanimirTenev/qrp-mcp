"""The TLS-termination caveat sits beside every TLS setting, not once per scan.

Row 25 of ZA-OPRAVYANE (21.10.2026). We said in public that the scanner "prints that
caveat next to every TLS setting it finds". On 0.30.0 it printed one statement per scan
(`tls_termination.statement`) and a list of places (`configured_in`); the evidence items
at those places carried nothing. Two nginx files gave one sentence for three settings.

Now every evidence item at a TLS place -- a pinned protocol version, a line that sets
key-exchange groups, and a classical group offered alone -- carries a short pointer to
the statement. The statement itself is still printed once. SSH configuration and
commented-out lines are not TLS places and carry nothing.
"""

import json
import subprocess
import sys

from qrp_mcp.assets import TLS_SETTING_NOTE
from qrp_mcp.closure import _identity
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

NGINX = ("server {\n    ssl_protocols TLSv1.2 TLSv1.3;\n"
         "    ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n")


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _items(result):
    return [(category, item) for category, items in result["evidence"].items()
            for item in items]


def _every_place_carries_it(result):
    places = {(p["path"], p["line"]) for p in result["tls_termination"]["configured_in"]}
    at_places = [item for _, item in _items(result) if (item["path"], item["line"]) in places]
    assert at_places
    assert all(item.get("tls_termination") == TLS_SETTING_NOTE for item in at_places), at_places
    # And nothing elsewhere.
    assert not [item for _, item in _items(result)
                if (item["path"], item["line"]) not in places and "tls_termination" in item]
    return at_places


def test_every_item_at_a_tls_place_carries_the_pointer(tmp_path):
    tree = _tree(tmp_path, {"a.conf": NGINX, "b.conf": NGINX})
    result = scan_directory(tree)
    at_places = _every_place_carries_it(result)
    assert len(result["tls_termination"]["configured_in"]) == 4
    # The classical group offered alone is a TLS setting too.
    groups = result["evidence"]["tls_groups"]
    assert groups and all(g["tls_termination"] == TLS_SETTING_NOTE for g in groups)
    # Both kinds of place: the pinned version and the group setting.
    categories = {c for c, item in _items(result) if item in at_places}
    assert {"protocols", "tls_groups"} <= categories
    # The statement is still printed once, and the pointer names it.
    assert "tls_termination.statement" in TLS_SETTING_NOTE
    assert "not negotiated" in TLS_SETTING_NOTE


def test_ssh_and_comments_carry_nothing(tmp_path):
    tree = _tree(tmp_path, {
        "sshd_config": "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n",
        "nginx.conf": "# ssl_ecdh_curve X25519:prime256v1;\n# ssl_protocols TLSv1.2;\n",
        "a.py": "from Crypto.PublicKey import RSA\nRSA.generate(2048)\n"})
    result = scan_directory(tree)
    assert result["tls_termination"] is None
    assert not [item for _, item in _items(result) if "tls_termination" in item]


def test_it_reaches_the_command_people_run(tmp_path):
    (tmp_path / "t").mkdir()
    tree = _tree(tmp_path / "t", {"nginx.conf": NGINX})
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    _every_place_carries_it(json.loads(out.read_text()))


def test_it_reaches_the_tool_at_every_level(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": NGINX})
    for level in ("masked", "trimmed", "full"):
        _every_place_carries_it(_tool(scan_repo)(str(tree), level=level))
    _every_place_carries_it(_tool(scan_repo)(str(tree)))


def test_the_cbom_names_it_on_every_tls_component(tmp_path):
    tree = _tree(tmp_path, {"nginx.conf": NGINX})
    cbom = _tool(export_cbom)(str(tree))
    tls = [c for c in cbom["components"]
           if c.get("cryptoProperties", {}).get("protocolProperties", {}).get("type") == "tls"
           or c.get("name", "").endswith("(TLS group offered alone)")]
    assert len(tls) >= 3  # TLSv1.2, TLSv1.3, X25519 offered alone
    for component in tls:
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        assert props.get("qrp:tls_termination") == TLS_SETTING_NOTE, component
    # The long statement still stays out.
    assert "outside the files read" not in json.dumps(cbom)


def test_the_pointer_is_not_identity_for_closure():
    """A result from before the pointer existed compares with one from after it."""
    item = {"path": "nginx.conf", "line": 2, "protocol": "tls", "version": "1.2",
            "excerpt": "ssl_protocols TLSv1.2 TLSv1.3;"}
    assert _identity("protocols", item) == _identity(
        "protocols", {**item, "tls_termination": TLS_SETTING_NOTE})
