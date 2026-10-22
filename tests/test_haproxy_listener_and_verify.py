"""An HAProxy listener that terminates TLS, and a backend whose certificate is not
verified (ZA-OPRAVYANE rows 42 and 44, the network-vs-code probe of 22.10.2026).

The probe's edge: `bind :8443 ssl crt edge.pem` with no ssl-min-ver and no cipher list
anywhere in the file. The scan placed TLS only on the curves line, and said nothing
about the listener, while the wire showed TLS 1.2 with 13 suites. Behind it,
`server app1 app:443 ssl verify none`: the hop is encrypted and not authenticated, the
one thing an outside scan cannot see, and the code scan did not say it either.
"""

import json
import subprocess
import sys

from qrp_mcp.assets import TLS_SETTING_NOTE
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

EDGE = ("global\n"
        "    ssl-default-bind-curves X25519MLKEM768:X25519\n"
        "    ssl-default-bind-options no-tls-tickets\n"
        "frontend fe\n"
        "    bind :8443 ssl crt /etc/haproxy/edge.pem\n"
        "backend be\n"
        "    server app1 app:443 ssl verify none sni str(app.local)\n")


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _by_basis(result, basis):
    return [p for p in result["evidence"]["protocols"] if p["basis"] == basis]


def test_a_bind_ssl_line_is_a_tls_place_with_its_defaults_named(tmp_path):
    result = scan_directory(_tree(tmp_path, {"haproxy.cfg": EDGE}))
    [listener] = _by_basis(result, "configured_listener")
    assert listener["line"] == 5
    assert listener["library_defaults"] == ["protocol versions", "TLS 1.2 cipher list",
                                            "TLS 1.3 cipher suites"]
    assert "defaults apply" in listener["description"]
    assert "TLSv1.2 as the ssl-min-ver default" in listener["description"]
    assert listener["tls_termination"] == TLS_SETTING_NOTE
    assert {"path": "haproxy.cfg", "line": 5, "basis": "configured_listener"} in \
        result["tls_termination"]["configured_in"]


def test_settings_given_on_the_line_or_in_the_globals_are_not_called_defaults(tmp_path):
    cfg = ("global\n    ssl-default-bind-options ssl-min-ver TLSv1.2\n"
           "    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384\n"
           "frontend f\n    bind :443 ssl crt a.pem ciphers ECDHE-RSA-AES128-GCM-SHA256 "
           "curves X25519\n")
    [listener] = _by_basis(scan_directory(_tree(tmp_path, {"haproxy.cfg": cfg})),
                           "configured_listener")
    assert listener["library_defaults"] == []
    assert "defaults apply" not in listener["description"]


def test_a_plain_bind_and_a_comment_are_not_listeners(tmp_path):
    cfg = "frontend f\n    bind :80\n#   bind :443 ssl crt a.pem\n"
    assert _by_basis(scan_directory(_tree(tmp_path, {"haproxy.cfg": cfg})),
                     "configured_listener") == []


def test_verification_off_is_a_finding_and_not_a_termination_place(tmp_path):
    files = {"haproxy.cfg": EDGE,
             "g.cfg": "global\n    ssl-server-verify none\n",
             "nginx.conf": "location / {\n    proxy_pass https://b;\n    proxy_ssl_verify off;\n}\n",
             # verify on a bind line is the client-certificate check; `required` is on.
             "h.cfg": ("frontend f\n    bind :443 ssl crt a.pem verify none\n"
                       "backend b\n    server s 1.2.3.4:443 ssl verify required\n"),
             "on.conf": "proxy_ssl_verify on;\n# proxy_ssl_verify off;\n"}
    result = scan_directory(_tree(tmp_path, files))
    found = {(p["path"], p["line"], p["verification_setting"])
             for p in _by_basis(result, "configured_verification")}
    assert found == {("haproxy.cfg", 7, "verify none"), ("g.cfg", 2, "ssl-server-verify none"),
                     ("nginx.conf", 3, "proxy_ssl_verify off")}
    for item in _by_basis(result, "configured_verification"):
        assert item["peer_verification"] == "off"
        assert "not authenticated" in item["description"]
        assert "app1" not in item["description"]  # the line is the excerpt's, not ours
    places = {(p["path"], p["line"]) for p in result["tls_termination"]["configured_in"]}
    assert ("haproxy.cfg", 7) not in places and ("nginx.conf", 3) not in places


def test_both_reach_the_command_the_tool_and_the_cbom(tmp_path):
    (tmp_path / "t").mkdir()
    tree = _tree(tmp_path / "t", {"haproxy.cfg": EDGE})
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    on_disk = json.loads(out.read_text())
    assert len(_by_basis(on_disk, "configured_listener")) == 1
    assert len(_by_basis(on_disk, "configured_verification")) == 1
    for level in ("masked", "trimmed", "full"):
        result = _tool(scan_repo)(str(tree), level=level)
        assert len(_by_basis(result, "configured_listener")) == 1
        assert len(_by_basis(result, "configured_verification")) == 1
    names = [c["name"] for c in _tool(export_cbom)(str(tree))["components"]]
    assert "TLS listener (HAProxy bind)" in names
    assert "TLS peer verification off (verify none)" in names
