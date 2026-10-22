"""HAProxy, a load balancer, is TLS configuration (ZA-OPRAVYANE row 30, 22.10.2026).

Kiran Murthy asked to validate the runtime negotiation points such as load balancers.
On 0.31.0 an haproxy.cfg with `ssl-default-bind-curves X25519MLKEM768:X25519` and
`ssl-default-bind-options ssl-min-ver TLSv1.2` gave the algorithms and nothing else:
`tls_termination: null`, no protocol pin, no classical group offered alone. The same
settings in nginx got all three. The directive names are HAProxy's own (Configuration
Manual, version 3.5, `doc/configuration.txt`, read 22.10.2026): the global
`ssl-default-bind-curves`, `ssl-default-server-curves`, `ssl-default-bind-options`,
`ssl-default-server-options`, and the `curves`, `ssl-min-ver`, `ssl-max-ver` keywords of
a `bind` or `server` line.
"""

import subprocess
import sys

from qrp_mcp.assets import TLS_SETTING_NOTE
from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

HAPROXY = ("global\n"
           "  ssl-default-bind-curves X25519MLKEM768:X25519\n"
           "  ssl-default-bind-options ssl-min-ver TLSv1.2\n")


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_the_global_settings_are_tls_configuration(tmp_path):
    result = scan_directory(_tree(tmp_path, {"haproxy.cfg": HAPROXY}))
    places = result["tls_termination"]["configured_in"]
    assert {(p["line"], p["basis"]) for p in places} == {
        (2, "configured_group"), (3, "configured_protocol")}
    pins = [a for a in result["evidence"]["protocols"] if a["protocol"] == "tls"]
    assert [(a["version"], a["line"]) for a in pins] == [("TLSv1.2", 3)]
    groups = result["evidence"]["tls_groups"]
    assert [(g["group"], g["setting"]) for g in groups] == [("X25519", "ssl-default-bind-curves")]
    assert all(g["tls_termination"] == TLS_SETTING_NOTE for g in groups + pins)


def test_server_side_and_max_version(tmp_path):
    cfg = ("global\n"
           "  ssl-default-server-curves P-256:X25519MLKEM768\n"
           "  ssl-default-server-options ssl-max-ver TLSv1.3\n")
    result = scan_directory(_tree(tmp_path, {"haproxy.cfg": cfg}))
    assert [(g["group"], g["setting"]) for g in result["evidence"]["tls_groups"]] == [
        ("P-256", "ssl-default-server-curves")]
    assert [a["version"] for a in result["evidence"]["protocols"]] == ["TLSv1.3"]


def test_bind_and_server_line_keywords(tmp_path):
    cfg = ("frontend fe\n"
           "  bind :443 ssl crt /etc/ssl/site.pem curves X25519MLKEM768:X25519 ssl-min-ver TLSv1.2\n"
           "backend be\n"
           "  server s1 10.0.0.1:443 ssl verify required curves secp384r1\n")
    result = scan_directory(_tree(tmp_path, {"haproxy.cfg": cfg}))
    assert [(g["group"], g["setting"], g["line"]) for g in result["evidence"]["tls_groups"]] == [
        ("X25519", "curves", 2), ("secp384r1", "curves", 4)]
    assert [a["version"] for a in result["evidence"]["protocols"]
            if a["basis"] == "configured_protocol"] == ["TLSv1.2"]
    # 0.33.0: the bind line is also the listener; it sets curves and ssl-min-ver itself.
    [listener] = [a for a in result["evidence"]["protocols"]
                  if a["basis"] == "configured_listener"]
    assert listener["line"] == 2
    assert listener["library_defaults"] == ["TLS 1.2 cipher list", "TLS 1.3 cipher suites"]


def test_the_word_curves_in_prose_is_not_a_setting(tmp_path):
    text = ("Supported curves X25519 and P-256 are listed below.\n"
            "    curves P-256 are fine\n")
    result = scan_directory(_tree(tmp_path, {"notes.cfg": text, "c.py": "# curves X25519\n"}))
    assert result["evidence"]["tls_groups"] == []
    assert result["tls_termination"] is None


def test_it_reaches_the_command_and_the_cbom(tmp_path):
    tree = _tree(tmp_path, {"haproxy.cfg": HAPROXY})
    out = tmp_path / "out.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                    "scan", str(tree), "--out", str(out)], check=True, capture_output=True)
    import json
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["tls_termination"] is not None
    assert written["evidence"]["tls_groups"]
    names = {c["name"] for c in build(scan_directory(tree))["components"]}
    assert "X25519 (TLS group offered alone)" in names
    assert "TLSv1.2" in names
