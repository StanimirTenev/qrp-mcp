"""Row 558 (25.11.2026, Yan Massart; probe `linkedin-postove/2026-11-25/stai/proba/massart` against
`massart-ml`).

`server { listen 443 ssl; ... ssl_certificate ...; ssl_certificate_key ...; }` on one line gave
`tls_listeners: null` and `tls_termination.authentication_not_read: null`; the same block written
over lines gave two listeners and four places. The readers matched a directive at the start of a
line, and nginx does not end a directive at a line: "A simple directive consists of the name and
parameters separated by spaces and ends with a semicolon (;). A block directive has the same
structure as a simple directive, but instead of the semicolon it ends with a set of additional
instructions surrounded by braces ({ and })" (https://nginx.org/en/docs/beginners_guide.html).

The class: every nginx directive the TLS-endpoint readers take -- listen, server_name,
ssl_ecdh_curve, ssl_certificate[_key], the *_ssl_verify switches and the TLS upstreams,
ssl_verify_client, the trust stores -- read wherever a statement starts, not only at the start of a
line: a block on one line, two directives on one line, `http { server { ... } }` on one line, two
servers on one line. The row keeps the physical line, as every row does.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo


def _scan(tmp_path: Path, text: str, name: str = "nginx.conf") -> dict:
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _listeners(result: dict) -> list[tuple]:
    return [(p["line"], [x["port"] for x in p["listen"]], p["server_name"],
             [g["name"] for g in p["groups"]["groups"]],
             [(c["line"], c["setting"]) for c in p["certificates"]])
            for p in (result.get("tls_listeners") or {}).get("places") or []]


def _unread(result: dict) -> list[tuple]:
    places = ((result.get("tls_termination") or {}).get("authentication_not_read") or {}).get(
        "places") or []
    return sorted((p["line"], p["setting"], p["file"]) for p in places)


ONE_LINE = ("server { listen 443 ssl; server_name core.example; ssl_ecdh_curve X25519:prime256v1; "
            "ssl_certificate /etc/pki/core.crt; ssl_certificate_key /etc/pki/core.key; }\n")
MULTI_LINE = ("server {\n  listen 443 ssl;\n  server_name core.example;\n"
              "  ssl_ecdh_curve X25519:prime256v1;\n  ssl_certificate /etc/pki/core.crt;\n"
              "  ssl_certificate_key /etc/pki/core.key;\n}\n")


def test_a_server_block_on_one_line_is_a_listener(tmp_path):
    result = _scan(tmp_path, ONE_LINE)
    assert _listeners(result) == [(1, ["443"], ["core.example"], ["X25519", "prime256v1"],
                                   [(1, "ssl_certificate"), (1, "ssl_certificate_key")])]


def test_a_server_block_on_one_line_names_its_unread_certificate_and_key(tmp_path):
    result = _scan(tmp_path, ONE_LINE)
    assert _unread(result) == [(1, "ssl_certificate", "/etc/pki/core.crt"),
                               (1, "ssl_certificate_key", "/etc/pki/core.key")]
    assert result["summary"]["by_role"]["signature"]["pqc_readiness"] == "not_established"


def test_one_line_and_multi_line_say_the_same_apart_from_the_lines(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    one = scan_directory(_write(tmp_path / "a", ONE_LINE))
    many = scan_directory(_write(tmp_path / "b", MULTI_LINE))
    strip = lambda rows: [tuple(x for x in r if not isinstance(x, int)) for r in rows]  # noqa: E731
    assert [r[1:4] for r in _listeners(one)] == [r[1:4] for r in _listeners(many)]
    assert strip(_unread(one)) == strip(_unread(many))


def _write(root: Path, text: str) -> Path:
    (root / "nginx.conf").write_text(text)
    return root


def test_two_directives_on_one_line_inside_a_block(tmp_path):
    # A group setting makes the file a TLS place (tls_termination), as it does over lines.
    result = _scan(tmp_path, "server {\n  listen 443 ssl; server_name a.example;\n"
                             "  ssl_certificate /e/a.crt; ssl_certificate_key /e/a.key;\n"
                             "  ssl_ecdh_curve X25519;\n}\n")
    assert _listeners(result) == [(1, ["443"], ["a.example"], ["X25519"],
                                   [(3, "ssl_certificate"), (3, "ssl_certificate_key")])]
    assert _unread(result) == [(3, "ssl_certificate", "/e/a.crt"),
                               (3, "ssl_certificate_key", "/e/a.key")]


def test_http_and_server_on_one_line(tmp_path):
    result = _scan(tmp_path, "http { server { listen 443 ssl; ssl_certificate /e/a.crt; } }\n")
    assert _listeners(result) == [(1, ["443"], [], [], [(1, "ssl_certificate")])]


def test_two_servers_on_one_line(tmp_path):
    result = _scan(tmp_path, "server { listen 443 ssl; ssl_certificate /e/a.crt; } "
                             "server { listen 8443 ssl; ssl_certificate /e/b.crt; }\n"
                             "ssl_ecdh_curve X25519;\n")
    outside = ["X25519"]
    assert _listeners(result) == [(1, ["443"], [], outside, [(1, "ssl_certificate")]),
                                  (1, ["8443"], [], outside, [(1, "ssl_certificate")])]
    assert _unread(result) == [(1, "ssl_certificate", "/e/a.crt"),
                               (1, "ssl_certificate", "/e/b.crt")]


def test_a_server_without_ssl_on_the_same_line_is_not_a_listener(tmp_path):
    result = _scan(tmp_path, "server { listen 80; } server { listen 443 ssl; }\n")
    assert [r[1] for r in _listeners(result)] == [["443"]]


def test_a_directive_after_a_comment_is_not_read(tmp_path):
    result = _scan(tmp_path, "server { listen 443 ssl; } # ssl_certificate /e/x.crt;\n")
    assert _unread(result) == []


def _protocols(result: dict) -> list[tuple]:
    return sorted((a["line"], a.get("peer_verification"), a.get("verification_setting"))
                  for a in result["evidence"]["protocols"]
                  if a.get("basis") == "configured_verification")


def test_proxy_ssl_verify_off_on_one_line(tmp_path):
    result = _scan(tmp_path, "server { listen 443 ssl; location / { proxy_pass https://up; "
                             "proxy_ssl_verify off; } }\n")
    assert _protocols(result) == [(1, "off", "proxy_ssl_verify off")]


def test_tls_upstream_without_verify_on_one_line(tmp_path):
    result = _scan(tmp_path, "server { location / { grpc_pass grpcs://up; } }\n")
    assert _protocols(result) == [(1, "off", "grpc_ssl_verify not set")]


def test_verify_on_on_one_line_is_set(tmp_path):
    # The default-off reading must see a `proxy_ssl_verify on` that is not at a line's start.
    result = _scan(tmp_path, "server {\n  location / { proxy_pass https://up; proxy_ssl_verify on; }\n}\n")
    assert _protocols(result) == []


def test_ssl_verify_client_on_one_line(tmp_path):
    result = _scan(tmp_path, "server { listen 443 ssl; ssl_verify_client optional; }\n")
    assert _protocols(result) == [(1, "optional", "ssl_verify_client optional")]


def test_trust_store_on_one_line(tmp_path):
    result = _scan(tmp_path, "server { listen 443 ssl; ssl_client_certificate /e/ca.pem; "
                             "location / { proxy_ssl_trusted_certificate /e/up.pem; } }\n")
    places = sorted((p["line"], p["setting"]) for p in result["trust_stores"]["places"])
    assert places == [(1, "proxy_ssl_trusted_certificate"), (1, "ssl_client_certificate")]


def test_cli_and_mcp_carry_the_one_line_listener(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    _write(root, ONE_LINE)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out), "--level", "full"],
                   check=True, capture_output=True, env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root), level="full")):
        assert [r[0] for r in _listeners(result)] == [1]
        assert len(_unread(result)) == 2
