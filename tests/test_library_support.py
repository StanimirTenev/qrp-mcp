"""A hybrid group and the pinned image that has to negotiate it (ZA-OPRAVYANE row 41).

The network-vs-code probe of 22.10.2026: the repository configures X25519MLKEM768, ops
keeps the service on nginx:1.24.0 -- OpenSSL 1.1.1, which does not know the group --
and nginx refused the repository's configuration, so a classical hotfix runs instead.
The pin was in a compose file the scanner read; nothing joined it to the group.

Facts used, each read at its source on 22.10.2026: OpenSSL added X25519MLKEM768,
SecP256r1MLKEM768 and SecP384r1MLKEM1024 in 3.5.0 (CHANGES.md); docker-nginx 1.24.0's
Debian image is FROM debian:bullseye-slim, whose openssl is 1.1.1w. Everything else is
"not established".
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.closure import _identity
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

COMPOSE = """services:
  edge:
    image: haproxy:3.2.4-alpine
    volumes:
      - ../repo/edge/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
  legacy:
    volumes:
      - ./legacy-override.conf:/etc/nginx/conf.d/default.conf:ro
      - certs:/etc/nginx/certs
    image: "nginx:1.24.0"
"""
FILES = {
    "deploy/compose.yaml": COMPOSE,
    "deploy/legacy-override.conf": "server {\n  ssl_ecdh_curve X25519:prime256v1;\n}\n",
    "repo/edge/haproxy.cfg": "global\n  ssl-default-bind-curves X25519MLKEM768:X25519\n",
    "repo/legacy/nginx.conf": ("# hybrid ML-KEM, SecP384r1MLKEM1024 in a comment\n"
                               "server {\n  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"),
}


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root, files):
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def _support(result):
    return {i["image"]: i for i in result["evidence"]["library_support"]}


def test_an_image_whose_openssl_predates_the_group(tmp_path):
    found = _support(scan_directory(_tree(tmp_path, FILES)))
    legacy = found["nginx:1.24.0"]
    assert (legacy["path"], legacy["line"]) == ("deploy/compose.yaml", 10)
    assert legacy["support"] == "not_supported"
    assert legacy["tls_library"] == "OpenSSL 1.1.1 (Debian bullseye)"
    assert legacy["not_negotiable"] == ["X25519MLKEM768"]
    assert legacy["group_places"] == ["repo/edge/haproxy.cfg:2", "repo/legacy/nginx.conf:3"]
    # Joined by its mount, in either key order: it serves the hotfix, which names none.
    assert legacy["serves"] == ["deploy/legacy-override.conf"]
    assert legacy["serves_group_places"] == []
    assert "cannot negotiate X25519MLKEM768" in legacy["description"]
    assert "names no hybrid group" in legacy["description"]


def test_an_image_not_in_the_table_is_not_established(tmp_path):
    edge = _support(scan_directory(_tree(tmp_path, FILES)))["haproxy:3.2.4-alpine"]
    assert edge["support"] == "not_established" and edge["tls_library"] is None
    assert edge["serves_group_places"] == ["repo/edge/haproxy.cfg:2"]
    assert "not established" in edge["description"]


def test_nothing_without_a_hybrid_group_or_a_tls_server_image(tmp_path):
    files = dict(FILES)
    files["repo/edge/haproxy.cfg"] = "global\n  ssl-default-bind-curves X25519\n"
    files["repo/legacy/nginx.conf"] = "server {}\n"
    assert scan_directory(_tree(tmp_path / "a", files))["evidence"]["library_support"] == []
    other = {"k8s.yaml": "spec:\n  containers:\n    - image: redis:7.2\n",
             "nginx.conf": "ssl_ecdh_curve X25519MLKEM768;\n"}
    assert scan_directory(_tree(tmp_path / "b", other))["evidence"]["library_support"] == []


def test_a_pin_without_a_mount_is_not_joined(tmp_path):
    files = {"k8s.yaml": "spec:\n  containers:\n    - name: web\n      image: nginx:1.24.0\n",
             "nginx.conf": "ssl_ecdh_curve X25519MLKEM768:X25519;\n"}
    [item] = scan_directory(_tree(tmp_path, files))["evidence"]["library_support"]
    assert item["support"] == "not_supported" and item["serves"] == []
    assert "not joined here" in item["description"]


def test_moving_the_group_line_is_not_a_new_finding():
    item = {"path": "c.yaml", "line": 3, "image": "nginx:1.24.0", "support": "not_supported",
            "group_places": ["a.conf:3"], "serves": [], "serves_group_places": []}
    moved = dict(item, group_places=["a.conf:9"])
    assert _identity("library_support", item) == _identity("library_support", moved)


def test_it_reaches_the_command_the_tool_and_the_cbom(tmp_path):
    tree = _tree(tmp_path / "t", FILES)
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert set(_support(json.loads(out.read_text()))) == {"nginx:1.24.0", "haproxy:3.2.4-alpine"}
    for level in ("masked", "trimmed", "full"):
        assert _support(_tool(scan_repo)(str(tree), level=level))[
            "nginx:1.24.0"]["support"] == "not_supported"
    cbom = _tool(export_cbom)(str(tree))
    image = next(c for c in cbom["components"] if c["name"] == "nginx:1.24.0")
    props = {p["name"]: p["value"] for p in image["properties"]}
    assert image["type"] == "container"
    assert props["qrp:support"] == "not_supported"
    assert props["qrp:not_negotiable"] == "X25519MLKEM768"
    jsonschema = pytest.importorskip("jsonschema")
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    errors = sorted(validator.iter_errors(cbom), key=str)
    assert not errors, errors[0].message
