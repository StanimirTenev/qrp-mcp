"""ZA-OPRAVYANE row 110 (agent 0.35.0, 23.10.2026): a Dockerfile is read since 0.35.0, but
its `FROM nginx:1.24.0` was not a pin, so the image that serves a hybrid group configured in
the same tree was never put beside it (`evidence.library_support`, row 41). Only `image:`
lines (compose, Kubernetes) were. A `FROM` line names no mount, so the pin and the groups
are named side by side, not joined."""

import json
import subprocess
import sys

import pytest

from qrp_mcp.scan import scan_directory


def _tree(tmp_path, dockerfile_name, from_line):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / dockerfile_name).write_text(from_line + "COPY nginx.conf /etc/nginx/nginx.conf\n",
                                        encoding="utf-8")
    (tree / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768;\n", encoding="utf-8")
    return tree


def test_a_from_line_is_a_pin_through_the_cli_and_the_cbom(tmp_path):
    tree = _tree(tmp_path, "Dockerfile", "FROM nginx:1.24.0\n")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    support = json.loads(out.read_text())["evidence"]["library_support"]
    assert [(s["path"], s["line"], s["image"], s["support"]) for s in support] == [
        ("Dockerfile", 1, "nginx:1.24.0", "not_supported")]
    assert "not joined here" in support[0]["description"]
    cbom = tmp_path / "cbom.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(cbom)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    containers = [c["name"] for c in json.loads(cbom.read_text())["components"]
                  if c["type"] == "container"]
    assert containers == ["nginx:1.24.0"]


@pytest.mark.parametrize("name, line, image", [
    ("Dockerfile", "FROM --platform=linux/amd64 nginx:1.27.4 AS edge\n", "nginx:1.27.4"),
    ("web.Dockerfile", "from docker.io/library/nginx:1.27.4\n", "docker.io/library/nginx:1.27.4"),
    ("Containerfile", "FROM haproxy:3.0\n", "haproxy:3.0"),
])
def test_the_spellings_of_from(tmp_path, name, line, image):
    support = scan_directory(str(_tree(tmp_path, name, line)))["evidence"]["library_support"]
    assert [(s["image"], s["support"]) for s in support] == [(image, "not_established")]


@pytest.mark.parametrize("line", ["FROM python:3.12\n", "# FROM nginx:1.24.0\n",
                                  "FROM nginx\n"])
def test_not_a_tls_server_pin(tmp_path, line):
    assert scan_directory(str(_tree(tmp_path, "Dockerfile", line)))["evidence"][
        "library_support"] == []
