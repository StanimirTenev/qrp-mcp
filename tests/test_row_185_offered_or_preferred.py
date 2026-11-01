"""ZA-OPRAVYANE row 185 (01.11.2026): ML-KEM found in a file does not show that it is
negotiated. Where a configuration orders the key exchanges, the scan now says where ML-KEM
stands in that order, and whose order it is; where nothing orders it, it says it was seen
in code only. No connection is made: this is still a file scanner.

SSH: RFC 4253 Sec. 7.1 -- the first algorithm on the client's list that the server also
supports is chosen, so the first entry in an sshd_config is the server's preference and not
what a connection uses. TLS: only the position in the configured list is stated; who decides
is the TLS library's setting and is not read."""

from __future__ import annotations

import json
import subprocess
import sys

from qrp_mcp.scan import scan_directory


def _mlkem(result):
    return [e for e in result["evidence"]["source_code"] if e["algorithm"] == "ML-KEM"]


def test_sshd_order_offered_not_first(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "sshd_config").write_text(
        "KexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n")
    result = scan_directory(tmp_path)
    [row] = _mlkem(result)
    order = row["order"]
    assert order["setting"] == "KexAlgorithms"
    assert (order["position"], order["of"], order["first"]) == (2, 2, "curve25519-sha256")
    assert order["preferred"] is False
    assert "RFC 4253" in order["note"] and "client" in order["note"]
    f = {x["algorithm_family"]: x for x in result["findings"]}
    assert f["ML-KEM"]["negotiation"]["configured_order_read"] is True


def test_ssh_client_config_first_is_preferred(tmp_path):
    (tmp_path / "ssh_config").write_text(
        "Host *\n  KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n")
    [row] = _mlkem(scan_directory(tmp_path))
    assert row["order"]["position"] == 1 and row["order"]["preferred"] is True


def test_appended_to_the_default_list_has_no_position(tmp_path):
    (tmp_path / "sshd_config").write_text("KexAlgorithms +mlkem768x25519-sha256\n")
    [row] = _mlkem(scan_directory(tmp_path))
    assert row["order"]["position"] is None and row["order"]["preferred"] is None


def test_tls_groups_position_without_a_negotiation_claim(tmp_path):
    (tmp_path / "openssl.cnf").write_text(
        "[system_default_sect]\nGroups = X25519:X25519MLKEM768\n")
    [row] = _mlkem(scan_directory(tmp_path))
    assert (row["order"]["position"], row["order"]["of"]) == (2, 2)
    assert row["order"]["preferred"] is False
    assert "not read" in row["order"]["note"]


def test_code_only_says_so(tmp_path):
    (tmp_path / "a.py").write_text("from x import ml_kem\nk = ml_kem.MLKEM768()\n")
    result = scan_directory(tmp_path)
    assert all("order" not in e for e in _mlkem(result))
    f = {x["algorithm_family"]: x for x in result["findings"]}
    assert f["ML-KEM"]["negotiation"]["configured_order_read"] is False
    assert "code only" in f["ML-KEM"]["negotiation"]["statement"]


def test_order_reaches_the_cbom(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "sshd_config").write_text(
        "KexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n")
    (tree / "a.py").write_text("from x import ml_kem\nk = ml_kem.MLKEM768()\n")
    out = tmp_path / "c.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    said = {}
    for c in json.loads(out.read_text())["components"]:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if "qrp:negotiation" in props:
            values = json.loads(props["qrp:negotiation"])
            assert len(values) == len(c["evidence"]["occurrences"])
            for o, v in zip(c["evidence"]["occurrences"], values):
                said[o["location"]] = v
    assert said["sshd_config"].startswith("offered: position 2 of 2")
    assert said["a.py"].startswith("seen in code only")


def test_haproxy_bind_line_counts_only_the_curves_value(tmp_path):
    (tmp_path / "haproxy.cfg").write_text(
        "frontend f\n  bind :443 ssl crt x.pem curves X25519MLKEM768:X25519 alpn h2\n")
    [row] = _mlkem(scan_directory(tmp_path))
    assert (row["order"]["position"], row["order"]["of"]) == (1, 2)
    assert row["order"]["preferred"] is True and "list" not in row["order"]


def test_nginx_trailing_comment_is_not_in_the_list(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        "server {\n  ssl_ecdh_curve X25519:X25519MLKEM768; # prefer pq later\n}\n")
    [row] = _mlkem(scan_directory(tmp_path))
    assert (row["order"]["position"], row["order"]["of"], row["order"]["first"]) == \
        (2, 2, "X25519")
