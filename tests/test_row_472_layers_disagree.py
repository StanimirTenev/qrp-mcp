"""Row 472 (15.11.2026, SITG-Consulting: "both go in, with the conflict marked; the pessimistic
one governs; the disagreement logged as an open finding with an owner").

nginx `ssl_ecdh_curve X25519MLKEM768:X25519` and an `aws_lb_listener` whose `ssl_policy` offers
classical (EC)DHE only came out as two findings in two sections, with nothing joining them. Now
one open finding in `layer_disagreements` names both lines, says the weaker value applies until
the connection is measured on the wire, and carries the CODEOWNERS owner of the terminator (the
load balancer). Nothing in the files ties this nginx to that listener -- port 443 alone would
tie any two HTTPS services -- so the link is "not established" and the finding stands at
repository level. Layers that agree emit nothing, and a link never clears a disagreement.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import _at_level, export_cbom, scan_repo

NGINX_PQ = ("server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.3;\n"
            "  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n")
NGINX_CLASSICAL = ("server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.3;\n"
                   "  ssl_ecdh_curve X25519:secp256r1;\n}\n")


def _lb(policy: str) -> str:
    return ('resource "aws_lb_listener" "https" {\n  load_balancer_arn = aws_lb.web.arn\n'
            f'  port              = 443\n  protocol          = "HTTPS"\n'
            f'  ssl_policy        = "{policy}"\n}}\n')


CLASSICAL_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"
PQ_POLICY = "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"
CODEOWNERS = "/scripts/  @acme/payments-ops\n/infra/  @acme/platform\n"


def _tree(root: Path, nginx: str, policy: str) -> Path:
    for name, text in {"web/nginx.conf": nginx, "infra/lb.tf": _lb(policy),
                       ".github/CODEOWNERS": CODEOWNERS}.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args):
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True)


def test_one_open_finding_names_both_lines_and_the_terminator_owner(tmp_path):
    root = _tree(tmp_path / "r", NGINX_PQ, CLASSICAL_POLICY)
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out), "--level", "full"])
    for result in (json.loads(out.read_text()), scan_repo(str(root), level="full"),
                   scan_directory(root)):
        (d,) = result["layer_disagreements"]
        assert d["status"] == "open"
        places = {(layer["path"], layer["line"], layer["post_quantum"]) for layer in d["layers"]}
        assert places == {("web/nginx.conf", 4, True), ("infra/lb.tf", 5, False)}
        assert (d["weaker"]["path"], d["weaker"]["line"]) == ("infra/lb.tf", 5)
        assert "until" in d["governs"] and "on the wire" in d["governs"]
        assert d["owners"] == ["@acme/platform"] and d["owners_source"] == ".github/CODEOWNERS:2"
        assert d["link"] == {"established": False,
                             "basis": "link not established: this version does not read "
                                      "which listener, target group or upstream joins "
                                      "web/nginx.conf to infra/lb.tf"}


def test_owners_are_masked_below_full_on_all_three_exits(tmp_path):
    root = _tree(tmp_path / "r", NGINX_PQ, CLASSICAL_POLICY)
    out, cbom = tmp_path / "s.json", tmp_path / "c.json"
    _cli(["scan", str(root), "--out", str(out)])
    _cli(["cbom", str(root), "--out", str(cbom)])
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert result["layer_disagreements"][0]["owners"] == ["@****/********"]
    for doc in (json.loads(cbom.read_text()), export_cbom(str(root)),
                build(_at_level(scan_directory(root), "masked"))):
        (prop,) = [p for p in doc["properties"] if p["name"] == "qrp:layer_disagreements"]
        (d,) = json.loads(prop["value"])
        assert d["owners"] == ["@****/********"] and d["status"] == "open"
        assert {layer["location"] for layer in d["layers"]} == {"web/nginx.conf", "infra/lb.tf"}


def test_layers_that_agree_emit_nothing(tmp_path):
    both_pq = scan_directory(_tree(tmp_path / "a", NGINX_PQ, PQ_POLICY))
    both_classical = scan_directory(_tree(tmp_path / "b", NGINX_CLASSICAL, CLASSICAL_POLICY))
    assert both_pq["layer_disagreements"] == []
    assert both_classical["layer_disagreements"] == []


def test_the_other_direction_is_a_disagreement_too(tmp_path):
    (d,) = scan_directory(_tree(tmp_path / "c", NGINX_CLASSICAL, PQ_POLICY))["layer_disagreements"]
    assert (d["weaker"]["path"], d["weaker"]["post_quantum"]) == ("web/nginx.conf", False)
    assert d["owners"] == ["@acme/platform"]


def test_a_layer_in_test_code_is_not_compared(tmp_path):
    root = tmp_path / "t"
    for name, text in {"tests/fixtures/nginx.conf": NGINX_PQ, "infra/lb.tf": _lb(CLASSICAL_POLICY)
                       }.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    assert scan_directory(root)["layer_disagreements"] == []
