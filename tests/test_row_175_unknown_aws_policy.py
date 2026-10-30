"""ZA-OPRAVYANE row 175 (Tokunbo Taiwo): an HTTPS `aws_lb_listener` whose `ssl_policy` is a name
the table does not hold gave 0 findings, "read every one of the 1 files", `tls_termination: null`
and `unknown` -- the listener dropped out. Now the policy is a TLS protocol asset with
`policy_known: false`, the listener is a TLS place, and the headline is not established."""

import json

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

ALB = '''resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "%s"
  certificate_arn   = aws_acm_certificate.api.arn
}
'''


def _scan(tmp_path, policy):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "alb.tf").write_text(ALB % policy)
    return t, scan_directory(t)


def test_unknown_policy_is_named_not_dropped(tmp_path):
    t, r = _scan(tmp_path, "ELBSecurityPolicy-TLS13-1-2-PQ-2099-01")
    assets = [p for p in r["evidence"]["protocols"] if p.get("policy")]
    assert len(assets) == 1
    a = assets[0]
    assert a["policy"] == "ELBSecurityPolicy-TLS13-1-2-PQ-2099-01" and a["policy_known"] is False
    assert a["protocol"] == "tls" and a["line"] == 5 and "not determined" in a["description"]
    assert r["tls_termination"] is not None
    # The vendor policy decides the key exchange, not a library default.
    assert "key_exchange" not in a
    s = r["summary"]
    assert s["pqc_readiness"] == "not_established"
    assert any("ELBSecurityPolicy-TLS13-1-2-PQ-2099-01" in b
               for b in s["readiness_not_established"]["because"])
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    props = [{p["name"]: p["value"] for p in c["properties"]}
             for c in json.loads(out.read_text())["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "protocol"]
    assert any(p.get("qrp:policy_known") == "false" for p in props)


def test_known_policy_unchanged(tmp_path):
    _t, r = _scan(tmp_path, "ELBSecurityPolicy-TLS13-1-2-2021-06")
    a = [p for p in r["evidence"]["protocols"] if p.get("policy")][0]
    assert "policy_known" not in a and a["post_quantum"] is False


def test_a_variable_is_not_an_unknown_name(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "alb.tf").write_text((ALB % "x").replace('"x"', "var.tls_policy"))
    r = scan_directory(t)
    assert not [p for p in r["evidence"]["protocols"] if p.get("policy")]
