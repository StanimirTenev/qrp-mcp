"""Row 16 (Vladimir Mikhalev, 7 Oct 2026): an AWS TLS policy is a configuration, and a
missing one is a policy too.

Reproduced on 0.28.0 + 178dcf2 before any change: `aws_lb_listener` with
`ssl_policy = "ELBSecurityPolicy-2016-08"` gave 0 findings, and the same listener with
no `ssl_policy` gave 0 findings. AWS (describe-ssl-policies, read 7 Oct 2026): "Other
methods (for example, the AWS CLI, AWS CloudFormation, and the AWS CDK) - The default
security policy is ELBSecurityPolicy-2016-08", and Terraform sends nothing when the
attribute is absent -- so both files mean TLS 1.0-1.2 with RSA key transport and no
post-quantum group.

Every check runs the way a user reaches it: the CLI writing a file, the MCP tool, the
CBOM export, and closure.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.server import export_cbom, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _both(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


def _families(result: dict) -> dict[str, str]:
    return {f["algorithm_family"]: f["classification"] for f in result["findings"]}


def _policies(result: dict) -> list[dict]:
    return [p for p in result["evidence"]["protocols"] if p.get("policy")]


EXPLICIT = """resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port = 443
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = var.cert
}
"""

OMITTED = """resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port = 443
  protocol = "HTTPS"
  certificate_arn = var.cert
}
"""


def test_the_probe_explicit_2016_08_is_no_longer_zero(tmp_path):
    for result in _both(tmp_path, {"main.tf": EXPLICIT}):
        found = _families(result)
        assert found["RSA"] == "classical_vulnerable"      # RSA key transport suites
        assert found["ECDH"] == "classical_vulnerable"     # ECDHE suites
        assert "ML-KEM" not in found
        assert result["summary"]["pqc_readiness"] == "classical_only"
        [policy] = _policies(result)
        assert policy["policy"] == "ELBSecurityPolicy-2016-08"
        assert policy["allows_versions"] == ["TLSv1.2", "TLSv1.1", "TLSv1.0"]
        assert policy["deprecated"] is True
        assert policy["post_quantum"] is False
        assert "default_applied" not in policy


def test_the_probe_omitted_policy_is_the_documented_default(tmp_path):
    for result in _both(tmp_path, {"main.tf": OMITTED}):
        found = _families(result)
        assert found["RSA"] == "classical_vulnerable"
        assert found["ECDH"] == "classical_vulnerable"
        [policy] = _policies(result)
        assert policy["policy"] == "ELBSecurityPolicy-2016-08"
        assert policy["default_applied"] == "default applied because ssl_policy is absent"
        assert policy["line"] == 1                     # the resource that lacks it
        assert policy["basis"] == "provider_default"
        rsa = [e for e in result["evidence"]["iac"] if e["algorithm"] == "RSA"]
        assert rsa and all(e["evidence_kind"] == "default" for e in rsa)


def test_the_default_statement_survives_the_default_level_and_reaches_the_cbom(tmp_path):
    tree = _tree(tmp_path / "tree", {"main.tf": OMITTED})
    # The MCP tool masks excerpts by default; the statement must not live in one.
    masked = _tool(scan_repo)(str(tree))
    assert _policies(masked)[0]["default_applied"].endswith("ssl_policy is absent")
    doc = _tool(export_cbom)(str(tree))
    comp = next(c for c in doc["components"]
                if c["name"].startswith("ELBSecurityPolicy-2016-08"))
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:default_applied"] == "default applied because ssl_policy is absent"
    assert props["qrp:allows_versions"] == '["TLSv1.2", "TLSv1.1", "TLSv1.0"]'
    assert comp["cryptoProperties"]["protocolProperties"]["type"] == "tls"


def test_a_pq_policy_is_hybrid_not_ready(tmp_path):
    files = {"main.tf": EXPLICIT.replace("ELBSecurityPolicy-2016-08",
                                         "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")}
    for result in _both(tmp_path, files):
        found = _families(result)
        assert found["ML-KEM"] == "pqc_ready"
        assert found["ECDH"] == "classical_vulnerable"   # classical groups still offered
        assert "RSA" not in found
        assert result["summary"]["pqc_readiness"] == "hybrid_partial"
        assert _policies(result)[0]["deprecated"] is False


def test_a_redirect_to_https_inside_an_http_listener_is_not_an_https_listener(tmp_path):
    text = """resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
"""
    result = _tool(scan_repo)(str(_tree(tmp_path, {"main.tf": text})))
    assert _policies(result) == []
    assert "RSA" not in _families(result)


def test_a_policy_from_a_variable_is_not_absent(tmp_path):
    text = OMITTED.replace('  certificate_arn', '  ssl_policy = var.tls_policy\n  certificate_arn')
    result = _tool(scan_repo)(str(_tree(tmp_path, {"main.tf": text})))
    assert _policies(result) == []


def test_cloudformation_yaml_explicit_and_omitted(tmp_path):
    text = """Resources:
  Explicit:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      Protocol: HTTPS
      Port: 443
      SslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-2021-06
  Omitted:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      Protocol: TLS
      Port: 443
      DefaultActions:
        - Type: redirect
          RedirectConfig:
            Protocol: HTTPS
  Plain:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      Protocol: HTTP
      DefaultActions:
        - RedirectConfig:
            Protocol: HTTPS
"""
    for result in _both(tmp_path, {"stack.yaml": text}):
        by_policy = {(p["policy"], p.get("default_applied")): p for p in _policies(result)}
        assert set(by_policy) == {
            ("ELBSecurityPolicy-TLS13-1-2-Res-2021-06", None),
            ("ELBSecurityPolicy-2016-08", "default applied because ssl_policy is absent"),
        }
        assert by_policy[("ELBSecurityPolicy-2016-08",
                          "default applied because ssl_policy is absent")]["line"] == 8


def test_cloudformation_json_omitted(tmp_path):
    doc = {"Resources": {"L": {"Type": "AWS::ElasticLoadBalancingV2::Listener",
                               "Properties": {"Protocol": "HTTPS", "Port": 443}}}}
    text = json.dumps(doc, indent=2)
    result = _tool(scan_repo)(str(_tree(tmp_path, {"stack.json": text})))
    [policy] = _policies(result)
    assert policy["default_applied"] == "default applied because ssl_policy is absent"
    assert policy["line"] == 3
    assert "RSA" in _families(result)


def test_cdk_enum_maps_to_the_policy(tmp_path):
    text = ("const l = lb.addListener('L', { port: 443, certificates: [c],\n"
            "  sslPolicy: elbv2.SslPolicy.TLS13_RES });\n"
            "const m = lb.addListener('M', { sslPolicy: elbv2.SslPolicy.RECOMMENDED });\n")
    result = _tool(scan_repo)(str(_tree(tmp_path, {"stack.ts": text})))
    names = sorted(p["policy"] for p in _policies(result))
    assert names == ["ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"]


def test_cdk_legacy_is_named_without_algorithms(tmp_path):
    """LEGACY -> ELBSecurityPolicy-TLS-1-0-2015-04 is on neither AWS page; its contents
    are known only from a CDK comment, so nothing is claimed about them."""
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "stack.ts": "lb.addListener('L', { sslPolicy: elbv2.SslPolicy.LEGACY });\n"})))
    assert _families(result) == {}


def test_an_unknown_policy_name_claims_nothing(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "main.tf": EXPLICIT.replace("2016-08", "2099-01")})))
    assert _families(result) == {}
    assert _policies(result) == []


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_closure_sees_the_default_replaced_by_a_pq_policy(tmp_path):
    tree = _tree(tmp_path / "tree", {"main.tf": OMITTED})
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "before")
    scans = []
    for label in ("before", "after"):
        if label == "after":
            (tree / "main.tf").write_text(EXPLICIT.replace(
                "ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"))
            _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "after")
        data = _cli(tree, tmp_path / f"{label}.json")
        data["coverage"]["instrument"]["source_commit"] = {
            "pinned": True, "commit": "instrument", "dirty": False}
        (tmp_path / f"{label}.json").write_text(json.dumps(data))
        scans.append(tmp_path / f"{label}.json")
    out = tmp_path / "closure.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "closure", *map(str, scans),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    per_family = json.loads(out.read_text())["closure"]["per_family_before_after"]
    assert per_family["RSA"] == [1, 0]
    assert per_family["ML-KEM"] == [0, 1]
