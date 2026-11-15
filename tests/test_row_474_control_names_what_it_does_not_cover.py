"""Row 474 (15.11.2026, John Bommeraveni Joseph: "provided the report states which styles were
planted"): the self-seeded control did not cover the styles of the tree itself.

The probe tree signs in `scripts/sign_batch.sh` (openssl) and configures TLS in
`web/nginx.conf`; the control planted cert-manager YAML, a Terraform key and Java properties,
and reported 9 of 9. The figure was right and said nothing about the lines that matter. The block
now lists, as `not_covered_by_control`, each file type that carries findings in the tree and in
which no style was planted, and its sentence says the figure does not cover them. The keys of
the block are a published shape: only added to.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp import control
from qrp_mcp.server import run_self_seeded_control

FILES = {
    "web/nginx.conf": "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.3;\n"
                      "  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n",
    "infra/lb.tf": 'resource "aws_lb_listener" "https" {\n  port = 443\n  protocol = "HTTPS"\n'
                   '  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}\n',
    "scripts/sign_batch.sh": "#!/bin/sh\n"
                             "openssl dgst -sha256 -sign /etc/batch/rsa2048.key -out b.sig b.csv\n",
}


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "r"
    for name, text in FILES.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args):
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True)


def _blocks(root: Path, tmp_path: Path) -> list[dict]:
    a, b, c = (tmp_path / n for n in ("a.json", "b.json", "c.json"))
    _cli(["control", str(root), "--seed", "1", "--out", str(a)])
    _cli(["scan", str(root), "--control-seed", "1", "--out", str(b)])
    return [json.loads(a.read_text())["self_seeded_control"],
            json.loads(b.read_text())["coverage"]["claims"]["self_seeded_control"],
            run_self_seeded_control(str(root), 1)["self_seeded_control"],
            control.run(root, 1)["self_seeded_control"]]


def test_the_tree_s_own_file_types_without_a_planted_style_are_named(tmp_path):
    root = _tree(tmp_path)
    for block in _blocks(root, tmp_path):
        got = {u["file_type"]: u for u in block["not_covered_by_control"]}
        assert set(got) == {".conf", ".sh"}, got
        assert got[".sh"]["paths"] == ["scripts/sign_batch.sh"]
        assert ".tf" not in got            # a Terraform style was planted
        assert "does not cover" in block["sentence"] and ".sh" in block["sentence"]


def test_the_cbom_carries_the_list(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--control-seed", "1", "--out", str(out)])
    names = {p["name"]: p["value"] for p in json.loads(out.read_text())["properties"]}
    assert any(k.startswith("qrp:coverage:claims:self_seeded_control:not_covered_by_control")
               and v == ".sh" for k, v in names.items())


def test_a_tree_whose_findings_are_all_in_planted_types_names_none(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "lb.tf").write_text(FILES["infra/lb.tf"])
    block = control.run(root, 1)["self_seeded_control"]
    assert block["not_covered_by_control"] == []
    assert "does not cover" not in block["sentence"]
