"""ZA-OPRAVYANE row 117 (LinkedIn 23.10.2026, Opaka; decided by Stanimir on 2 Nov 2026): a
TLS server image pinned beside the hybrid group the tree configures, with
`support: not_established` (nginx:1.27.4: which OpenSSL it carries is not in this scan's
table), left the headline at `hybrid_partial` and `readiness_not_established` null -- as if
the group were negotiated. The headline now says it is not established and why, with the
would-be value beside it. Scoped as row 55 is: only where every use of the post-quantum
family is such a TLS place; ML-KEM used by code beside it still counts."""

import json
import subprocess
import sys

from qrp_mcp.scan import scan_directory

NGINX = "server {\n  listen 443 ssl;\n  ssl_ecdh_curve X25519MLKEM768;\n  ssl_protocols TLSv1.3;\n}\n"
KEM = "from pqcrypto.kem.ml_kem_768 import generate_keypair\npk, sk = generate_keypair()\n"


def _tree(tmp_path, image, extra=None):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "nginx.conf").write_text(NGINX, encoding="utf-8")
    (tree / "docker-compose.yml").write_text(
        f"services:\n  web:\n    image: {image}\n", encoding="utf-8")
    for name, text in (extra or {}).items():
        (tree / name).write_text(text, encoding="utf-8")
    return tree


def test_an_unestablished_image_withholds_the_headline_through_the_cli(tmp_path):
    tree = _tree(tmp_path, "nginx:1.27.4")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    summary = json.loads(out.read_text())["summary"]
    assert summary["pqc_readiness"] == "not_established"
    withheld = summary["readiness_not_established"]
    assert withheld["would_read"] == "hybrid_partial"
    assert any("nginx:1.27.4 (docker-compose.yml:3)" in b and "not established" in b
               for b in withheld["because"]), withheld
    assert summary["by_role"]["key_establishment"]["pqc_readiness"] == "not_established"


def test_mlkem_in_code_as_well_keeps_the_headline(tmp_path):
    result = scan_directory(str(_tree(tmp_path, "nginx:1.27.4", {"kem.py": KEM})))
    assert result["summary"]["pqc_readiness"] == "hybrid_partial"
    assert result["summary"]["readiness_not_established"] is None


def test_an_image_known_not_to_support_it_is_unchanged(tmp_path):
    """Row 55's case: nginx:1.24.0 cannot negotiate it; ML-KEM is set aside, not withheld."""
    result = scan_directory(str(_tree(tmp_path, "nginx:1.24.0")))
    assert result["summary"]["pqc_readiness"] == "classical_only"
