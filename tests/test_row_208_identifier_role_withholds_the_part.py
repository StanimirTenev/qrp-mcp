"""ZA-OPRAVYANE row 208 (LinkedIn, 04.11.2026; fixture from the room's probe `rn-kms`).

AWS KMS in C#: an ML-KEM-768 key, and the stored records wrapped with
`EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256`. The RSA line is an identifier row, which by
design (rel3-rules) never moves the headline or by_role, so `by_role.key_establishment` read
`pqc_ready` -- with RSA key transport on the line the scan had read.

The identifier row still does not count. But a part that would say nothing classical, beside
an identifier row naming a classical family for that role, now reads `not_established` and
names the row."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "row-208" / "Envelope.cs"


def _scan(tmp_path: Path, text: str | None = None):
    from qrp_mcp.scan import scan_directory
    tree = tmp_path / "t"
    tree.mkdir()
    if text is None:
        shutil.copy(FIXTURE, tree / "Envelope.cs")
    else:
        (tree / "Envelope.cs").write_text(text)
    return scan_directory(tree)


def test_rsa_oaep_named_beside_ml_kem_withholds_key_establishment(tmp_path):
    result = _scan(tmp_path)
    row = [e for e in result["evidence"]["source_code"]
           if e["algorithm"] == "RSA" and e["line"] == 25][0]
    assert row["evidence_kind"] == "identifier" and row["role"] == "key_establishment"
    part = result["summary"]["by_role"]["key_establishment"]
    assert part["pqc_readiness"] == "not_established", part
    assert any("Envelope.cs:25" in b for b in part["because"]), part
    # Still not counted: RSA does not join the part's families on a name alone.
    assert "RSA" not in part["families"]


def test_without_the_rsa_line_the_part_reads_ready(tmp_path):
    text = FIXTURE.read_text().replace(
        "EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256 });", "});")
    part = _scan(tmp_path, text)["summary"]["by_role"]["key_establishment"]
    assert part["pqc_readiness"] == "pqc_ready", part


def test_through_the_mcp_tool(tmp_path):
    from qrp_mcp.server import scan_repo
    tree = tmp_path / "m"
    tree.mkdir()
    shutil.copy(FIXTURE, tree / "Envelope.cs")
    part = scan_repo(str(tree))["summary"]["by_role"]["key_establishment"]
    assert part["pqc_readiness"] == "not_established"
