"""ZA-OPRAVYANE row 208 (LinkedIn, 04.11.2026; fixture from the room's probe `rn-kms`).

AWS KMS in C#: an ML-KEM-768 key, and the stored records wrapped with
`EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256`. That constant was read only as a component of
an identifier, and identifier rows by design (rel3-rules) never move the headline or by_role,
so `by_role.key_establishment` read `pqc_ready` with RSA key transport on a line the scan had
read.

The constant is an AWS KMS API value naming RSA-OAEP, as `KeySpec.RSA_2048` names an RSA key:
it is now a rule of its own (a key spec), not an identifier. The rel3 rule for identifiers
stands (test_identifier_rows_keep_the_headline)."""

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


def test_rsa_oaep_spec_counts_for_key_establishment(tmp_path):
    result = _scan(tmp_path)
    row = [e for e in result["evidence"]["source_code"]
           if e["algorithm"] == "RSA" and e["line"] == 25][0]
    assert row["evidence_kind"] != "identifier" and row["role"] == "key_establishment"
    part = result["summary"]["by_role"]["key_establishment"]
    assert "RSA" in part["families"]
    assert part["pqc_readiness"] == "hybrid_partial", part


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
    assert part["pqc_readiness"] == "hybrid_partial"
