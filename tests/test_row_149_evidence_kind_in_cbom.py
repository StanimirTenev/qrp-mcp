"""ZA-OPRAVYANE row 149 (the part left after 0.37.0): how an occurrence was found -- call,
declaration, import, default -- was in the scan JSON and not in the CBOM. A CycloneDX 1.6
occurrence takes no properties, so the component carries `qrp:evidence_kind`, one entry per
occurrence in order, as it carries `qrp:confidence`."""

import json

from qrp_mcp import server


def test_evidence_kind_per_occurrence(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                            "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    rsa = [c for c in json.loads(out.read_text())["components"] if c["name"].startswith("RSA")]
    assert rsa
    for c in rsa:
        props = {p["name"]: p["value"] for p in c["properties"]}
        kinds = json.loads(props["qrp:evidence_kind"])
        assert len(kinds) == len(c["evidence"]["occurrences"])
        assert "call" in kinds
