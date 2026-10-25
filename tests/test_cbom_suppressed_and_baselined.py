"""Release A, after the merge: what the owner held back is in the CBOM, counted.

The two branches met here. relA-ci moves a suppressed row out of `evidence` and marks each
row new or baselined; relA-cbom builds the CBOM from the coverage block. A suppressed row is
counted in `coverage.suppressed` and a baseline in `coverage.baseline`, and both travel into
the CBOM properties: a document sent outward that shows fewer rows than the code holds,
without saying why, is the silent skip in another form.
"""

from __future__ import annotations

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

CODE = ("from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "k2 = rsa.generate_private_key(public_exponent=65537, key_size=4096)"
        "  # qrp:ignore RSA legacy HSM, ticket 41\n")
NEW = "k3 = ec.generate_private_key(ec.SECP256R1())\n"


def _run(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.py").write_text(CODE)
    base = tmp_path / "baseline.json"
    assert server.scan_to_file([str(tree), "--write-baseline", str(base),
                                "--out", str(tmp_path / "r.json")]) == 0
    (tree / "app.py").write_text(CODE + NEW)
    return scan_directory(tree, baseline=base)


def test_coverage_counts_the_suppressed_and_the_baselined(tmp_path):
    cov = _run(tmp_path)["coverage"]
    assert cov["suppressed"]["count"] == 1
    assert cov["suppressed"]["items"][0]["reason"] == "legacy HSM, ticket 41"
    assert cov["baseline"]["new"] >= 1 and cov["baseline"]["baselined"] >= 1
    assert "new_items" not in cov["baseline"]


def test_the_cbom_properties_carry_both(tmp_path):
    result = _run(tmp_path)
    props = {p["name"]: p["value"] for p in cyclonedx.build(result)["properties"]}
    assert props["qrp:coverage:suppressed:count"] == "1"
    assert props["qrp:coverage:suppressed:items:0:line"] == "3"
    assert props["qrp:coverage:baseline:new"] == str(result["baseline"]["new"])
    assert props["qrp:coverage:baseline:baselined"] == str(result["baseline"]["baselined"])
    # The import row of the first run is gone once a call names EC (an import beside its
    # call is not counted twice), so the baseline holds one entry this run did not find.
    assert props["qrp:coverage:baseline:absent"] == "1" == str(result["baseline"]["absent"])
    assert not any(k.startswith("qrp:coverage:baseline:file") for k in props)
