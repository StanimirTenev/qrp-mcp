"""A DNSSEC record whose algorithm number has no family here is named, not dropped
(ZA-OPRAVYANE row 102; Georgi Ivanov's post-quantum DNSSEC posts; `dnssec.py:61 if known
is None: continue`, seen by stenly). Mnemonics from IANA's DNSSEC Algorithm Numbers registry
(qrp-kachestvo/linkedin-2026-10-23/izvori/iana-dnssec.csv)."""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

ZONE = ("example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+Gq==\n"
        "example.com. 3600 IN DNSKEY 257 3 253 AAAAexperimentalPQkeyAAAA==\n")


def _unnamed(result):
    return [p for p in result["evidence"]["protocols"] if p.get("dnssec_algorithm") is not None]


def test_private_algorithm_is_named(tmp_path):
    (tmp_path / "example.zone").write_text(ZONE)
    result = scan_directory(tmp_path)
    [asset] = _unnamed(result)
    assert (asset["dnssec_algorithm"], asset["dnssec_mnemonic"]) == (253, "PRIVATEDNS")
    assert asset["line"] == 2
    # Still no family invented for it.
    assert result["detected_algorithms"] == ["ECDSA"]
    assert any("DNSSEC algorithm 253" in (c.get("name") or "") for c in build(result)["components"])


def test_an_unnamed_number_withholds_reassurance(tmp_path):
    (tmp_path / "example.zone").write_text(
        "example.com. 3600 IN DNSKEY 257 3 18 AAAAmldsa44keyAAAA==\n"
        "example.com. 3600 IN DNSKEY 257 3 253 AAAAexperimentalPQkeyAAAA==\n")
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "not_established"
    assert any("253" in reason for reason in summary["readiness_not_established"]["because"])


def test_unassigned_number_says_so(tmp_path):
    (tmp_path / "example.zone").write_text("example.com. 3600 IN DNSKEY 257 3 99 AAAA==\n")
    [asset] = _unnamed(scan_directory(tmp_path))
    assert asset["dnssec_mnemonic"] is None
    assert "unassigned or reserved" in asset["description"]
