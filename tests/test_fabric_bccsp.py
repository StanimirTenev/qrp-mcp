"""Fix list, Fabric BCCSP (entered 04.11.2026 from an internal comparison). Inputs: core.yaml
and orderer.yaml written for the comparison, and the peer core.yaml of Hyperledger Fabric's
test network (fabric-samples, Apache-2.0).

`BCCSP: Default: SW` with `SW: Security: 256|384` gave no evidence at all. Fabric's software
provider signs with ECDSA on P-256 or P-384 by that level (bccsp/sw/conf.go at v2.5.9), and
the PKCS#11 provider does the same inside the HSM (bccsp/pkcs11/pkcs11.go; the Fabric 2.5 HSM
guide). Both are now an ECDSA row with the curve; the PKCS#11 one says the key is held in
the HSM."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "fabric"


def _rows(tmp_path: Path, folder: str):
    from qrp_mcp.scan import scan_directory
    shutil.copytree(FIXTURES / folder, tmp_path / folder)
    result = scan_directory(tmp_path / folder)
    return result, [e for e in result["evidence"]["source_code"] if e["algorithm"] == "ECDSA"]


def test_software_provider_gives_ecdsa_on_the_security_curve(tmp_path):
    result, rows = _rows(tmp_path, "bccsp-sw")
    assert sorted((e["path"], e["curve"]) for e in rows) == [("core.yaml", "P-256"),
                                                             ("orderer.yaml", "P-384")]
    assert all("key_held" not in e for e in rows)
    assert result["summary"]["by_role"]["signature"]["families"] == ["ECDSA"]


def test_pkcs11_provider_says_the_key_is_in_the_hsm(tmp_path):
    _, rows = _rows(tmp_path, "bccsp-hsm")
    assert [(e["line"], e["curve"], e["key_held"]) for e in rows] == [(3, "P-256", "hsm")]


def test_the_fabric_samples_peer_config(tmp_path):
    _, rows = _rows(tmp_path, "bccsp-samples")
    assert [(e["curve"], e["excerpt"]) for e in rows] == [("P-256", "Default: SW")]


def test_another_yaml_with_a_default_key_is_not_read(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "x.yaml").write_text("crypto:\n  Default: SW\n  SW:\n    Security: 256\n")
    assert not [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
                if e["algorithm"] == "ECDSA"]
