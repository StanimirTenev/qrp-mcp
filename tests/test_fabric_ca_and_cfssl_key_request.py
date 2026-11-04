"""Fix list, Fabric CA key request (entered 04.11.2026 from an internal comparison). Inputs: a
Fabric CA server config and a cfssl CSR from Hyperledger Fabric's test network (Apache-2.0).

Fabric CA `csr: keyrequest: algo: rsa, size: 2048` gave nothing at all; `algo: ecdsa, size:
256` gave ECDSA with `key_size: undetermined`, and so did cfssl's `"key": {"algo": "ecdsa",
"size": 256}`. Fabric CA's guide gives the ECDSA sizes as curves (256 prime256v1, 384
secp384r1); cfssl's csr.KeyRequest takes 256/384/521 as P-256/P-384/P-521 and an RSA size in
bits. The size in the same block is now read, as for Terraform and YAML keys (row 156)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "fabric"


@pytest.mark.parametrize("folder, name, family, size", [
    ("keyreq-rsa", "fabric-ca-server-config.yaml", "RSA", 2048),
    ("keyreq-ecdsa", "fabric-ca-server-config.yaml", "ECDSA", 256),
    ("cfssl", "ca-peer.json", "ECDSA", 256),
])
def test_key_request_gives_family_and_size(tmp_path, folder, name, family, size):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / folder / name, tmp_path / name)
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == family]
    assert [e["key_size"] for e in rows] == [size], rows
    if family == "ECDSA":
        assert rows[0]["curve"] == "P-256"


def test_a_size_in_another_ini_section_is_not_taken(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "x.ini").write_text("[ca]\nalgo = \"rsa\"\n[other]\nsize = 4096\n")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == "RSA"]
    assert rows and rows[0]["key_size"] == "undetermined"
