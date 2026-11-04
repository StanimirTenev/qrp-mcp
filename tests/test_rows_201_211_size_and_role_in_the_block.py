"""ZA-OPRAVYANE rows 201, 205, 209, 211 and 196 (a) (LinkedIn, 03-04.11.2026; fixtures from the
rooms' probes `fl-vault`, `gf-aws`, `ra-azure`, `vb-mcu`, `m-gw`).

The key size was on the line beside the algorithm, or in the same token, and the scan said
`key_size: undetermined`:
- Vault `key_type = "rsa"` with `key_bits = 4096` on the next line (201), Azure Key Vault
  `key_type = "RSA"` with `key_size = 2048` (211);
- AWS KMS `customer_master_key_spec = "RSA_3072"` (209), the size in the spec's name;
- MCUboot `CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=2048` (205), Yocto `FIT_SIGN_ALG = "rsa2048"`
  (196 a).
And the role was in the same resource: KMS `key_usage = "SIGN_VERIFY"` (209), Azure
`key_opts = ["sign", "verify"]` (211), a Vault root CA, which only signs (201)."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "rows-201-211"


def _rows(tmp_path: Path, name: str, as_name: str | None = None):
    from qrp_mcp.scan import scan_directory
    tree = tmp_path / "t"
    tree.mkdir(parents=True)
    shutil.copy(FIXTURES / name, tree / (as_name or name))
    result = scan_directory(tree)
    return {(e["line"], e["algorithm"]): e
            for items in result["evidence"].values() for e in items
            if isinstance(e, dict) and e.get("algorithm")}


def test_vault_key_bits_on_the_next_line_and_root_ca_signs(tmp_path):
    rows = _rows(tmp_path, "vault-pki.tf")
    assert rows[(5, "RSA")]["key_size"] == 4096
    assert rows[(5, "RSA")]["role"] == "signature"
    assert rows[(12, "EC")]["key_size"] == 256
    # An issuing role's leaf key may sign or exchange: not decided by the block.
    assert rows[(12, "EC")]["role"] == "undetermined"


def test_kms_spec_name_gives_the_size_and_key_usage_the_role(tmp_path):
    rows = _rows(tmp_path, "aws-kms.tf")
    assert rows[(29, "RSA")]["key_size"] == 3072
    assert rows[(29, "RSA")]["role"] == "signature"


def test_azure_key_size_and_key_opts(tmp_path):
    rows = _rows(tmp_path, "azure-kv.tf")
    assert rows[(4, "RSA")]["key_size"] == 2048
    assert rows[(4, "RSA")]["role"] == "signature"


def test_usage_in_another_block_is_not_taken(tmp_path):
    from qrp_mcp.scan import scan_directory
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "a" {\n'
        '  key_type = "RSA"\n'
        '}\n'
        'resource "azurerm_key_vault_key" "b" {\n'
        '  key_size = 4096\n'
        '  key_opts = ["sign", "verify"]\n'
        '}\n')
    row = [e for e in scan_directory(tree)["evidence"]["iac"] if e["algorithm"] == "RSA"][0]
    assert row["key_size"] == "undetermined" and row["role"] == "undetermined"


def test_kconfig_len_and_rsa2048_token(tmp_path):
    rows = _rows(tmp_path, "mcuboot-prj.conf", "prj.conf")
    assert rows[(2, "RSA")]["key_size"] == 2048
    rows = _rows(tmp_path / "y", "yocto-local.conf", "local.conf")
    assert rows[(4, "RSA")]["key_size"] == 2048
