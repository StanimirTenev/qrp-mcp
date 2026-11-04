"""The new evidence shapes of batch 0.42.0 (formats) reach the CBOM by the MCP tool and the
document stays valid CycloneDX 1.6: switches with no version, FortiOS firmware defaults (a
`fortios` protocol and default rows), IKE groups, OpenPGP/.snk/plist/WireGuard keys."""

import json
import shutil
from pathlib import Path

import pytest

from qrp_mcp.server import export_cbom
from test_fortios_firmware_defaults import BACKUP
from test_snk_strong_name_keys import _blob
from test_switches_off import FORTIOS, VAULT
from test_wireguard import WG

FIXTURES = Path(__file__).parent / "fixtures" / "openpgp"


def _tool(tool):
    return getattr(tool, "fn", tool)


def test_cbom_is_valid_with_every_new_shape(tmp_path):
    (tmp_path / "fw.conf").write_text(FORTIOS)
    (tmp_path / "backup.conf").write_text(BACKUP)
    (tmp_path / "vault.hcl").write_text(VAULT)
    (tmp_path / "wg0.conf").write_text(WG)
    (tmp_path / "key.snk").write_bytes(_blob(1024))
    shutil.copy(FIXTURES / "release-keys.asc", tmp_path / "release-keys.asc")
    (tmp_path / "srx.conf").write_text("set security ike proposal P1 dh-group group2\n")
    cbom = _tool(export_cbom)(str(tmp_path))
    names = {c["name"] for c in cbom["components"]}
    assert "FortiOS firmware defaults (FGT60F 7.6.6)" in names
    assert "TLS disabled (tls_disable)" in names
    jsonschema = pytest.importorskip("jsonschema")
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    assert sorted(str(e.message) for e in validator.iter_errors(cbom)) == []


def test_static_rsa_basis_says_a_switch(tmp_path):
    (tmp_path / "fw.conf").write_text(FORTIOS)
    cbom = _tool(export_cbom)(str(tmp_path))
    comp = next(c for c in cbom["components"]
                if c["name"] == "RSA key exchange (static RSA cipher suites)")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:basis"] == "configured_switch"
