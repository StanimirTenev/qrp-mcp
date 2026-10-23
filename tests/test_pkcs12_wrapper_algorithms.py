"""PKCS#12's own algorithms, from the unencrypted wrapper (ZA-OPRAVYANE row 85, swarm C of
22.10.2026, `roy-2026-10-22/c-korpus` test_c7: spring-security-samples' .p12 files with
40-bit RC2 and a SHA-1 MAC, read as only "claimed_but_not_decoded").

The fixture is the swarm's own keystore (fixtures/r7-p12-legacy, written by keytool/openssl,
no repository file copied): bags under pbeWithSHAAnd40BitRC2-CBC and
pbeWithSHAAnd3-KeyTripleDES-CBC, MAC sha1 (`openssl pkcs12 -info`: "MAC: sha1"). The OIDs are
RFC 7292's pkcs-12PbeIds.
"""

import base64
from pathlib import Path

from qrp_mcp.scan import scan_directory

FIXTURE = Path(__file__).parent / "fixtures" / "legacy-pbe.p12.b64"
SHROUDED = Path(__file__).parent / "fixtures" / "shrouded.p12.b64"


def _scan(tmp_path, fixture):
    (tmp_path / "keystore.p12").write_bytes(base64.b64decode(fixture.read_text()))
    return scan_directory(tmp_path)


def test_legacy_pbe_and_mac_are_named(tmp_path):
    result = _scan(tmp_path, FIXTURE)
    assert {"RC2", "3DES", "SHA1"} <= set(result["detected_algorithms"])
    rc2 = next(f for f in result["findings"] if f["algorithm_family"] == "RC2")
    assert rc2["classification"] == "deprecated_weak"


def test_the_contents_are_still_not_decoded(tmp_path):
    # The wrapper was read; the bags were not. The file says both.
    result = _scan(tmp_path, FIXTURE)
    assert "keystore.p12" in result["claimed_but_not_decoded"]


def test_the_shrouded_key_is_still_reported(tmp_path):
    result = _scan(tmp_path, SHROUDED)
    assert result["evidence"]["embedded_keys"]
