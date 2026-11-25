"""Row 556 (25.11.2026, Vikas Dubey; probe `linkedin-postove/2026-11-25/stai/proba/vikas`).

`res/xml/network_security_config.xml` with `<pin-set><pin digest="SHA-256">` was `type_not_claimed`:
`.xml` is read only where it names something this scanner reads (rows 12 and 386). The Android
network security configuration is now one of those, by its root element -- the file's name is the
app's choice, given in the manifest (`android:networkSecurityConfig="@xml/network_security_config"`)
-- and what it configures about the TLS endpoint is read
(https://developer.android.com/privacy-and-security/security-config):

* `<pin-set expiration="...">` with `<pin digest="SHA-256">`: "Certificate pinning is done by
  providing a set of certificates by hash of the public key (SubjectPublicKeyInfo of the X.509
  certificate)"; "Currently, only "SHA-256" is supported". A pin is a hash of a key, so the row names
  no family: the pinned key is not in the file, and a key replaced by a post-quantum one needs the
  pins replaced with it.
* `<trust-anchors><certificates src="@raw/my_ca"/>` ("a raw resource ID pointing to a file containing
  X.509 certificates"), `src="system"`, `src="user"`: a trust store, linked to `res/raw/my_ca.*`
  where that file is read.

Every other `.xml` stays the declared boundary it was.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

CONFIG = "app/src/main/res/xml/network_security_config.xml"
PINS = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2018-01-01">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <!-- backup pin -->
            <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
"""


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _pins(result: dict) -> list[tuple]:
    return [(a["path"], a["line"], a.get("pins"), a.get("pin_digest"), a.get("pin_expiration"))
            for a in result["evidence"]["protocols"] if a.get("basis") == "configured_pin"]


def test_the_file_is_read_and_its_pin_set_is_a_row(tmp_path):
    result = _scan(tmp_path, {CONFIG: PINS})
    assert CONFIG in result["files_read"]
    assert ".xml" not in (result.get("files_skipped_by_type") or {})
    assert _pins(result) == [(CONFIG, 5, 2, "SHA-256", "2018-01-01")]
    row = next(a for a in result["evidence"]["protocols"] if a.get("basis") == "configured_pin")
    assert "algorithm" not in row and "not in this file" in row["description"]


def test_a_pin_set_without_expiration_on_one_line(tmp_path):
    text = ('<network-security-config><domain-config><domain>api.bank.example</domain>'
            '<pin-set><pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>'
            '</pin-set></domain-config></network-security-config>\n')
    assert _pins(_scan(tmp_path, {"res/xml/nsc.xml": text})) == [
        ("res/xml/nsc.xml", 1, 1, "SHA-256", None)]


def test_the_name_is_the_apps_choice(tmp_path):
    result = _scan(tmp_path, {"res/xml/net_config_release.xml": PINS})
    assert [p[1] for p in _pins(result)] == [5]


def test_another_xml_is_still_not_claimed(tmp_path):
    result = _scan(tmp_path, {"res/xml/backup_rules.xml":
                              '<full-backup-content><include domain="sharedpref" path="."/>'
                              '</full-backup-content>\n'})
    assert result["files_skipped_by_type"] == {".xml": 1}


def _trust(result: dict) -> list[tuple]:
    return sorted((p["path"], p["line"], p.get("file"), tuple(p.get("file_read") or []))
                  for p in (result.get("trust_stores") or {}).get("places") or [])


def test_trust_anchors_raw_resource_linked_to_the_file_read(tmp_path):
    result = _scan(tmp_path, {
        "app/src/main/res/xml/network_security_config.xml": (
            '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
            '    <base-config>\n        <trust-anchors>\n'
            '            <certificates src="@raw/extracas"/>\n'
            '            <certificates src="system"/>\n'
            '        </trust-anchors>\n    </base-config>\n</network-security-config>\n'),
        "app/src/main/res/raw/extracas.pem": "not a certificate\n"})
    assert _trust(result) == [
        ("app/src/main/res/xml/network_security_config.xml", 5, "@raw/extracas",
         ("app/src/main/res/raw/extracas.pem",)),
        ("app/src/main/res/xml/network_security_config.xml", 6, "system", ())]


def test_user_store_in_debug_overrides(tmp_path):
    result = _scan(tmp_path, {CONFIG: (
        '<network-security-config>\n  <debug-overrides>\n    <trust-anchors>\n'
        '      <certificates src="user"/>\n    </trust-anchors>\n  </debug-overrides>\n'
        '</network-security-config>\n')})
    assert _trust(result) == [(CONFIG, 4, "user", ())]


def test_cli_and_mcp_carry_the_pin(tmp_path):
    root = tmp_path / "tree"
    _scan(root, {CONFIG: PINS})
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert [p[1:4] for p in _pins(result)] == [(5, 2, "SHA-256")]


def test_cbom_carries_the_pin(tmp_path):
    from qrp_mcp.cyclonedx import build
    cbom = build(_scan(tmp_path, {CONFIG: PINS}))
    names = [c["name"] for c in cbom["components"]]
    assert any("pin" in n.lower() for n in names), names
