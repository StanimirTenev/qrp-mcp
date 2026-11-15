"""ZA-OPRAVYANE row 487: the CBOM recorded the absolute path of the scanned folder.

Own probe while preparing the letter to Shivansh (`linkedin-postove/2026-11-15/`): regenerating
`docs/examples/h5bp-server-configs-nginx.cbom.json` with 0.46.0 gave
`qrp:coverage:corpus:target` = the absolute path on this machine. Two CBOMs of one commit made
on two machines were never the same bytes, though `qrp:findings_fingerprint:sha256` was, and
the published sample carried a local path.

The CBOM now records the folder's own name there, as `metadata.component` already did (row
430), and says so in `qrp:coverage:corpus:target_basis`. The scan JSON keeps the absolute path
(`coverage.corpus.target`): SARIF's SRCROOT and compare_coverage read it from there.
"""

import json
import shutil

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory


def _tree(parent):
    t = parent / "server-configs-nginx"
    t.mkdir(parents=True)
    (t / "tls.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519;\n")
    (t / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                            "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    return t


def _props(doc):
    return {p["name"]: p["value"] for p in doc["properties"]}


def test_cbom_target_is_the_folder_name_not_the_absolute_path(tmp_path):
    t = _tree(tmp_path / "machine-one" / "deep")
    for doc in (cyclonedx.build(scan_directory(t)), server.export_cbom(str(t))):
        props = _props(doc)
        assert props["qrp:coverage:corpus:target"] == "server-configs-nginx"
        assert "absolute path" in props["qrp:coverage:corpus:target_basis"]
        # The local path is nowhere in the document.
        assert str(tmp_path) not in json.dumps(doc)


def test_cbom_from_two_places_is_the_same_bytes(tmp_path):
    first = _tree(tmp_path / "one")
    second = tmp_path / "two" / "elsewhere" / "server-configs-nginx"
    second.parent.mkdir(parents=True)
    shutil.copytree(first, second)
    a = json.dumps(cyclonedx.build(scan_directory(first)), sort_keys=True)
    b = json.dumps(cyclonedx.build(scan_directory(second)), sort_keys=True)
    assert a == b


def test_cli_cbom_carries_no_local_path(tmp_path):
    t = _tree(tmp_path / "x")
    out = tmp_path / "r.cbom.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    text = out.read_text()
    assert str(tmp_path) not in text
    assert _props(json.loads(text))["qrp:coverage:corpus:target"] == "server-configs-nginx"


def test_scan_json_keeps_the_absolute_path(tmp_path):
    t = _tree(tmp_path / "y")
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(t), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["coverage"]["corpus"]["target"] == str(t)
