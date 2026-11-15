"""Row 440 (06.11.2026, a probe for a LinkedIn reply on 0.44.0): `mech =
os.environ.get("HSM_SIGN_MECH", "RSA-PSS")` gave RSA on line 5 and
`chosen_outside_files.count = 0`; with the default "ML-DSA-65" it gave ML-DSA, still 0. The
default is what runs when nothing is set, so its family stays a finding; the environment can
replace it, so the line is now also a place, with `default` and `overridable: true`.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

HSM = ("import os\n"
       "from pkcs11 import Mechanism\n"
       "\n"
       "def sign(session, key, data):\n"
       '    mech = os.environ.get("HSM_SIGN_MECH", "{default}")\n'
       "    return key.sign(data, mechanism=getattr(Mechanism, mech))\n")


def _check(result, default, family):
    places = result["chosen_outside_files"]["places"]
    assert [(p["line"], p["default"], p["overridable"]) for p in places] == [(5, default, True)]
    assert places[0]["default_family"] == family
    rows = [o for o in result["evidence"]["source_code"] if o["line"] == 5]
    assert family in {o["algorithm"] for o in rows}, rows


def test_a_default_beside_an_env_read_is_a_place_and_a_finding(tmp_path):
    for default, family in (("RSA-PSS", "RSA"), ("ML-DSA-65", "ML-DSA")):
        d = tmp_path / family
        d.mkdir()
        (d / "h.py").write_text(HSM.replace("{default}", default))
        _check(scan_directory(d), default, family)


def test_other_languages_and_non_crypto_defaults(tmp_path):
    (tmp_path / "a.js").write_text('const wrap = process.env.KEY_WRAP ?? "RSA-OAEP";\n')
    (tmp_path / "b.sh").write_text('openssl genpkey -algorithm "${KEY_ALG:-ed25519}" -out k\n')
    (tmp_path / "c.py").write_text('import os\nregion = os.environ.get("AWS_REGION", "us-east-1")\n'
                                   'mode = os.environ.get("UI_MODE", "desktop")\n')
    # Shapes the corpus regression turned up: a path or a command is not an algorithm name,
    # and the classifier alone reads `echo` as EC and `desktop` as DES.
    (tmp_path / "d.sh").write_text('USER_HOME="${HOME:-$(eval echo ~)}"\n'
                                   'PREFIX="${PREFIX:-"$DESTDIR/usr/local"}"\n')
    places = {p["path"]: p for p in scan_directory(tmp_path)["chosen_outside_files"]["places"]}
    assert places["a.js"]["default"] == "RSA-OAEP" and places["a.js"]["overridable"] is True
    assert places["b.sh"]["default"] == "ed25519"
    assert "c.py" not in places and "d.sh" not in places


def test_the_default_leaves_by_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "h.py").write_text(HSM.replace("{default}", "RSA-PSS"))
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()), "RSA-PSS", "RSA")
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)), "RSA-PSS", "RSA")
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        props = {p["name"]: p["value"] for p in b["properties"]}
        assert props["qrp:chosen_outside_files:count"] == "1"
        assert json.loads(props["qrp:chosen_outside_files:overridable_defaults"]) == [
            {"place": "h.py:5", "default": "RSA-PSS", "family": "RSA"}]
