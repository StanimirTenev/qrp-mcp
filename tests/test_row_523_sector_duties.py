"""Row 523 (17.11.2026, Meir Goldman, under the post on deadlines; qrp-mcp 0.48.0).

A financial regulator can require a plan or a roadmap of its sector by a date without dating a
single algorithm: Bank of Israel letter 202501 (a plan within a year), FINMA Guidance 05/2026 (a
roadmap by mid-2027), HKMA circular B1/15C (sectoral readiness by 2030), MAS consultation paper
P019-2026 (proposed dates, not in force). They were in `srokove-v-skenera/REGISTAR.md` section 2
and not in `--mandate`, which knew only documents that date code. `--mandate il-boi | ch-finma |
hk-hkma | sg-mas` is a new kind, `sector_duty`: the block names the sector, quotes the duty
exactly as the register does, carries `read_on` like every mandate, and dates no occurrence --
`in_scope` stays 0 and `gate` is `not_applicable`, never counted.

Not claimed: that a repository's owner is in the sector, or that the duty was met. The Bank of
Israel's one year is not turned into a date (7.01.2026 is an inference the register marks И), nor
FINMA's "mid-2027".
"""

import json
import os
import subprocess
import sys
from datetime import date

from qrp_mcp import mandates
from qrp_mcp.scan import scan_directory

# The quotes as REGISTAR.md section 2 has them (П, read 17.11.2026 11:15).
REGISTER = {
    "il-boi": ["…תכנית היערכות זו תועבר … בתוך שנה מיום מכתבי זה"],
    "ch-finma": ["FINMA recommends that a PQC roadmap be drawn up by mid-2027 at the latest."],
    "hk-hkma": ["with the expectation that full sectoral readiness will be achieved by 2030"],
    "sg-mas": ["b) By 31 December 2030 – Complete the migration of critical systems …",
               "c) By 31 December 2034 – … all remaining systems"],
}

RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)\n"


def _result(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.py").write_text(RSA)
    return scan_directory(tmp_path)


def test_each_sector_duty_quotes_the_register_and_dates_nothing(tmp_path):
    result = _result(tmp_path)
    failed = mandates.apply(result, sorted(REGISTER), date(2026, 11, 17), lead_months=1200)
    assert failed is False
    for name, quotes in REGISTER.items():
        block = result["mandates"][name]
        assert block["kind"] == "sector_duty"
        assert [d["quote"] for d in block["duties"]] == quotes
        assert block["read_on"] == "2026-11-17" and block["read_on_age_days"] == 0
        assert block["in_scope"] == 0 and block["gate"] == "not_applicable"
        assert block["sector"] and block["dates_no_occurrence"] is True
    for items in result["evidence"].values():
        for item in items:
            assert not set((item.get("mandates") or {})) & set(REGISTER)


def test_no_inferred_date_is_emitted(tmp_path):
    result = _result(tmp_path)
    mandates.apply(result, ["il-boi", "ch-finma"], date(2026, 11, 17))
    text = json.dumps(result["mandates"], ensure_ascii=False)
    assert "2026-01-07" not in text and "2027-06-30" not in text


def test_mas_is_a_consultation_not_in_force(tmp_path):
    result = _result(tmp_path)
    mandates.apply(result, ["sg-mas"], date(2026, 11, 17))
    block = result["mandates"]["sg-mas"]
    assert block["in_force"] is False
    assert "legally binding obligations" in block["nature"]


def test_beside_a_dated_mandate_that_one_is_unchanged(tmp_path):
    alone = _result(tmp_path / "a")
    mandates.apply(alone, ["eu-pqc-roadmap"], date(2026, 11, 17))
    both = _result(tmp_path / "b")
    mandates.apply(both, ["eu-pqc-roadmap", "il-boi"], date(2026, 11, 17))
    keep = lambda b: {k: v for k, v in b.items() if k != "as_of"}
    assert keep(both["mandates"]["eu-pqc-roadmap"]) == keep(alone["mandates"]["eu-pqc-roadmap"])


def test_the_command_line_takes_it_and_exits_0(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "app.py").write_text(RSA)
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                        str(tmp_path / "t"), "--out", str(out), "--mandate", "ch-finma",
                        "--lead-months", "600", "--as-of", "2026-11-17"],
                       capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["mandates"]["ch-finma"]["gate"] == "not_applicable"


def test_sarif_and_the_config_file_take_it(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "app.py").write_text(RSA)
    sarif = tmp_path / "s.sarif"
    r = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                        str(root), "--format", "sarif", "--out", str(sarif), "--as-of",
                        "2026-11-17", "--mandate", "il-boi", "--mandate", "hk-hkma",
                        "--mandate", "eu-pqc-roadmap"],
                       capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 0, r.stderr
    said = json.loads(sarif.read_text())["runs"][0]["properties"]["mandates"]
    assert said["hk-hkma"]["kind"] == "sector_duty" and said["hk-hkma"]["url"] is None
    assert said["eu-pqc-roadmap"]["in_scope"] >= 1
    (root / ".qrp.toml").write_text('mandate = ["ch-finma"]\n')
    out = tmp_path / "c.json"
    r = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                        str(root), "--out", str(out), "--as-of", "2026-11-17"],
                       capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 0, r.stderr
    assert list(json.loads(out.read_text())["mandates"]) == ["ch-finma"]
