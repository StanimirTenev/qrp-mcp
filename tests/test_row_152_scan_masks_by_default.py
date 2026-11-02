"""ZA-OPRAVYANE row 152 (stranica-bezplaten-otchet, 27.10.2026; decided by Stanimir on
2 Nov 2026): `qrp-mcp scan --out` wrote every quoted line whole by default, while `cbom` has
masked since 0.16.0 and the scan_repo tool masks too. The file a customer sends for the free
report is exactly `scan --out` (qrp-dora `--from-scan`). The default is now `masked`, as for
`cbom`; `--level full` and a `.qrp.toml` level still give the line as written."""

import json
import subprocess
import sys

LINE = 'key = rsa.generate_private_key(65537, 2048)  # secret-token-abc123'


def _scan(tmp_path, *extra, toml=None):
    tree = tmp_path / "t"
    tree.mkdir(exist_ok=True)
    (tree / "a.py").write_text(LINE + "\n", encoding="utf-8")
    if toml is not None:
        (tree / ".qrp.toml").write_text(toml, encoding="utf-8")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out), *extra], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    result = json.loads(out.read_text())
    return result, [e["excerpt"] for e in result["evidence"]["source_code"]]


def test_the_default_is_masked(tmp_path):
    result, excerpts = _scan(tmp_path)
    assert result["excerpt_level"] == "masked"
    assert excerpts and all("secret" not in e and "2048" not in e for e in excerpts)


def test_level_full_still_gives_the_line(tmp_path):
    result, excerpts = _scan(tmp_path, "--level", "full")
    assert result["excerpt_level"] == "full"
    assert excerpts == [LINE]


def test_the_config_file_level_still_wins_over_the_default(tmp_path):
    result, excerpts = _scan(tmp_path, toml='level = "full"\n')
    assert result["excerpt_level"] == "full"
    assert excerpts == [LINE]


def test_the_help_says_the_default(tmp_path):
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", "--help"],
                       capture_output=True, text=True)
    assert "else masked" in " ".join(r.stdout.split())
