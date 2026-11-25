"""`action.yml`: the GitHub Action runs the real `scan` command, pinned to this release.

The action is a composite step that installs qrp-mcp with uvx at this release and runs
`qrp-mcp scan PATH --format sarif --out FILE --level LEVEL`. Nothing in it is checked by
GitHub until someone runs it, so the command it holds is checked here against the CLI itself:
every flag and value it passes must be one `qrp-mcp scan` accepts, the same arguments must
write SARIF 2.1.0, and the pin must be the version in pyproject.toml (a pin that lags the
release runs an old scanner). PyYAML is not a dependency, so the file is read as text.
"""
import json
import re
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the declared tomli backport
    import tomli as tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"


def _version():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def _scan_line():
    """The one line of action.yml that runs the scan, split into words."""
    lines = [ln.strip() for ln in ACTION.read_text().splitlines() if " scan " in ln and "uvx" in ln]
    assert len(lines) == 1, lines
    return lines[0].split()


def _help():
    return subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", "--help"],
                          capture_output=True, text=True, check=True).stdout


def _inputs():
    """Names declared under `inputs:` and their defaults."""
    text = ACTION.read_text()
    block = re.search(r"^inputs:\n((?:  .*\n|\n)*)", text, re.M).group(1)
    names = re.findall(r"^  ([a-z][a-z-]*):\s*$", block, re.M)
    defaults = dict(re.findall(r"^  ([a-z][a-z-]*):\s*\n(?:    .*\n)*?    default:\s*\"?([^\"\n]*)\"?", block, re.M))
    return names, defaults


def test_the_action_is_composite_and_pins_the_release():
    text = ACTION.read_text()
    assert re.search(r"^  using:\s*\"?composite\"?\s*$", text, re.M), "not a composite action"
    words = _scan_line()
    assert words[:3] == ["uvx", "--from", f"qrp-mcp=={_version()}"], words


def test_every_flag_and_value_is_one_scan_accepts():
    words = _scan_line()
    assert words[3:5] == ["qrp-mcp", "scan"], words
    flags = [w for w in words if w.startswith("--") and w != "--from"]
    assert flags, words
    usage = _help()
    for flag in flags:
        assert re.search(rf"\[{re.escape(flag)}[ \]]", usage), f"{flag} is not a flag of `qrp-mcp scan`"
    assert words[words.index("--format") + 1] == "sarif"
    names, defaults = _inputs()
    level_choices = re.search(r"--level \{([a-z,]+)\}", usage).group(1).split(",")
    assert defaults["level"] in level_choices, defaults
    # Every input the command reads is declared, and passed through env, not ${{ }} in `run:`.
    for word in words:
        assert "${{" not in word, word
    for name in re.findall(r"\$\{?QRP_([A-Z_]+)", " ".join(words)):
        assert name.lower().replace("_", "-") in names, (name, names)


def test_the_same_arguments_write_sarif(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                 "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    out = tmp_path / "out.sarif"
    _, defaults = _inputs()
    values = {"PATH": str(tree), "OUTPUT": str(out), "LEVEL": defaults["level"]}
    words = _scan_line()[5:]
    args = [re.sub(r"^\"?\$\{?QRP_([A-Z_]+)\}?\"?$", lambda m: values[m.group(1)], w) for w in words]
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", *args],
                   capture_output=True, text=True, check=True)
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], doc["runs"][0]


def test_the_readme_example_uses_the_same_release():
    readme = (ROOT / "README.md").read_text()
    uses = re.findall(r"uses: StanimirTenev/qrp-mcp@(\S+)", readme)
    assert uses == [f"v{_version()}"], uses
