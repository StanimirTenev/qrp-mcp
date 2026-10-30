"""ZA-OPRAVYANE row 157 (Caleb Montour, Magpie Projects): requirements.txt named cryptography,
pycryptodome and paramiko, each "declared, not observed: nothing here says a line of code calls
it" -- while client.py imported and called paramiko. And `provider-payments-sdk`, whose TLS and
signing happen inside, was not named at all. The row now says where the package is imported (an
import is not an algorithm call, so the row stays a declaration), and declared packages the table
does not know are listed as not determined."""

from qrp_mcp.scan import scan_directory


def _tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "requirements.txt").write_text("cryptography==42.0.5\npycryptodome==3.20.0\n"
                                        "paramiko==3.4.0\nprovider-payments-sdk==2.1.0\n")
    (t / "client.py").write_text("import paramiko\ndef connect(h):\n"
                                 "    c = paramiko.SSHClient()\n    c.connect(h)\n")
    (t / "aes.py").write_text("from Crypto.Cipher import AES\n")
    (t / "payments.py").write_text("from provider_sdk import PaymentClient\n")
    return t


def test_imports_join_the_declaration(tmp_path):
    deps = {d["package"]: d for d in scan_directory(_tree(tmp_path))["evidence"]["dependencies"]}
    assert deps["paramiko"]["imported_in"] == ["client.py:1"]
    assert "imported in client.py:1" in deps["paramiko"]["description"]
    assert deps["paramiko"]["basis"] == "declared_dependency"
    assert deps["pycryptodome"]["imported_in"] == ["aes.py:1"]
    assert "imported_in" not in deps["cryptography"]
    assert "Declared, not observed" in deps["cryptography"]["description"]


def test_unknown_declared_package_is_named(tmp_path):
    block = scan_directory(_tree(tmp_path))["dependencies_not_in_table"]
    assert block["count"] == 1
    assert block["packages"] == [{"path": "requirements.txt", "line": 4,
                                  "package": "provider-payments-sdk"}]


def test_npm_import(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "package.json").write_text('{"dependencies": {"node-forge": "1.3.1", "left-pad": "1"}}\n')
    (t / "a.js").write_text("const forge = require('node-forge');\n")
    r = scan_directory(t)
    assert r["evidence"]["dependencies"][0]["imported_in"] == ["a.js:1"]
    assert [p["package"] for p in r["dependencies_not_in_table"]["packages"]] == ["left-pad"]
