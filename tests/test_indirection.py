"""Uses reached through one step of indirection (release E, 05-novi-merki T5).

The metamorphic pilot (5 seeds x 16 rewrites) lost a JS destructured alias, literals
concatenated on one line (Java, JS) and a constant from another file (Java, JS), and kept the
Python and Go aliases only through the import line. Each is resolved on the line, and each
negative below must stay silent.
"""

from qrp_mcp.scan import scan_directory


def _rows(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return {(r["path"], r["line"], r["algorithm"], r["evidence_kind"])
            for r in result["evidence"]["source_code"]}, result


def test_python_alias_call_is_tagged(tmp_path):
    rows, result = _rows(tmp_path, {"app.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa as keyalg\n"
        "key = keyalg.generate_private_key(public_exponent=65537, key_size=2048)\n")})
    assert ("app.py", 2, "RSA", "call") in rows
    row = next(r for r in result["evidence"]["source_code"] if r["line"] == 2)
    assert "read through the alias keyalg for rsa" in row["description"]
    assert row["confidence"] == "medium"
    assert row["excerpt"].startswith("key = keyalg.")


def test_go_alias_call_is_tagged(tmp_path):
    rows, _ = _rows(tmp_path, {"main.go": (
        'package main\n\nimport (\n\t"crypto/rand"\n\tasym "crypto/rsa"\n)\n\n'
        "func main() {\n\tk, _ := asym.GenerateKey(rand.Reader, 2048)\n\t_ = k\n}\n")})
    assert ("main.go", 9, "RSA", "call") in rows


def test_js_destructured_alias(tmp_path):
    rows, _ = _rows(tmp_path, {"app.js": (
        "const { generateKeyPairSync: mk } = require('crypto');\n"
        "const kp = mk('rsa', { modulusLength: 2048 });\n")})
    assert ("app.js", 2, "RSA", "call") in rows


def test_literals_concatenated_on_the_line(tmp_path):
    rows, _ = _rows(tmp_path, {
        "App.java": 'class App { void f() throws Exception {\n'
                    '  java.security.KeyPairGenerator.getInstance("R" + "SA");\n} }\n',
        "app.js": "const crypto = require('crypto');\n"
                  "crypto.generateKeyPairSync('r' + 'sa', { modulusLength: 2048 });\n"})
    assert ("App.java", 2, "RSA", "call") in rows
    assert ("app.js", 2, "RSA", "call") in rows


def test_constant_in_another_file(tmp_path):
    rows, _ = _rows(tmp_path, {
        "App.java": 'class App { void f() throws Exception {\n'
                    '  java.security.KeyPairGenerator.getInstance(Algs.ASYM);\n} }\n',
        "Algs.java": 'final class Algs {\n  static final String ASYM = "RSA";\n}\n',
        "app.js": "const crypto = require('crypto');\nconst { ASYM } = require('./algs');\n"
                  "crypto.generateKeyPairSync(ASYM, { modulusLength: 2048 });\n",
        "algs.js": "module.exports = { ASYM: 'rsa' };\n"})
    assert ("App.java", 2, "RSA", "call") in rows
    assert ("app.js", 3, "RSA", "call") in rows


def test_negatives_stay_silent(tmp_path):
    rows, _ = _rows(tmp_path, {
        # An alias of a module that names no algorithm.
        "a.py": "import numpy as np\nx = np.zeros(3)\n",
        # Literals that do not fold into an algorithm name.
        "b.js": "const s = 'ab' + 'cd';\nconsole.log('x' + 'y');\n",
        # A constant assigned two different values is not guessed between.
        "App.java": 'class App { void f() throws Exception {\n'
                    '  java.security.KeyPairGenerator.getInstance(Two.ALG);\n} }\n',
        "Two.java": 'class Two {\n  static final String ALG = "RSA";\n'
                    '  static final String ALG = "EC";\n}\n',
        # A commented-out aliased call.
        "c.py": "from cryptography.hazmat.primitives.asymmetric import rsa as k\n"
                "# k.generate_private_key(public_exponent=3, key_size=512)\n"})
    assert not [r for r in rows if r[0] in ("a.py", "b.js", "App.java")]
    assert [r for r in rows if r[0] == "c.py" and r[3] not in ("comment", "import")] == []


def test_a_constant_outside_the_tree_is_not_read(tmp_path):
    inner = tmp_path / "repo"
    inner.mkdir()
    (tmp_path / "algs.js").write_text("module.exports = { ASYM: 'rsa' };\n")
    rows, _ = _rows(inner, {"app.js": "const crypto = require('crypto');\n"
                                      "const { ASYM } = require('../algs');\n"
                                      "crypto.generateKeyPairSync(ASYM, {});\n"})
    assert ("app.js", 3, "RSA", "call") not in rows
