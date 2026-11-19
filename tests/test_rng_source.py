"""Operation `rng_source` (ZA-OPRAVYANE rows 531, 539; rng-prouchvane/02-dizajn.md): the generator a
line calls, in three classes, as context outside the findings. The documented spellings are in
data/operations/rng_source.toml and run in test_operation_closure.py; these are the resolution traps
around them, each a line that must not be read as the generator it resembles."""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory


def _calls(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["randomness"]["calls"]


def _apis(calls: list[dict]) -> set[tuple[str, str]]:
    return {(c["api"], c["class"]) for c in calls}


@pytest.mark.parametrize("name, text", [
    # C: a word ending in rand, a member, OpenSSL's names, arc4random.
    ("a.c", "int f(int operand) { return operand(); }\n"),
    ("b.c", "int f(struct s *p) { return p->rand(); }\n"),
    ("c.c", "#include <openssl/rand.h>\nint f(unsigned char *b) { return RAND_bytes(b, 8); }\n"),
    ("d.c", "#include <stdlib.h>\nunsigned f(void) { return arc4random(); }\n"),
    # Java: SecureRandom is not Random; a Random that java.util does not supply.
    ("E.java", "import java.security.SecureRandom;\nclass E { Object f() { return new SecureRandom(); } }\n"),
    ("F.java", "import com.example.Random;\nclass F { Object f() { return new Random(); } }\n"),
    # Python: a name nobody imported; a module of the same name from elsewhere.
    ("g.py", "def f(random):\n    return random.random()\n"),
    ("h.py", "from mylib import random\nx = random.randint(1, 2)\n"),
    # Comments and strings.
    ("i.py", "import random\n# x = random.random()\ns = 'random.random()'\n"),
    ("j.js", "// Math.random() is not used here\nconst s = \"Math.random()\";\n"),
    # PHP: a declaration and a method are not the function.
    ("k.php", "<?php\nfunction rand() { return 4; }\n$x = $obj->rand();\n$y = Foo::rand();\n"),
    # Go: crypto/rand under the name rand is not math/rand.
    ("l.go", "package l\n\nimport \"crypto/rand\"\n\nfunc F(b []byte) { rand.Read(b) }\n"),
])
def test_a_line_that_resembles_a_weak_generator_is_not_one(tmp_path, name, text):
    weak = [c for c in _calls(tmp_path, {name: text}) if c["class"] == "weak"]
    assert not weak, weak


def test_go_aliases_are_resolved_per_import(tmp_path):
    calls = _calls(tmp_path, {"m.go": (
        'package m\n\nimport (\n\tcrand "crypto/rand"\n\t"math/rand"\n)\n\n'
        "func F(b []byte) int { crand.Read(b); return rand.Intn(9) }\n")})
    assert _apis(calls) == {("crypto/rand.Read", "csprng"), ("math/rand.Intn", "weak")}


def test_a_java_random_is_read_with_its_import_or_qualified_name(tmp_path):
    calls = _calls(tmp_path, {
        "A.java": "import java.util.*;\nclass A { Object f() { return new Random(); } }\n",
        "B.java": "class B { Object f() { return new java.util.Random(7); } }\n"})
    assert {(c["path"], c["class"]) for c in calls} == {("A.java", "weak"), ("B.java", "weak")}


def test_dotnet_random_is_not_read_in_a_java_file(tmp_path):
    calls = _calls(tmp_path, {"R.java": "class R { Object f() { return Random.Shared; } }\n"})
    assert not calls


def test_rows_carry_the_ecosystem_and_whether_they_are_test_code(tmp_path):
    calls = _calls(tmp_path, {"tests/test_x.py": "import random\nx = random.random()\n",
                              "src/y.js": "const r = Math.random();\n"})
    by_path = {c["path"]: c for c in calls}
    assert by_path["tests/test_x.py"]["ecosystem"] == "Py"
    assert by_path["tests/test_x.py"]["in_test_code"] is True
    assert by_path["src/y.js"]["ecosystem"] == "JS"
    assert by_path["src/y.js"]["in_test_code"] is False


def test_randomness_moves_neither_the_findings_nor_their_fingerprint(tmp_path, monkeypatch):
    (tmp_path / "keys.py").write_text(
        "import random\nfrom cryptography.hazmat.primitives.asymmetric import ec\n"
        "seed = random.getrandbits(256)\npriv = ec.generate_private_key(ec.SECP256R1())\n")
    with_it = scan_directory(tmp_path)
    from qrp_mcp import randomness
    monkeypatch.setattr(randomness, "section", lambda result, root: None)
    without = scan_directory(tmp_path)
    assert with_it["randomness"]["calls"] and without.get("randomness") is None
    assert with_it["findings_fingerprint"] == without["findings_fingerprint"]
    assert with_it["findings"] == without["findings"]
    assert with_it["evidence"] == without["evidence"]


# --- the ecosystem status (the per-tree rule of 0.51.0) ---------------------------------------------

def _eco(result: dict, name: str) -> dict:
    return next(e for e in result["ecosystems"]["present"] if e["ecosystem"] == name)


_GO_NO_RNG = {"cmd/main.go": 'package main\nimport "crypto/rsa"\nfunc main() { _ = rsa.GenerateKey }\n'}


def test_a_tree_without_a_generator_keeps_its_status(tmp_path):
    for name, text in _GO_NO_RNG.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    go = _eco(scan_directory(tmp_path), "Go")
    assert go["status"] == "not_closed" and "rng_source" not in go["known_operations"]


def test_a_generator_row_counts_where_the_tree_has_one(tmp_path):
    files = {**_GO_NO_RNG, "cmd/jitter.go": 'package main\nimport "math/rand"\n'
                                            "func j() int { return rand.Intn(9) }\n"}
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    go = _eco(scan_directory(tmp_path), "Go")
    assert go["status"] == "partially_closed"
    assert go["closed_operations"] == ["rng_source"] and go["open_operations"] == ["external"]


def test_a_generator_only_in_test_code_does_not_move_the_status(tmp_path):
    files = {**_GO_NO_RNG, "cmd/jitter_test.go": 'package main\nimport "math/rand"\n'
                                                 "func j() int { return rand.Intn(9) }\n"}
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    go = _eco(scan_directory(tmp_path), "Go")
    assert go["status"] == "not_closed" and "rng_source" not in go["known_operations"]


def test_rng_source_is_a_recorded_gap_of_the_seven_ecosystems():
    from qrp_mcp.adaptive import KNOWN_OPERATIONS
    assert {e for e, ops in KNOWN_OPERATIONS.items() if "rng_source" in ops} == {
        "Py", "Go", "Java", "JS", "C", "NET", "PHP"}


# --- the reproduction from LinkedIn (19.11.2026, fairouz/proba/repo), byte for byte ------------------

FAIROUZ = {
    "keys.py": ("import random, secrets, os\n"
                "from cryptography.hazmat.primitives.asymmetric import ec\n"
                "seed = random.getrandbits(256)          # weak\n"
                "nonce = random.randint(0, 2**64)        # weak\n"
                "good = secrets.token_bytes(32)\n"
                "key = os.urandom(32)\n"
                "priv = ec.generate_private_key(ec.SECP256R1())\n"),
    "gen.go": ('package main\n'
               'import ("math/rand"; "crypto/ecdsa"; "crypto/elliptic"; crand "crypto/rand")\n'
               "func main(){ r := rand.New(rand.NewSource(42)); _ = r.Int63(); "
               "k,_ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader); _ = k }\n"),
    "Gen.java": ("import java.util.Random; import java.security.SecureRandom;\n"
                 "class Gen { void f() throws Exception { Random r = new Random(); "
                 "SecureRandom s = SecureRandom.getInstance(\"SHA1PRNG\"); } }\n"),
}


def test_the_reproduction_gives_its_rows(tmp_path):
    calls = _calls(tmp_path, FAIROUZ)
    got = {(c["path"], c["line"], c["api"], c["class"]) for c in calls}
    assert got == {
        ("keys.py", 3, "random.getrandbits", "weak"),
        ("keys.py", 4, "random.randint", "weak"),
        ("keys.py", 5, "secrets.token_bytes", "csprng"),
        ("keys.py", 6, "os.urandom", "csprng"),
        ("gen.go", 3, "math/rand.New", "weak"),
        ("gen.go", 3, "math/rand.NewSource", "weak"),
        ("gen.go", 3, "crypto/rand.Reader", "csprng"),
        ("Gen.java", 2, "java.util.Random", "weak"),
        ("Gen.java", 2, "java.security.SecureRandom.getInstance", "csprng"),
    }
    sha1prng = next(c for c in calls if c["path"] == "Gen.java" and c["class"] == "csprng")
    assert sha1prng["algorithm"] == "SHA1PRNG" and "why" not in sha1prng
    assert next(c for c in calls if c["api"] == "math/rand.NewSource")["seed"] == "literal"

