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


# --- places to check: co-location, never a verdict and never a flow --------------------------------

def _places(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["randomness"]["places"]


def test_the_reproduction_gives_its_places(tmp_path):
    places = _places(tmp_path, FAIROUZ)
    got = {(p["path"], p["line"], p["api"], p["link_scope"]) for p in places}
    assert got == {
        ("keys.py", 3, "random.getrandbits", "same_line"),
        ("keys.py", 4, "random.randint", "same_line"),
        ("gen.go", 3, "math/rand.New", "same_line"),
        ("gen.go", 3, "math/rand.NewSource", "same_line"),
    }
    seed = next(p for p in places if p["line"] == 3 and p["path"] == "keys.py")
    assert {"kind": "assigned_to_name", "line": 3, "word": "seed"} in seed["anchors"]
    assert {"kind": "public_key_operation", "line": 7, "family": "EC"} in seed["anchors"]
    go = next(p for p in places if p["api"] == "math/rand.New")
    assert {"kind": "public_key_operation", "line": 3, "family": "ECDSA"} in go["anchors"]
    # Gen.java makes no key: its weak Random is a row, not a place.
    assert not [p for p in places if p["path"] == "Gen.java"]


def test_every_place_says_it_is_co_location_and_not_a_flow(tmp_path):
    places = _places(tmp_path, FAIROUZ)
    assert places and all(p["link"] == "co-location" for p in places)
    for p in places:
        assert "not followed" in p["statement"] and "flow" not in p["statement"].replace(
            "not followed", "")


def test_negative_control_a_csprng_beside_a_key_gives_no_place(tmp_path):
    places = _places(tmp_path, {
        "good.py": ("import secrets, os\nfrom cryptography.hazmat.primitives.asymmetric import ec\n"
                    "seed = secrets.token_bytes(32)\nnonce = os.urandom(12)\n"
                    "priv = ec.generate_private_key(ec.SECP256R1())\n"),
        "good.go": ('package good\n\nimport (\n\t"crypto/ecdsa"\n\t"crypto/elliptic"\n\t"crypto/rand"\n)\n\n'
                    "func K() { seed := make([]byte, 32); rand.Read(seed); "
                    "k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); _ = k }\n"),
        "Good.java": ("import java.security.*;\nclass Good { void f() throws Exception {\n"
                      "  SecureRandom seed = SecureRandom.getInstanceStrong();\n"
                      "  KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n"
                      "  g.initialize(3072, new SecureRandom()); } }\n")})
    assert places == []


def test_a_weak_generator_with_no_key_and_no_key_name_is_no_place(tmp_path):
    assert _places(tmp_path, {"sim.py": "import random\nx = random.random()\n"}) == []


def test_function_scope_in_python(tmp_path):
    places = _places(tmp_path, {"k.py": (
        "import random\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n\n"
        "def make():\n    x = random.random()\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=3072)\n\n"
        "def other():\n    return random.random()\n")})
    scopes = {p["line"]: p["link_scope"] for p in places}
    assert scopes == {5: "same_function", 9: "same_file"}


def test_function_scope_in_a_brace_language(tmp_path):
    places = _places(tmp_path, {"k.go": (
        'package k\n\nimport (\n\t"crypto/ecdsa"\n\t"crypto/elliptic"\n\tcr "crypto/rand"\n'
        '\t"math/rand"\n)\n\n'
        "func Make() *ecdsa.PrivateKey {\n\t_ = rand.Intn(3)\n"
        "\tk, _ := ecdsa.GenerateKey(elliptic.P256(), cr.Reader)\n\treturn k\n}\n\n"
        "func Jitter() int {\n\tif true {\n\t\treturn rand.Intn(9)\n\t}\n\treturn 0\n}\n")})
    scopes = {p["line"]: p["link_scope"] for p in places}
    assert scopes == {11: "same_function", 18: "same_file"}


def test_a_check_generator_beside_a_key_is_a_place(tmp_path):
    places = _places(tmp_path, {"k.cpp": (
        "#include <random>\n#include <openssl/rsa.h>\n"
        "void make(RSA *r, BIGNUM *e) {\n  std::random_device rd;\n"
        "  RSA_generate_key_ex(r, 3072, e, NULL);\n}\n")})
    assert [(p["api"], p["class"], p["link_scope"]) for p in places] == [
        ("std::random_device", "check", "same_function")]


def test_a_place_carries_no_source_text_outside_its_excerpt(tmp_path):
    places = _places(tmp_path, {"k.py": (
        "import random\nmy_secret_seed_zq = random.getrandbits(128)\n")})
    assert len(places) == 1
    text = repr({k: v for k, v in places[0].items() if k not in ("excerpt", "path")})
    assert "zq" not in text and "my_secret" not in text


# --- FIPS 203/204: the requirement named where ML-KEM or ML-DSA meets a visible generator -----------

def _pqc(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["randomness"]["pqc_requirements"]


FIPS_203 = ("These random bytes shall be generated using an approved RBG, as prescribed in SP 800-90A, "
            "SP 800-90B, and SP 800-90C [18, 19, 20]. Moreover, this RBG shall have a security "
            "strength of at least 128 bits for ML-KEM-512, at least 192 bits for ML-KEM-768, and at "
            "least 256 bits for ML-KEM-1024.")


def test_ml_kem_beside_a_weak_generator_names_fips_203(tmp_path):
    reqs = _pqc(tmp_path, {"k.py": (
        "import oqs\nimport random\n\ndef make():\n    seed = random.randbytes(32)\n"
        "    kem = oqs.KeyEncapsulation(\"ML-KEM-1024\")\n    return kem.generate_keypair()\n")})
    assert len(reqs) == 1
    r = reqs[0]
    assert (r["path"], r["line"], r["family"], r["parameter_set"]) == ("k.py", 6, "ML-KEM", "1024")
    assert r["generators"] == [{"line": 5, "class": "weak", "api": "random.randbytes",
                                "link_scope": "same_function"}]
    (req,) = r["requirements"]
    assert (req["document"], req["section"], req["page"], req["level"]) == (
        "FIPS 203", "3.3", "16 (PDF page 25)", "shall")
    assert req["quote"] == FIPS_203 and req["min_strength_bits"] == {"1024": 256}
    assert "named, not checked" in r["statement"]


def test_ml_dsa_names_both_the_seed_and_rnd(tmp_path):
    reqs = _pqc(tmp_path, {"s.py": (
        "import oqs\nimport secrets\n\ndef sign(m):\n    n = secrets.token_bytes(32)\n"
        "    s = oqs.Signature(\"ML-DSA-65\")\n    return s.sign(m)\n")})
    (r,) = reqs
    levels = {(q["applies_to"], q["level"]): q for q in r["requirements"]}
    xi = levels[("ML-DSA.KeyGen, the seed \U0001d709", "shall")]
    assert xi["min_strength_bits"] == {"65": 192} and xi["section"] == "3.6.1"
    assert xi["page"] == "12 (PDF page 22)"
    rnd = levels[("ML-DSA.Sign and HashML-DSA.Sign, hedged, rnd", "should")]
    assert rnd["quote"] == ("While this value should ideally be generated by an approved RBG, other "
                            "methods for generating fresh random values may be used.")
    # A csprng beside ML-DSA: the requirement is named, the generator is not said to meet it.
    assert r["generators"][0]["class"] == "csprng"
    assert "does not establish" in r["statement"]


def test_ml_dsa_44_and_an_unread_parameter_set(tmp_path):
    reqs = _pqc(tmp_path, {
        "a.py": ("import oqs, random\n\ndef f():\n    x = random.random()\n"
                 "    return oqs.Signature(\"ML-DSA-44\")\n"),
        "C.java": ("import java.security.*;\nclass C { void f() throws Exception {\n"
                   "  KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"ML-KEM\", \"BC\");\n"
                   "  SecureRandom r = new SecureRandom(); } }\n")})
    by_path = {r["path"]: r for r in reqs}
    xi44 = [q for q in by_path["a.py"]["requirements"] if q["level"] == "shall"
            and q["applies_to"].startswith("ML-DSA.KeyGen")]
    assert {q["min_strength_bits"]["44"] for q in xi44} == {128}
    assert any(q["level"] == "should" and q.get("min_strength_bits") == {"44": 192}
               for q in by_path["a.py"]["requirements"])
    kem = by_path["C.java"]
    assert kem["parameter_set"] is None
    assert kem["requirements"][0]["min_strength_bits"] == {"512": 128, "768": 192, "1024": 256}


def test_a_generator_elsewhere_in_the_file_names_no_requirement(tmp_path):
    assert _pqc(tmp_path, {"k.py": (
        "import oqs, random\n\ndef a():\n    return random.random()\n\n"
        "def b():\n    return oqs.KeyEncapsulation(\"ML-KEM-768\")\n")}) == []


def test_go_mlkem_with_crypto_rand_is_a_requirement_and_no_place(tmp_path):
    files = {"k.go": ('package k\n\nimport (\n\t"crypto/mlkem"\n\t"crypto/rand"\n)\n\n'
                      "func K() {\n\tb := make([]byte, 32)\n\trand.Read(b)\n"
                      "\tdk, _ := mlkem.GenerateKey768()\n\t_ = dk\n}\n")}
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    section = scan_directory(tmp_path)["randomness"]
    assert section["places"] == []
    (r,) = section["pqc_requirements"]
    assert r["family"] == "ML-KEM" and r["parameter_set"] == "768"
    assert r["generators"] == [{"line": 10, "class": "csprng", "api": "crypto/rand.Read",
                                "link_scope": "same_function"}]


def test_python_imports_are_read_one_statement_at_a_time(tmp_path):
    # An import read on past its line took the next lines for module names (found by the FIPS test).
    calls = _calls(tmp_path, {"a.py": "import oqs\nimport random\n\nx = random.randbytes(8)\n",
                              "b.py": ("from random import (\n    randint,\n    choice as pick,\n)\n"
                                       "from os import urandom\ny = pick([1]) + randint(0, 1)\n"
                                       "z = urandom(8)\n")})
    assert {(c["path"], c["api"], c["class"]) for c in calls} == {
        ("a.py", "random.randbytes", "weak"), ("b.py", "random.choice", "weak"),
        ("b.py", "random.randint", "weak"), ("b.py", "os.urandom", "csprng")}
