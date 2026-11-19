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


# --- what a code scan cannot know about randomness, and the counts ----------------------------------

def test_the_not_read_block_names_what_the_code_cannot_show(tmp_path):
    (tmp_path / "a.py").write_text("import random\nx = random.random()\n")
    block = scan_directory(tmp_path)["randomness"]["not_read"]
    text = " ".join(block["what"]).lower()
    for words in ("boot", "virtual machine", "container", "hsm", "pkcs#11", "injected",
                  "configuration", "environment", "statistical"):
        assert words in text, words
    assert "no entropy is estimated" in block["meaning"]


def test_counts_seen_and_classified(tmp_path):
    (tmp_path / "a.py").write_text(
        "import random, secrets\nx = random.random()\ny = secrets.token_hex(8)\n"
        "z = custom_random_source()\nw = rng_draw(3)\nv = operand(2)\n")
    (tmp_path / "S.java").write_text(
        "import java.security.SecureRandom;\nclass S { Object f(String n) throws Exception {"
        " return SecureRandom.getInstance(n); } }\n")
    counts = scan_directory(tmp_path)["randomness"]["counts"]
    assert counts["calls_classified"] == 3
    assert counts["by_class"] == {"weak": 1, "csprng": 1, "check": 1}
    # The two names with a randomness word that no spelling classifies; `operand` has none.
    assert counts["calls_seen"] == 5
    assert counts["calls_seen_not_classified"] == 2
    assert counts["chosen_at_run_time"] == 1


def test_out_of_scope_says_where_randomness_now_is(tmp_path):
    (tmp_path / "a.py").write_text("import random\nx = random.random()\n")
    said = scan_directory(tmp_path)["coverage"]["claims"]["out_of_scope_by_design"]
    rng = next(w for w in said["what"] if "random number generation" in w)
    assert "`randomness`" in rng and "not findings" in rng
    # Row 531 b: the one place a generator is read for a size is said, not hidden.
    assert "os.urandom(n)" in rng and "symmetric key" in rng


# --- masked and trimmed: no source text leaves in the new fields, on any of the three exits ---------

CANARY = "zqcanary"
CANARY_TREE = {
    "k.py": ("import oqs, random\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\n"
             "def make():\n"
             f"    seed_{CANARY} = random.getrandbits(256)  # {CANARY}\n"
             f"    kem = oqs.KeyEncapsulation(\"ML-KEM-768\")  # {CANARY}\n"
             "    return ec.generate_private_key(ec.SECP256R1()), kem\n"),
    "S.java": ("import java.security.SecureRandom;\nclass S { Object f() throws Exception {"
               f" return SecureRandom.getInstance(\"{CANARY}PRNG\"); }} }}\n"),
}


def _canary_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "t"
    for name, text in CANARY_TREE.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text)
    return tree


@pytest.mark.parametrize("level", ["masked", "trimmed"])
def test_no_source_text_in_the_scan_file(tmp_path, level):
    import json
    from qrp_mcp.server import main
    tree = _canary_tree(tmp_path)
    out = tmp_path / "r.json"
    with pytest.raises(SystemExit):
        main(["scan", str(tree), "--no-config", "--level", level, "--out", str(out)])
    result = json.loads(out.read_text())
    section = result["randomness"]
    assert section["calls"] and section["places"] and section["pqc_requirements"]
    assert CANARY not in json.dumps(section)
    assert CANARY not in out.read_text()
    if level == "trimmed":
        assert not any("excerpt" in r for r in section["calls"] + section["places"])


@pytest.mark.parametrize("level", ["masked", "trimmed"])
def test_no_source_text_through_the_tools(tmp_path, level):
    import json
    from qrp_mcp.server import export_cbom, scan_repo
    tree = _canary_tree(tmp_path)
    assert CANARY not in json.dumps(scan_repo(str(tree), level=level))
    assert CANARY not in json.dumps(export_cbom(str(tree), level=level))


def test_the_full_level_still_quotes_the_line(tmp_path):
    import json
    from qrp_mcp.server import scan_repo
    section = scan_repo(str(_canary_tree(tmp_path)), level="full")["randomness"]
    assert CANARY in json.dumps(section["calls"])
    # Even at full, a name that is not a standard one is not copied into a field.
    java = next(c for c in section["calls"] if c["path"] == "S.java")
    assert java["algorithm"] == "not_a_standard_name"
    assert CANARY not in json.dumps({k: v for k, v in java.items() if k != "excerpt"})


# --- the CBOM: our own properties, and `drbg` only where the family is read -------------------------

CBOM_TREE = {
    "keys.py": FAIROUZ["keys.py"],
    "drbg.c": ('#include <openssl/evp.h>\n#include <openssl/rand.h>\n'
               'EVP_RAND *get(void) { return EVP_RAND_fetch(NULL, "CTR-DRBG", NULL); }\n'
               "int fill(unsigned char *b) { return RAND_bytes(b, 32); }\n"),
    "S.java": ("import java.security.SecureRandom;\nclass S { Object f() throws Exception {"
               " return SecureRandom.getInstance(\"DRBG\"); } }\n"),
}


def _cbom(tmp_path: Path) -> dict:
    from qrp_mcp import cyclonedx
    for name, text in CBOM_TREE.items():
        (tmp_path / name).write_text(text)
    return cyclonedx.build(scan_directory(tmp_path))


def test_the_cbom_carries_rows_places_and_counts_as_properties(tmp_path):
    import json
    props = {p["name"]: p["value"] for p in _cbom(tmp_path)["properties"]}
    calls = json.loads(props["qrp:randomness:calls"])
    assert {"location": "keys.py", "line": 3, "class": "weak", "api": "random.getrandbits"} in calls
    assert not any("excerpt" in c for c in calls)
    places = json.loads(props["qrp:randomness:places"])
    assert {(p["location"], p["line"], p["link"], p["link_scope"]) for p in places} == {
        ("keys.py", 3, "co-location", "same_line"), ("keys.py", 4, "co-location", "same_line")}
    assert props["qrp:randomness:calls_classified"] == str(len(calls))
    assert "qrp:randomness:calls_seen" in props


def test_a_drbg_component_only_where_its_family_is_read(tmp_path):
    bom = _cbom(tmp_path)
    drbg = [c for c in bom["components"]
            if c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive") == "drbg"]
    assert [c["name"] for c in drbg] == ["CTR_DRBG"]
    (component,) = drbg
    assert component["evidence"]["occurrences"] == [{"location": "drbg.c", "line": 3}]
    # A weak generator is never a component; neither is a csprng whose mechanism is not named.
    names = {c["name"] for c in bom["components"]}
    assert not names & {"random.getrandbits", "os.urandom", "DRBG", "RAND_bytes"}
    assert component["bom-ref"] in bom["compositions"][0]["assemblies"]


def test_the_cbom_stays_valid_cyclonedx_1_6(tmp_path):
    import json
    jsonschema = pytest.importorskip("jsonschema")
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    assert sorted(str(e.message) for e in validator.iter_errors(_cbom(tmp_path))) == []


# --- hostile lines: one row per API on a line, and the shapes that were quadratic --------------------

def test_a_line_of_a_thousand_calls_is_one_row_per_api(tmp_path):
    (tmp_path / "a.c").write_text("#include <stdlib.h>\nint f(void) { return " + "rand() + " * 1000
                                  + "srand(1); }\n")
    section = scan_directory(tmp_path)["randomness"]
    assert [(c["line"], c["api"]) for c in section["calls"]] == [(2, "rand"), (2, "srand")]
    # The other 999 are the same API on the same line: covered, not "seen, not classified".
    assert section["counts"]["calls_seen_not_classified"] == 0


@pytest.mark.parametrize("name, line", [
    ("q.js", '"' + '\\"' * 20000 + " Math.random()"),         # an escaped quote left open
    ("b.c", "/*" * 20000 + " rand();"),                         # block comments left open
    ("d.go", "{" * 20000),                                      # nesting, no closing brace
    ("p.php", "rand(); " * 20000),                              # a declaration looked for each call
    ("n.js", "a = " * 20000 + "Math.random();"),                # an assignment looked for each call
], ids=["escaped-quotes", "open-comments", "nesting", "php-calls", "assignments"])
def test_hostile_lines_finish(tmp_path, name, line):
    import time
    head = 'package d\nimport "math/rand"\nimport "crypto/ecdsa"\n' if name.endswith(".go") else ""
    tail = "\nfunc F() { _ = rand.Intn(2); ecdsa.GenerateKey(nil, nil) }\n" if head else "\n"
    (tmp_path / name).write_text(head + ("<?php\n" if name.endswith(".php") else "") + line + tail)
    started = time.monotonic()
    scan_directory(tmp_path)
    assert time.monotonic() - started < 20


# --- the second look before the review (19.11): loops, Go import comments, cross products -----------

def test_a_for_loop_or_a_go_if_init_is_not_a_function(tmp_path):
    places = _places(tmp_path, {
        "K.java": ("import java.util.Random;\nimport java.security.KeyPairGenerator;\n"
                   "class K {\n  void make() throws Exception {\n    Random r = new Random();\n"
                   "    for (int i = 0; i < 3; i++) {\n"
                   "      KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n    }\n  }\n}\n"),
        "k.go": ('package k\n\nimport (\n\t"crypto/ecdsa"\n\t"crypto/elliptic"\n\tcr "crypto/rand"\n'
                 '\t"math/rand"\n)\n\nfunc Make() {\n\t_ = rand.Intn(3)\n'
                 "\tif k, err := ecdsa.GenerateKey(elliptic.P256(), cr.Reader); err == nil {\n"
                 "\t\t_ = k\n\t}\n}\n")})
    assert {(p["path"], p["link_scope"]) for p in places} == {("K.java", "same_function"),
                                                               ("k.go", "same_function")}


def test_a_comment_above_a_go_import_is_not_its_alias(tmp_path):
    calls = _calls(tmp_path, {"j.go": ('package j\n\nimport (\n\t// seeded jitter\n\t"math/rand"\n)\n\n'
                                       "func J() int { return rand.Intn(9) }\n")})
    assert [(c["api"], c["class"]) for c in calls] == [("math/rand.Intn", "weak")]


def test_anchors_and_generators_are_capped_with_their_count(tmp_path):
    lines = ["import oqs, random", "from cryptography.hazmat.primitives.asymmetric import ec", "",
             "def f():"]
    for _ in range(300):
        lines += ["    x = random.random()", "    k = ec.generate_private_key(ec.SECP256R1())",
                  "    m = oqs.KeyEncapsulation(\"ML-KEM-768\")"]
    (tmp_path / "a.py").write_text("\n".join(lines) + "\n")
    section = scan_directory(tmp_path)["randomness"]
    place = section["places"][0]
    # Each line of `k = ec...` and `m = oqs...` is a public-key call row: 600 anchors.
    assert len(place["anchors"]) <= 3 and place["anchors_count"] == 600
    req = section["pqc_requirements"][0]
    assert len(req["generators"]) <= 3 and req["generators_count"] == 300


@pytest.mark.parametrize("name, line", [
    ("c.c", "/* x */ " * 30000 + " rand();"),                   # closed comments, one after another
    ("w.py", "import random\nx = " + "rand" * 60000 + " + random.random()"),  # a word run, no `(`
], ids=["closed-comments", "word-run"])
def test_more_hostile_lines_finish(tmp_path, name, line):
    import time
    (tmp_path / name).write_text(line + "\n")
    started = time.monotonic()
    calls = scan_directory(tmp_path)["randomness"]["calls"]
    assert time.monotonic() - started < 20
    assert calls


def test_the_meanings_state_the_limits(tmp_path):
    (tmp_path / "a.py").write_text("import random\nx = random.random()\n")
    section = scan_directory(tmp_path)["randomness"]
    assert "named, not checked" in section["pqc_requirements_meaning"]
    assert "decapsulation, verification or a parameter name" in section["pqc_requirements_meaning"]
    assert "co-location" in section["places_meaning"] and "not a verdict" in section["places_meaning"]
    assert "one row per generator API on a line" in section["meaning"]


def test_a_line_of_open_braces_finishes(tmp_path):
    import time
    (tmp_path / "d.go").write_text('package d\nimport "math/rand"\nimport "crypto/ecdsa"\n' + "{" * 1000000
                                   + "\nfunc F() { _ = rand.Intn(2); ecdsa.GenerateKey(nil, nil) }\n")
    started = time.monotonic()
    places = scan_directory(tmp_path)["randomness"]["places"]
    assert time.monotonic() - started < 20 and places
