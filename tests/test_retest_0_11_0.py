"""The findings of an external retest of 0.11.0, pinned as regressions.

Each test is the auditor's own probe and their acceptance criterion, not a
paraphrase. They were all reproduced here before anything was changed.

The through-line of R01 to R03: a label was decided for a whole line, so a word
in a comment governed the code beside it. A rule that hides cryptography is the
same defect as a rule that invents it.
"""

import copy
import json

import pytest

from qrp_mcp import coverage, detectors
from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, body):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / name).write_text(body, encoding="utf-8")
    return scan_directory(repo)


# --- R01 · a denial word must not hide a call -------------------------------

@pytest.mark.parametrize("body", [
    "weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n",
    "key = rsa.generate_private_key(key_size=1024)  # weak key used for compatibility\n",
    "if allow_weak:\n    key = rsa.generate_private_key(key_size=1024)\n",
])
def test_a_variable_named_weak_is_not_a_ban(tmp_path, body):
    """`weak` describes a risk. It does not prohibit anything, and naming a
    variable honestly made this scanner drop the key it was there to find."""
    result = _scan(tmp_path, "app.py", body)
    assert "RSA" in result["detected_algorithms"]
    assert result["algorithm_key_sizes"].get("RSA") == 1024


def test_a_real_denial_list_is_still_a_ban(tmp_path):
    result = _scan(tmp_path, "java.properties",
                   "jdk.tls.disabledAlgorithms=RSA keySize < 2048, DSA\n")
    assert result["detected_algorithms"] == []


def test_a_banned_ciphers_collection_is_still_a_ban(tmp_path):
    result = _scan(tmp_path, "policy.py", 'BANNED_CIPHERS = ["RSA", "DSA"]\n')
    assert result["detected_algorithms"] == []


def test_a_struck_out_entry_is_still_a_ban(tmp_path):
    result = _scan(tmp_path, "sshd_config", "HostKeyAlgorithms -ssh-dss\n")
    assert "DSA" not in result["detected_algorithms"]


# --- R02 · comments and strings, by language and by position ----------------

def test_a_block_marker_inside_a_python_string_opens_nothing(tmp_path):
    """`marker = "/*"` silenced every call beneath it, in a language that has no
    block comments at all."""
    result = _scan(tmp_path, "app.py",
                   'marker = "/*"\nkey = rsa.generate_private_key(key_size=2048)\n')
    assert "RSA" in result["detected_algorithms"]


def test_a_call_written_inside_a_comment_is_not_a_use(tmp_path):
    result = _scan(tmp_path, "app.py", "x = 1  # rsa.generate_private_key(key_size=1024)\n")
    assert result["detected_algorithms"] == []
    assert "RSA" in result["named_but_not_used"]


def test_a_block_comment_still_works_where_the_language_has_one(tmp_path):
    result = _scan(tmp_path, "app.c", "/* RSA_generate_key(1024, 3, NULL, NULL); */\n")
    assert result["detected_algorithms"] == []


def test_a_trailing_comment_does_not_hide_the_code_before_it(tmp_path):
    result = _scan(tmp_path, "app.c",
                   "RSA *k = RSA_generate_key(2048, 3, NULL, NULL); // legacy\n")
    assert "RSA" in result["detected_algorithms"]


# --- R03 · a size excluded from the finding cannot grade it -----------------

def test_a_size_in_a_comment_does_not_downgrade_the_real_key(tmp_path):
    result = _scan(tmp_path, "app.py",
                   "# old example: rsa.generate_private_key(key_size=1024)\n"
                   "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n")
    assert result["algorithm_key_sizes"].get("RSA") == 4096


def test_a_real_weak_key_is_still_reported_weak(tmp_path):
    result = _scan(tmp_path, "app.py",
                   "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n")
    assert result["algorithm_key_sizes"].get("RSA") == 1024


# --- R04 · the digest identifies the bytes, not the decoded text ------------

def test_two_binary_inputs_that_scan_differently_get_different_digests(tmp_path):
    """One of these is read as RSA and the other is not. They shared a digest,
    so two runs that saw different content compared as comparable."""
    repo = tmp_path / "repo"
    repo.mkdir()
    digests, families = [], []
    for raw in ("06092a864886f70d010101", "06092a874886f70d010101"):
        (repo / "x.der").write_bytes(bytes.fromhex(raw))
        result = scan_directory(repo)
        digests.append(result["coverage"]["corpus"]["content_digest"])
        families.append(tuple(result["detected_algorithms"]))
    assert families[0] != families[1]
    assert digests[0] != digests[1]


# --- R05 · a file link is a reason, not a hole in the arithmetic ------------

def test_a_linked_file_is_accounted_for(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("rsa.generate_private_key(key_size=1024)\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.py").symlink_to(outside)
    block = scan_directory(repo)["coverage"]
    reasons = {r["reason"]: r["count"] for r in block["not_examined"]}
    assert reasons.get("symlink_not_followed") == 1
    assert block["accounts_for_every_file"] is True
    assert block["scope"]["coverage_pct"] == 0.0


def test_a_linked_directory_still_leaves_the_count_open(tmp_path):
    """Its contents are unknown, which is a different claim from a skipped file."""
    outside = tmp_path / "outdir"
    outside.mkdir()
    (outside / "a.py").write_text("x = 1\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked").symlink_to(outside)
    block = scan_directory(repo)["coverage"]
    assert block["accounts_for_every_file"] is False


# --- R06 · the read does not follow a link that appeared after the walk -----

def test_a_file_swapped_for_a_link_after_enumeration_is_not_read(tmp_path, monkeypatch):
    outside = tmp_path / "outside.py"
    outside.write_text('marker = "SYNTHETIC_RACE_ONLY"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    original = detectors.iter_repo_files

    def swapped(*args, **kwargs):
        entries = list(original(*args, **kwargs))
        target.unlink()
        target.symlink_to(outside)
        yield from entries

    monkeypatch.setattr(detectors, "iter_repo_files", swapped)
    result = scan_directory(repo)
    assert "SYNTHETIC_RACE_ONLY" not in json.dumps(result)
    assert "app.py" in result["unreadable_files"]


# --- R07 · a lockfile is routed by its name, not by its suffix --------------

@pytest.mark.parametrize("name,body,expected", [
    ("composer.lock",
     json.dumps({"packages": [{"name": "phpseclib/phpseclib", "version": "3.0.0"}]}),
     "phpseclib/phpseclib"),
    ("pnpm-lock.yaml",
     "lockfileVersion: '9.0'\npackages:\n  node-forge@1.3.1:\n    resolution: {integrity: sha512-x}\n",
     "node-forge"),
    ("pnpm-lock.yaml",
     "lockfileVersion: 6.0\npackages:\n  /node-forge/1.3.1:\n    resolution: {integrity: sha512-x}\n",
     "node-forge"),
    ("package-lock.json",
     json.dumps({"lockfileVersion": 3, "packages": {"node_modules/node-forge": {"version": "1.3.1"}}}),
     "node-forge"),
])
def test_a_declared_lockfile_format_is_actually_parsed(tmp_path, name, body, expected):
    """Both of these were counted as read while their dependencies were dropped:
    composer.lock is JSON and went to a Ruby regex, pnpm-lock.yaml does not end
    in `.lock` and never reached the lockfile reader at all."""
    result = _scan(tmp_path, name, body)
    assert expected in [d["package"] for d in result["evidence"]["dependencies"]]


# --- R08 · a value has to be one this field is allowed to take --------------

def _pinned_block(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    block = scan_directory(repo)["coverage"]
    block["instrument"]["source_commit"] = {"pinned": True, "commit": "a" * 40, "dirty": False}
    block["corpus"]["pinned_at"] = {"pinned": True, "commit": "b" * 40,
                                    "dirty": False, "shallow": False}
    return block


def test_the_clean_control_still_compares(tmp_path):
    block = _pinned_block(tmp_path)
    assert coverage.compare(block, copy.deepcopy(block))["verdict"] == "comparable"


@pytest.mark.parametrize("value", ["true", "false", 0, 1])
def test_a_dirty_flag_that_is_not_a_boolean_is_not_an_answer(tmp_path, value):
    block = _pinned_block(tmp_path)
    block["corpus"]["pinned_at"]["dirty"] = value
    assert coverage.compare(block, copy.deepcopy(block))["verdict"] == "unestablished"


@pytest.mark.parametrize("value", ["", "sha256:zz", "not-a-digest"])
def test_a_digest_that_identifies_nothing_is_refused(tmp_path, value):
    block = _pinned_block(tmp_path)
    block["corpus"]["content_digest"] = value
    assert coverage.compare(block, copy.deepcopy(block))["verdict"] == "unestablished"


def test_a_genuinely_dirty_corpus_is_still_not_comparable(tmp_path):
    block = _pinned_block(tmp_path)
    block["corpus"]["pinned_at"]["dirty"] = True
    assert coverage.compare(block, copy.deepcopy(block))["verdict"] == "not_comparable"


# --- the gap the position fix uncovered -------------------------------------

def test_arc4_is_detected_from_the_call_and_not_from_a_comment(tmp_path):
    """A test pinned `cipher = ARC4.new(key)  # RC4` as found, and it was -- by
    reading the comment. `\\bRC4\\b` never matched PyCryptodome's own spelling."""
    result = _scan(tmp_path, "c.py", "cipher = ARC4.new(key)\n")
    assert "RC4" in result["detected_algorithms"]


# --- from an independent comparison of 0.11.0 against qScan ------------------
# Two of its five negative files survived the position fix above, for two
# different reasons. Both are here with the controls that keep the fix narrow.

def test_an_example_call_inside_a_python_docstring_is_not_a_use(tmp_path):
    result = _scan(tmp_path, "app.py",
                   '"""\nExample: rsa.generate_private_key(key_size=2048)\n"""\nx = 1\n')
    assert result["detected_algorithms"] == []
    assert "RSA" in result["named_but_not_used"]


def test_a_key_pasted_into_a_triple_quoted_value_is_still_found(tmp_path):
    """A docstring opens a statement. `KEY = \"\"\"-----BEGIN ...` opens a value,
    and a private key pasted into one is exactly what this scanner is for."""
    result = _scan(tmp_path, "k.py",
                   'KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n"""\n')
    assert result["evidence"]["embedded_keys"]


def test_a_constant_naming_a_pem_header_is_not_key_material(tmp_path):
    result = _scan(tmp_path, "parser.ts",
                   'const PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";\n')
    assert result["evidence"]["embedded_keys"] == []


def test_a_real_pem_block_is_still_key_material(tmp_path):
    result = _scan(tmp_path, "id_rsa.pem",
                   "-----BEGIN RSA PRIVATE KEY-----\n"
                   "MIIEowIBAAKCAQEAwJ8kZ3vL9qT2mN4pR7sX1yB6cD0fH5gJ2kL8mN3pQ7rS9tU1vW\n"
                   "-----END RSA PRIVATE KEY-----\n")
    assert result["evidence"]["embedded_keys"]


def test_a_one_line_key_in_a_terraform_variable_is_still_found(tmp_path):
    result = _scan(tmp_path, "k.tf",
                   'key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIB...\\n'
                   '-----END RSA PRIVATE KEY-----"\n')
    assert result["evidence"]["embedded_keys"]


def test_a_cipher_suite_in_a_string_is_still_configuration(tmp_path):
    """Strings stay code on purpose: a suite named in one is the configuration."""
    result = _scan(tmp_path, "app.py", 'suites = "ECDHE-RSA-AES128-GCM-SHA256"\n')
    assert "ECDH" in result["detected_algorithms"]
