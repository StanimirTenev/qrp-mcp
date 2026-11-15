"""ZA-OPRAVYANE row 495 (LinkedIn, Abhishek J., "AES-256 data is largely safe"; probe
`linkedin-postove/2026-11-15/aes-proba/`, 0.46.0).

An AES-256 archive key wrapped with RSA-4096 OAEP (`kek.public_key().encrypt(archive_key,
padding.OAEP(...))`): RSA-4096 was found (lines 7, 8), AES not at all, and nothing said that
this RSA key protects that symmetric key -- which is the point of "AES-256 is safe": it is as
safe as the key that wraps it.

The RSA row of an OAEP `.encrypt(<name>, ...)` now carries `wraps`: the wrapped value's name
(masked below `--level full`, as a line is), the line it is assigned on where it is assigned
exactly once in the file, and its size where that assignment is a recognised generator
(`generate_key(bit_length=N)`, `os.urandom(n)`, `secrets.token_bytes(n)`,
`get_random_bytes(n)`). In the scan JSON, the MCP tools and the CBOM (`qrp:wraps`).

Not claimed: ECIES, or AES key wrap under a DH-derived key -- those need the data flow across
lines and are not read. AES on its own gives no row, by design (docs/measurement.md: symmetric
cryptography is out of scope); this pins that.
"""

import json

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

STORE = (
    "import os\n"
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
    "from cryptography.hazmat.primitives import hashes\n"
    "data_key = AESGCM.generate_key(bit_length=128)\n"
    "archive_key = AESGCM.generate_key(bit_length=256)\n"
    "kek = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    "wrapped = kek.public_key().encrypt(archive_key, padding.OAEP(mgf=padding.MGF1("
    "hashes.SHA256()), algorithm=hashes.SHA256(), label=None))\n"
)


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "store.py").write_text(STORE)
    return t


def _wrap_rows(evidence):
    return [e for e in evidence["source_code"] if e.get("wraps")]


def test_aes_alone_gives_no_row(tree):
    """By design: docs/measurement.md, symmetric cryptography is out of scope."""
    r = scan_directory(tree)
    assert not [e for e in r["evidence"]["source_code"] if "AES" in e["algorithm"]]
    assert r["detected_algorithms"] == ["RSA"]


def test_the_rsa_row_says_what_it_wraps_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--level", "full", "--out", str(out)]) == 0
    (row,) = _wrap_rows(json.loads(out.read_text())["evidence"])
    assert (row["line"], row["algorithm"], row["operation"]) == (8, "RSA", "encrypt")
    assert row["wraps"] == {"what": "symmetric key", "name": "archive_key", "key_size": 256,
                            "assigned_at": 6,
                            "basis": row["wraps"]["basis"]}
    assert "generate_key(bit_length=N)" in row["wraps"]["basis"]


@pytest.mark.parametrize("level", ["masked", "trimmed"])
def test_the_name_is_masked_below_full(tree, tmp_path, level):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--level", level, "--out", str(out)]) == 0
    text = out.read_text()
    (row,) = _wrap_rows(json.loads(text)["evidence"])
    assert row["wraps"]["name"] == "*******_***"
    assert row["wraps"]["key_size"] == 256
    assert "archive_key" not in text


def test_wraps_reaches_the_mcp_tool_and_the_cbom(tree):
    (row,) = _wrap_rows(server.scan_repo(str(tree), level="full")["evidence"])
    assert row["wraps"]["name"] == "archive_key"
    (masked,) = _wrap_rows(server.scan_repo(str(tree))["evidence"])
    assert masked["wraps"]["name"] != "archive_key"
    for doc, name in ((cyclonedx.build(scan_directory(tree)), "archive_key"),
                      (server.export_cbom(str(tree)), "*******_***")):
        said = {}
        for c in doc["components"]:
            props = {p["name"]: p["value"] for p in c.get("properties", [])}
            if "qrp:wraps" in props:
                wraps = json.loads(props["qrp:wraps"])
                assert len(wraps) == len(c["evidence"]["occurrences"])
                for o, w in zip(c["evidence"]["occurrences"], wraps):
                    said[(o["location"], o["line"])] = w
        assert said[("store.py", 8)]["key_size"] == 256
        assert said[("store.py", 8)]["name"] == name
        assert said[("store.py", 8)]["what"] == "symmetric key"


@pytest.mark.parametrize("source, want", [
    # os.urandom(32): 32 bytes.
    ("k = os.urandom(32)\nct = pub.encrypt(k, padding.OAEP(m, a, None))  # RSA\n",
     {"name": "k", "key_size": 256, "assigned_at": 1}),
    # Assigned twice: which one is wrapped is not read; the name only.
    ("k = os.urandom(16)\nk = os.urandom(32)\nct = pub.encrypt(k, padding.OAEP(m, a, None))"
     "  # RSA\n", {"name": "k"}),
    # Not assigned in the file: the name only.
    ("def f(k):\n    return pub.encrypt(k, padding.OAEP(m, a, None))  # RSA\n", {"name": "k"}),
])
def test_size_only_from_one_recognised_assignment(tmp_path, source, want):
    (tmp_path / "a.py").write_text(source)
    rows = _wrap_rows(server.scan_repo(str(tmp_path), level="full")["evidence"])
    assert len(rows) == 1, rows
    got = {k: v for k, v in rows[0]["wraps"].items() if k in ("name", "key_size", "assigned_at")}
    assert got == want
    if "key_size" not in want:
        assert rows[0]["wraps"]["what"] == "not read"


def test_a_call_split_over_lines_is_read(tmp_path):
    (tmp_path / "store.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
        "archive_key = AESGCM.generate_key(bit_length=256)\n"
        "kek = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
        "wrapped = kek.public_key().encrypt(\n"
        "    archive_key,\n"
        "    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),"
        " label=None),\n"
        ")\n")
    rows = _wrap_rows(server.scan_repo(str(tmp_path), level="full")["evidence"])
    assert rows and {r["wraps"]["name"] for r in rows} == {"archive_key"}
    assert {r["wraps"]["key_size"] for r in rows} == {256}
    # The generator line (3) is not inside the call.
    assert all(r["line"] >= 4 for r in rows)


@pytest.mark.parametrize("source", [
    # A signature, or encryption without OAEP named: not a key transport this reads.
    "sig = key.sign(data, padding.PSS(m, s), h)  # RSA\n",
    "ct = pub.encrypt(k, padding.PKCS1v15())  # RSA\n",
    # A literal, not a named value.
    "ct = pub.encrypt(b'secret', padding.OAEP(m, a, None))  # RSA\n",
])
def test_no_wraps_where_it_is_not_an_oaep_encrypt_of_a_name(tmp_path, source):
    (tmp_path / "a.py").write_text(source)
    assert not _wrap_rows(server.scan_repo(str(tmp_path), level="full")["evidence"])
