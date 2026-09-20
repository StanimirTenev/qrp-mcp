"""Findings of a third external analysis, this one of 0.13.1.

It confirmed the eight earlier fixes and found four more. Three share a shape:
the scan reads a path twice, or reads something it wrote, and the second read is
not the thing the first one described.
"""

import json
import shutil

from qrp_mcp import detectors
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_to_file


def _swap_after_walk(monkeypatch, action):
    original = detectors.iter_repo_files

    def swapped(*args, **kwargs):
        entries = list(original(*args, **kwargs))
        action()
        yield from entries

    monkeypatch.setattr(detectors, "iter_repo_files", swapped)


# --- N01 · the certificate parser read the file a second time ---------------

def test_a_certificate_swapped_after_the_first_read_yields_nothing(tmp_path, monkeypatch):
    """The digest described one set of bytes and the finding another: the parser
    opened the path again after the scan had hashed it."""
    outside = tmp_path / "outside.der"
    outside.write_bytes(bytes.fromhex("06092a864886f70d010101"))
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "c.der"
    target.write_bytes(b"\x00" * 16)

    def swap():
        target.unlink()
        target.symlink_to(outside)

    _swap_after_walk(monkeypatch, swap)
    result = scan_directory(repo)
    assert result["detected_algorithms"] == []
    assert "c.der" in result["unreadable_files"]


# --- N02 · a parent directory replaced after the walk -----------------------

def test_a_parent_directory_swapped_after_the_walk_is_refused(tmp_path, monkeypatch):
    """O_NOFOLLOW guards the last component only. Each component is now opened
    relative to the one before it, and a refusal does not fall back to a plain
    open -- falling back re-opened the very path that had just been rejected."""
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    (repo / "sub" / "app.py").write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path / "evil"
    outside.mkdir()
    (outside / "app.py").write_text(
        'marker = "SYNTHETIC_PARENT_SWAP"\nk = rsa.generate_private_key(key_size=1024)\n',
        encoding="utf-8")

    def swap():
        shutil.rmtree(repo / "sub")
        (repo / "sub").symlink_to(outside)

    _swap_after_walk(monkeypatch, swap)
    result = scan_directory(repo)
    assert "SYNTHETIC_PARENT_SWAP" not in json.dumps(result)
    assert result["detected_algorithms"] == []
    assert any("app.py" in p for p in result["unreadable_files"])


# --- N03 · the command from the documentation scanned its own output --------

def test_the_output_file_is_left_out_and_said_so(tmp_path):
    """`scan . --out result.json` put the result inside the tree it had scanned.
    The second run saw one file become two and quoted findings out of its own
    output, with a different corpus digest for an unchanged tree."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import rsa\nk = rsa.generate_private_key(key_size=2048)\n", encoding="utf-8")
    out = repo / "result.json"

    digests = []
    for _ in range(2):
        assert scan_to_file([str(repo), "--out", str(out)]) == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        digests.append(data["coverage"]["corpus"]["content_digest"])

    assert sum(data["files_scanned"].values()) == 1
    assert data["files_left_out"] == ["result.json"]
    assert digests[0] == digests[1]
    assert all("result.json" not in f["path"] for f in data["evidence"]["source_code"])


# --- N04 · an identifier observed is not a certificate parsed ---------------

def test_an_identifier_in_arbitrary_bytes_says_what_it_is(tmp_path):
    """Arbitrary bytes carrying a valid RSA identifier produce a finding. That is
    correct for what is measured; the README promised more than that, and the
    finding now says which of the two it is."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "junk.der").write_bytes(b"not a certificate" + bytes.fromhex("06092a864886f70d010101"))
    result = scan_directory(repo)
    findings = [f for f in result["evidence"]["source_code"] if f["algorithm"] == "RSA"]
    assert findings, "the identifier is there and is reported"
    assert "not decoded as a certificate" in findings[0]["description"]
    assert findings[0]["evidence_kind"] == "reference"
