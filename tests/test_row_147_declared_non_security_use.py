"""A hash the code declares is not for security (ZA-OPRAVYANE row 147).

`hashlib.md5(path.encode(), usedforsecurity=False)` (Python 3.9+) says in the code itself
that the digest is not a security use -- a cache key, an ETag. None of six tools read it
(qrp-pokazateli 06-propusnato). The finding keeps its family, its severity and its place in
the inventory: the flag is the developer's statement, not a proof, and dropping the row
would let anyone silence the scanner with it. It gets the role `non_security_use`, so a
reader can tell it from password hashing. Read on the line of the call only.
"""

from pathlib import Path

from qrp_mcp import detectors
from qrp_mcp.scan import scan_directory


def _rows(lines: list[str], name: str = "a.py") -> list[tuple[int, str, str | None]]:
    found = detectors.scan_source_file(Path(name), name, lines=lines)
    return [(f["line"], f["algorithm"], f.get("role")) for f in found]


def test_used_for_security_false_is_a_non_security_use():
    rows = _rows(["import hashlib",
                  "h = hashlib.md5(path.encode(), usedforsecurity=False)",
                  "p = hashlib.md5(password.encode())",
                  "s = hashlib.sha1(data, usedforsecurity=False).hexdigest()",
                  "n = hashlib.new('md5', b'x', usedforsecurity = False)"])
    assert (2, "MD5", "non_security_use") in rows
    assert (3, "MD5", None) in rows
    assert (4, "SHA1", "non_security_use") in rows
    assert (5, "MD5", "non_security_use") in rows


def test_used_for_security_true_or_absent_changes_nothing():
    rows = _rows(["h = hashlib.md5(b'x', usedforsecurity=True)"])
    assert rows == [(1, "MD5", None)]


def test_the_role_survives_into_the_scan_result_and_the_family_stays(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\n"
                                   "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()\n")
    result = scan_directory(str(tmp_path))
    rows = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "MD5"]
    assert rows and rows[0]["role"] == "non_security_use"
    assert "MD5" in result["detected_algorithms"]
