"""ZA-OPRAVYANE row 429 (the W2 cross-OS round, 04.11.2026): a per-file hash that survives a
line-ending change.

The same openssh commit checked out with CRLF (Windows default) and with LF gave different
`evidence_file_sha256` for 315 of 315 files, and 315 of 363 CBOM components differed only in
their hash, so an auditor on Linux could not confirm "same bytes" against a Windows run. After
CRLF -> LF the hashes agreed 315/315. `evidence_file_sha256_crlf_as_lf` is that digest, named
for what was hashed; the raw digest stays as the integrity of the bytes read.
"""

from __future__ import annotations

import hashlib

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory

LINES = ["import rsa", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", ""]


def _scan(root, newline):
    root.mkdir()
    (root / "a.py").write_bytes(newline.join(LINES).encode())
    return scan_directory(root, settings=None)


def test_crlf_and_lf_checkouts_share_the_folded_digest(tmp_path):
    crlf, lf = _scan(tmp_path / "w", "\r\n"), _scan(tmp_path / "l", "\n")
    assert crlf["evidence_file_sha256"]["a.py"] != lf["evidence_file_sha256"]["a.py"]
    folded = crlf["evidence_file_sha256_crlf_as_lf"]["a.py"]
    assert folded == lf["evidence_file_sha256_crlf_as_lf"]["a.py"]
    assert folded == hashlib.sha256("\n".join(LINES).encode()).hexdigest()
    # An LF file's folded digest is its raw digest.
    assert lf["evidence_file_sha256_crlf_as_lf"]["a.py"] == lf["evidence_file_sha256"]["a.py"]


def test_the_cbom_carries_it_beside_the_raw_hash(tmp_path):
    document = cyclonedx.build(_scan(tmp_path / "w", "\r\n"))
    files = [c for c in document["components"] if c["type"] == "file"]
    assert files
    props = {p["name"]: p["value"] for p in files[0]["properties"]}
    assert props["qrp:sha256_crlf_as_lf"] == hashlib.sha256("\n".join(LINES).encode()).hexdigest()
    assert files[0]["hashes"][0]["content"] != props["qrp:sha256_crlf_as_lf"]
