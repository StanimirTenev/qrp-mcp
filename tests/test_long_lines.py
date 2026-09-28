"""A test-vector line of tens of thousands of hex digits must not stall the scan.

2026-09-28: BoringSSL never finished -- one 9,272-digit ML-DSA vector line cost 2.8 s for
the 48 patterns, growing with the square of its length, and the tree has 12,921 lines over
2,000 characters. The blob is now blanked before searching; a match inside it was always
discarded, so nothing found changes.
"""

import time

from qrp_mcp import detectors


def test_a_huge_hex_line_is_scanned_quickly(tmp_path):
    line = '  "sig": "' + "79c286ca136d6925f9a067" * 2500 + '",\n'   # 55,000 hex digits
    f = tmp_path / "vectors.json"
    f.write_text('{\n  "algorithm": "ML-DSA-87",\n' + line * 3 + "}\n")
    lines = f.read_text().splitlines()
    t = time.monotonic()
    detectors.scan_source_file(f, "vectors.json", lines, cipher_exclusions=True)
    assert time.monotonic() - t < 5      # was minutes before the blob was blanked


def test_blanking_keeps_positions_and_the_edges():
    line = 'x = "' + "ab" * 40 + '" # RSA'
    spans = detectors._blob_spans(line)
    masked = detectors._masked(line, spans)
    assert len(masked) == len(line)
    start, end = spans[0]
    assert masked[start] == line[start] and masked[end - 1] == line[end - 1]
    assert set(masked[start + 1:end - 1]) == {" "}
    assert masked.endswith("# RSA")


def test_a_finding_next_to_a_blob_is_still_found(tmp_path):
    f = tmp_path / "a.py"
    f.write_text('key = rsa.generate_private_key(65537, 2048)  # ' + "0f" * 40 + "\n")
    out = detectors.scan_source_file(f, "a.py", f.read_text().splitlines())
    assert any(o["algorithm"] == "RSA" for o in out)
