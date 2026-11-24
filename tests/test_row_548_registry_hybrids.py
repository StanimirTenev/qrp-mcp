"""Row 548 (24.11.2026): the hybrid KEM names of a scheme registry -- `"MLKEM768-X25519"`,
`"X25519-MLKEM768"`, `"HQC-256-X448"` -- are hybrids with two halves, as the TLS group names are.

The truth set is every name the combiner registers in katzenpost/hpqc kem/schemes/schemes.go at
30f6aab (26 names), and the reversed forms used elsewhere in the same repository. qrp-mcp 0.52.2 gave
the right families on each line and `hybrid_names` = [].
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory

# (name as hpqc writes it, halves)
HPQC = [
    ("CTIDH512-X25519", [["CSIDH/CTIDH", "512"], ["X25519", None]]),
    ("CTIDH1024-X448", [["CSIDH/CTIDH", "1024"], ["X448", None]]),
    ("Kyber768-X25519", [["Kyber", "768"], ["X25519", None]]),
    ("MLKEM512-X25519", [["ML-KEM", "512"], ["X25519", None]]),
    ("MLKEMHedged512-X25519", [["ML-KEM", "512"], ["X25519", None]]),
    ("MLKEM768-X25519", [["ML-KEM", "768"], ["X25519", None]]),
    ("MLKEMHedged768-X25519", [["ML-KEM", "768"], ["X25519", None]]),
    ("MLKEM1024-X25519", [["ML-KEM", "1024"], ["X25519", None]]),
    ("MLKEMHedged1024-X25519", [["ML-KEM", "1024"], ["X25519", None]]),
    ("MLKEM1024-X448", [["ML-KEM", "1024"], ["X448", None]]),
    ("HQC-128-X25519", [["HQC", "128"], ["X25519", None]]),
    ("HQC-192-X25519", [["HQC", "192"], ["X25519", None]]),
    ("HQC-256-X25519", [["HQC", "256"], ["X25519", None]]),
    ("HQC-256-X448", [["HQC", "256"], ["X448", None]]),
    ("FrodoKEM-640-SHAKE-X448", [["FrodoKEM", "640-SHAKE"], ["X448", None]]),
    ("sntrup4591761-X448", [["NTRU", "sntrup4591761"], ["X448", None]]),
] + [(f"mceliece{n}-X25519", [["Classic McEliece", n], ["X25519", None]])
     for n in ("348864", "348864f", "460896", "460896f", "6688128", "6688128f", "6960119",
               "6960119f", "8192128", "8192128f")]
REVERSED = [
    ("X25519-MLKEM768", [["X25519", None], ["ML-KEM", "768"]]),
    ("X25519-CTIDH1024", [["X25519", None], ["CSIDH/CTIDH", "1024"]]),
]


def _hybrids(tmp_path, text, name="schemes.go"):
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)["hybrid_names"]


def test_the_truth_set_is_complete():
    assert len(HPQC) == 26


@pytest.mark.parametrize("name, halves", HPQC + REVERSED, ids=[n for n, _ in HPQC + REVERSED])
def test_a_registry_name_is_a_hybrid_with_its_halves(tmp_path, name, halves):
    found = _hybrids(tmp_path, f'package schemes\n\nvar s = mustCombine(\n\t"{name}",\n\tnil,\n)\n')
    assert [(h["line"], h["name"], h["halves"]) for h in found] == [(4, name, halves)]


def test_the_whole_registry_gives_one_entry_per_name(tmp_path):
    text = "package schemes\n\n" + "".join(f'var _ = mustCombine("{n}", nil)\n' for n, _ in HPQC)
    found = _hybrids(tmp_path, text)
    assert [h["name"] for h in found] == [n for n, _ in HPQC]


@pytest.mark.parametrize("text", [
    '"X25519"', '"MLKEM768"', '"ML-KEM-768"', '"X448"', '"RSA-X25519"', '"AES-256-X25519"',
    "MLKEM768-X25519",  # not a string: an identifier or prose
    '"MLKEM768-X25519-extra"',
])
def test_neighbours_are_not_hybrids(tmp_path, text):
    assert _hybrids(tmp_path, f"package schemes\n\nvar n = {text}\n") == []


@pytest.mark.parametrize("name, halves", [
    ("X25519MLKEM768", [["X25519", None], ["ML-KEM", "768"]]),
    ("mlkem768x25519-sha256", [["ML-KEM", "768"], ["X25519", None]]),
    ("X-Wing", [["ML-KEM", "768"], ["X25519", None]]),
])
def test_the_registered_names_still_give_one_entry_each(tmp_path, name, halves):
    found = _hybrids(tmp_path, f'package schemes\n\nvar n = "{name}"\n')
    assert [(h["name"], h["halves"]) for h in found] == [(name, halves)]
