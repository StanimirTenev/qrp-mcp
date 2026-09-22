"""A key size that was measured has to reach the document that leaves.

The scanner reads the size off the line and grades a weak key with it. Until
0.17.0 that was where it stopped: the CBOM component was the bare family name,
`RSA`, with nothing about the modulus — so the measurement existed and did not
travel.

It matters more since 19.09.2026, when RSA-896 was factored on 2048 GPUs in ten
days as a low-priority background job. The author claims no improvement to GNFS
and no impact on RSA-2048, and one thing in the present tense: RSA-1024 is within
reach of anyone with a data-centre fleet. That turns a dated risk into an
inventory question — *where is RSA-1024 still in use* — and an inventory that
names algorithms without key sizes cannot answer it.

Two rules here, and the second is the one worth keeping:

* `algorithm_key_sizes` stays the **smallest** size seen per family. It grades
  weakness, and a weak key anywhere has to stay visible.
* What is emitted must not **invent**. Where one size was observed it is stated;
  where several were, all of them are listed and none is chosen. Collapsing them
  into one value would produce a number that looks measured and is not — which is
  the defect this project exists to find.
"""

from __future__ import annotations

import json

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory


def _tree(tmp_path, **files: str):
    for name, body in files.items():
        (tmp_path / name.replace("_", ".")).write_text(body, encoding="utf-8")
    return scan_directory(str(tmp_path))


def _crypto_component(document: dict, family: str) -> dict | None:
    for component in document.get("components", []):
        if component.get("name") == family:
            return component
    return None


def _properties(component: dict) -> dict:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


ONE = "import rsa\nk = rsa.generate_private_key(key_size=1024)\n"
OTHER = "import rsa\nk = rsa.generate_private_key(key_size=4096)\n"


def test_every_observed_size_is_kept_not_only_the_smallest(tmp_path):
    result = _tree(tmp_path, a_py=ONE, b_py=OTHER)
    assert result["algorithm_key_sizes"]["RSA"] == 1024, "the grading figure stays the minimum"
    assert result["algorithm_key_sizes_observed"]["RSA"] == [1024, 4096]


def test_a_single_size_reaches_the_cbom_component(tmp_path):
    """The schema's own example: in AES128, '128' identifies the key length."""
    document = cyclonedx.build(_tree(tmp_path, a_py=ONE))
    rsa = _crypto_component(document, "RSA")
    assert rsa is not None
    identifier = rsa["cryptoProperties"]["algorithmProperties"].get("parameterSetIdentifier")
    assert identifier == "1024"


def test_several_sizes_are_all_named_and_none_is_chosen(tmp_path):
    """Picking one would publish a number that looks measured and is not."""
    document = cyclonedx.build(_tree(tmp_path, a_py=ONE, b_py=OTHER))
    rsa = _crypto_component(document, "RSA")
    assert "parameterSetIdentifier" not in rsa["cryptoProperties"]["algorithmProperties"]
    assert _properties(rsa)["qrp:observedKeySizes"] == "1024, 4096"


def test_a_family_with_no_size_read_says_nothing_about_size(tmp_path):
    """Absent is absent. An algorithm whose size was never on the line does not
    acquire one."""
    document = cyclonedx.build(_tree(tmp_path, a_py="import hashlib\nhashlib.md5(b'x')\n"))
    md5 = _crypto_component(document, "MD5")
    assert md5 is not None
    assert "parameterSetIdentifier" not in md5["cryptoProperties"]["algorithmProperties"]
    assert "qrp:observedKeySizes" not in _properties(md5)


def test_a_size_only_in_a_comment_does_not_reach_the_document(tmp_path):
    """The rule that produced the minimum-size filter, applied to the new field:
    evidence excluded from the finding cannot come back in to describe it."""
    body = "import rsa\n# an old 1024-bit example\nk = rsa.generate_private_key(key_size=4096)\n"
    result = _tree(tmp_path, a_py=body)
    assert result["algorithm_key_sizes_observed"]["RSA"] == [4096]


def test_the_document_still_validates(tmp_path):
    """parameterSetIdentifier is a string in CycloneDX 1.6, not an integer."""
    document = cyclonedx.build(_tree(tmp_path, a_py=ONE))
    rsa = _crypto_component(document, "RSA")
    value = rsa["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"]
    assert isinstance(value, str)
    json.dumps(document)
