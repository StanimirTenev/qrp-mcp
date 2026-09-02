"""RFC 8784: quantum resistance with no post-quantum algorithm to find.

A Principal Engineer at Cisco, running country-wide QKD-driven PPK deployments,
made the point in public: scanning tools and their reporting need to include PPK.
He was right, and this scanner was the example. Pointed at a swanctl.conf with
ppk_required = yes -- a tunnel that resists a quantum adversary today -- it
returned zero findings and pqc_readiness "unknown". Pointed at a fuller one it
would have said "classical_only", which is the strongest available way of saying
"you have not started" to someone who had finished.

The cause is structural, not an oversight: RFC 8784 mixes a preshared key into
IKEv2 key derivation, so there is no algorithm name anywhere for a scanner to
match. A tool that reads only algorithm names cannot see it by construction.

So it is matched by the directives that switch it on, classified as a mechanism
rather than an algorithm, and kept out of the pqc_ready count -- a preshared key
is not ML-KEM, and reporting it as one would trade a false negative for a false
positive.
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory

# The shape strongSwan actually takes, from the configuration in the article.
SWANCTL = """\
connections {
   pq-tunnel {
      version = 2
      proposals = aes256gcm16-prfsha384-ecp384
      ppk_id = quantum-ppk-1
      ppk_required = yes
      local { auth = psk }
   }
}
"""


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(str(tmp_path))


def test_ppk_is_found_at_all(tmp_path):
    families = {f["algorithm_family"] for f in _scan(tmp_path, "swanctl.conf", SWANCTL)["findings"]}
    assert "PPK (RFC 8784)" in families


def test_ppk_is_a_mechanism_not_an_algorithm(tmp_path):
    """Counting it as pqc_ready would trade a false negative for a false positive."""
    result = _scan(tmp_path, "swanctl.conf", SWANCTL)
    ppk = [f for f in result["findings"] if f["algorithm_family"] == "PPK (RFC 8784)"][0]
    assert ppk["classification"] == "quantum_resistant_mechanism"
    assert ppk["quantum_vulnerable"] is False
    assert result["summary"]["pqc_ready_count"] == 0


def test_a_protected_deployment_does_not_report_classical_only(tmp_path):
    """The part that was actually asked for: the reporting, not just the detection."""
    result = _scan(tmp_path, "swanctl.conf", SWANCTL)
    assert result["summary"]["pqc_readiness"] == "mechanism_protected"


def test_the_classical_half_is_still_named(tmp_path):
    """"Protected by a mechanism" is only useful if it says what it protects."""
    families = {f["algorithm_family"] for f in _scan(tmp_path, "swanctl.conf", SWANCTL)["findings"]}
    assert "EC" in families


@pytest.mark.parametrize("line,expected", [
    ("ppk_id = quantum-ppk-1", True),
    ("ppk_required = yes", True),
    ("ppk_secret = 0x00112233", True),
    ("@ppk : PPKS 0xdeadbeef", True),
    ("crypto ikev2 policy ppk manual", True),
    ("# quantum resistance per RFC 8784", True),
    ("RFC-8784 postquantum preshared key", True),
    # .ppk is PuTTY's private key format. A key file is not a preshared key, and
    # matching the bare word would report every PuTTY user as quantum-resistant.
    ("PrivateKeyFile = C:\\\\keys\\\\id_rsa.ppk", False),
    ("appkey = 12345", False),
    ("APPKEY_SECRET", False),
])
def test_only_the_directives_count(tmp_path, line, expected):
    result = _scan(tmp_path, "ipsec.conf", line + "\n")
    found = "PPK (RFC 8784)" in {f["algorithm_family"] for f in result["findings"]}
    assert found is expected, line


@pytest.mark.parametrize("line,expected", [
    ("proposals = aes256gcm16-prfsha384-ecp384", "EC"),
    ("proposals = aes256-sha256-modp2048", "DH"),
    ("esp_proposals = aes256gcm16-ecp521", "EC"),
])
def test_ike_proposal_syntax_is_read(tmp_path, line, expected):
    """ecp384 is NIST P-384 and modp2048 is group 14. Both live in swanctl.conf,
    where a scanner reading only library calls never meets them."""
    families = {f["algorithm_family"] for f in _scan(tmp_path, "swanctl.conf", line)["findings"]}
    assert expected in families
