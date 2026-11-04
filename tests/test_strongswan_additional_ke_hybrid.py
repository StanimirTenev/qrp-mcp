"""strongSwan's additional key exchange names a hybrid (rows 345, 353).

Measured on 0.41.0 (L2 probe, `swanctl.conf`): `proposals = aes256-sha256-ecp256-ke1_mlkem768`
gave EC and ML-KEM as two rows and no hybrid: the CBOM did not make it one asset with both
halves. strongSwan's proposal syntax (https://docs.strongswan.org/docs/latest/config/proposals.html):
additional key exchanges "can be configured by prefixing the algorithm keyword with keX_
(where X is a number between 1 and 7)"; "x25519-ke1_mlkem768 adds ML-KEM-768 as additional key
exchange method after the initial key exchange with X25519"; `ecp256` is IANA group 19 (the
256-bit random ECP group, P-256) and `mlkem768` IANA 36. RFC 9370 defines the additional key
exchanges in IKEv2.

Not added: `ssh-mldsa44-ed25519` (row 353). draft-sfluhrer-ssh-mldsa-08 names only
"ssh-mldsa-44", "ssh-mldsa-65" and "ssh-mldsa-87"; no source for a composite with Ed25519 was
found.
"""

from qrp_mcp.scan import scan_directory


def test_ecp256_with_mlkem768_is_one_hybrid(tmp_path):
    (tmp_path / "swanctl.conf").write_text(
        "connections {\n"
        "    gw {\n"
        "        proposals = aes256-sha256-ecp256-ke1_mlkem768\n"
        "        children {\n"
        "            net { esp_proposals = aes128gcm16-ecp256-ke1_mlkem768-ke1_none }\n"
        "        }\n"
        "    }\n"
        "}\n")
    r = scan_directory(tmp_path)
    got = [(h["line"], h["name"], h["halves"]) for h in r["hybrid_names"]]
    halves = [["ECDH", "P-256"], ["ML-KEM", "768"]]
    assert got == [(3, "ecp256-ke1_mlkem768", halves), (5, "ecp256-ke1_mlkem768", halves)]
