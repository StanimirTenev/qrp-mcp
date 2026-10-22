"""A group removed with OpenSSL's `-` is not a use (ZA-OPRAVYANE row 56, the summary probe
of 22.10.2026).

`Groups = DEFAULT:-X25519MLKEM768` switches the hybrid OFF. The TLS group rule already read
a leading `-` as "not an offer"; the algorithm rule did not, because its list of directives
named no group setting, so ML-KEM was detected and the summary said `hybrid_partial` for a
configuration whose only post-quantum line removes it. One rule for both now: the algorithm
path asks the same group-setting test the TLS group path asks.
"""

from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def test_removed_hybrid_is_a_ban(tmp_path):
    result = _scan(tmp_path, "openssl.cnf",
                   "[system_default_sect]\nGroups = DEFAULT:-X25519MLKEM768\n")
    assert "ML-KEM" not in result["detected_algorithms"]
    assert "ML-KEM" in result["named_but_not_used"]
    assert result["summary"]["pqc_ready_count"] == 0


def test_an_offered_hybrid_is_still_a_use(tmp_path):
    result = _scan(tmp_path, "openssl.cnf",
                   "[system_default_sect]\nGroups = X25519MLKEM768:X25519\n")
    assert "ML-KEM" in result["detected_algorithms"]


def test_nginx_removal_reads_the_same(tmp_path):
    result = _scan(tmp_path, "nginx.conf",
                   "server {\n  ssl_conf_command Groups -X25519MLKEM768:X25519;\n}\n")
    assert "ML-KEM" not in result["detected_algorithms"]
