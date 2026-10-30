"""ZA-OPRAVYANE row 166: Python's stdlib `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` gave no
protocol row and no TLS place, while pyOpenSSL's `set_min_proto_version(SSL.TLS1_3_VERSION)` did.
The version was matched; the setting's name (`minimum_version`) was not a TLS context."""

from qrp_mcp.scan import scan_directory

SERVER = ("import ssl\n"
          "def make_context():\n"
          "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
          "    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n"
          "    ctx.maximum_version = ssl.TLSVersion.TLSv1_2\n")


def test_stdlib_minimum_and_maximum_version(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "server.py").write_text(SERVER)
    r = scan_directory(t)
    versions = {(p["line"], p.get("version")) for p in r["evidence"]["protocols"]}
    assert (4, "TLSv1.3") in versions and (5, "TLSv1.2") in versions
    assert r["tls_termination"] is not None


def test_a_sentence_is_still_not_a_setting(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "notes.py").write_text('# the minimum version we document is TLSv1.2 somewhere\n')
    assert scan_directory(t)["evidence"]["protocols"] == []
