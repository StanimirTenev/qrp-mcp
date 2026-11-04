"""`java.security` disabled-algorithm lists are bans, continuation lines included (row 222).

Measured on 0.41.0 (`proba/ub-legacy`): `conf/java.security.override` was not read (type not
claimed), and in a file named `java.security` the property's continuation lines -- the way
the JDK's own file writes `jdk.tls.disabledAlgorithms` -- were read as uses: `MD5withRSA`,
`3DES_EDE_CBC` and `ECDH` as `reference` rows. The versions it disables gave no protocols row.

OpenJDK, src/java.base/share/conf/security/java.security
(https://raw.githubusercontent.com/openjdk/jdk/master/src/java.base/share/conf/security/java.security):
jdk.tls.disabledAlgorithms -- "Disabled algorithms will not be negotiated for SSL/TLS
connections, even if they are enabled explicitly in an application."; jdk.certpath.
disabledAlgorithms -- "certain algorithms or key lengths may be undesirable for certification
path building and validation"; "An alternate java.security properties file may be specified
from the command line via the system property -Djava.security.properties=<URL>".
Not done: `-D...=${VAR}` as a choice made outside the files.
"""

from qrp_mcp.scan import scan_directory

TEXT = ("# comment\n"
        "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, \\\n"
        "    MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \\\n"
        "    ECDH\n"
        "jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, \\\n"
        "    RSA keySize < 1024, SHA1withRSA usage SignedJAR & denyAfter 2019-01-01\n"
        "jdk.security.provider.preferred=AES/GCM/NoPadding:SunJCE, SHA1withRSA:SunRsaSign\n")


def test_disabled_lists_are_bans_on_every_line(tmp_path):
    (tmp_path / "java.security").write_text(TEXT)
    r = scan_directory(tmp_path)
    kinds = {(f["line"], f["algorithm"]): f["evidence_kind"] for f in r["evidence"]["source_code"]}
    assert all(kind == "ban" for (line, _), kind in kinds.items() if 2 <= line <= 6), kinds
    assert (3, "MD5") in kinds and (4, "ECDH") in kinds
    # The property after the lists is not a ban.
    assert kinds[(7, "SHA1")] != "ban"
    protocols = {(p["line"], p["version"], p["banned"]) for p in r["evidence"]["protocols"]}
    assert protocols == {(2, "SSLv3", True), (2, "TLSv1.0", True), (2, "TLSv1.1", True)}
    assert r["summary"]["deprecated_protocols"] == []


def test_an_override_file_is_read(tmp_path):
    (tmp_path / "java.security.override").write_text(TEXT)
    r = scan_directory(tmp_path)
    assert r["coverage"]["scope"]["files_examined"] == 1
    assert {p["version"] for p in r["evidence"]["protocols"]} == {"SSLv3", "TLSv1.0", "TLSv1.1"}
