"""TLS versions set from code that gave nothing (fix list rows 378, 406, 409, 411).

Measured on 0.41.0 (Windows and language probes): each line below gave no `protocols` row, and
`deprecated_protocols` missed the versions they pin.

- .NET, row 378: SecurityProtocolType "Ssl3 ... Specifies the Secure Socket Layer (SSL) 3.0
  security protocol", "Tls ... Specifies the Transport Layer Security (TLS) 1.0 security
  protocol", "Tls11 ... (TLS) 1.1". https://learn.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype
- Java, row 406: SSLSocket.setEnabledProtocols "Sets the protocol versions enabled for use on
  this connection ... only protocols listed in the protocols parameter are enabled for use."
  https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/SSLSocket.html;
  the names: "TLSv1.1 | Supports RFC 4346: TLS version 1.1", "SSLv3 | Supports SSL version 3"
  https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
- Ruby, row 409: SSLContext#ssl_version= "Sets the SSL/TLS protocol version for the context.
  This forces connections to use only the specified protocol version."
  https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLContext.html
- Rust and mbedTLS, row 411: openssl crate set_min_proto_version "Sets the minimum supported
  protocol version." https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html;
  rustls `version` module: "All defined protocol versions appear in this module", TLS12
  "TLS1.2", TLS13 "TLS1.3" https://docs.rs/rustls/latest/rustls/version/index.html; mbedTLS
  ssl.h `mbedtls_ssl_protocol_version`: "MBEDTLS_SSL_VERSION_TLS1_2 = 0x0303, /*!< (D)TLS 1.2 */"
  https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/include/mbedtls/ssl.h
"""

from qrp_mcp.scan import scan_directory


def _versions(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    r = scan_directory(tmp_path)
    return r, {(p["line"], p["version"]) for p in r["evidence"]["protocols"]}


def test_dotnet_security_protocol_type(tmp_path):
    r, got = _versions(tmp_path, "W.cs",
                       "class W {\n"
                       "  void F() {\n"
                       "    ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;\n"
                       "    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;\n"
                       "    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;\n"
                       "  }\n"
                       "}\n")
    assert {(3, "SSLv3"), (3, "TLSv1.0"), (4, "TLSv1.1"), (5, "TLSv1.2")} <= got
    assert r["summary"]["deprecated_protocols"] == ["SSLv3", "TLSv1.0", "TLSv1.1"]


def test_powershell_security_protocol_type(tmp_path):
    _, got = _versions(tmp_path, "tls.ps1",
                       "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls\n")
    assert got == {(1, "TLSv1.0")}


def test_java_protocol_lists(tmp_path):
    r, got = _versions(tmp_path, "J.java",
                       "class J {\n"
                       "  void f(SSLSocket sock, SSLParameters p) {\n"
                       "    sock.setEnabledProtocols(new String[]{\"TLSv1.1\"});\n"
                       "    p.setProtocols(new String[]{\"TLSv1.2\", \"TLSv1.3\"});\n"
                       "    System.setProperty(\"jdk.tls.client.protocols\", \"SSLv3,TLSv1.2\");\n"
                       "    System.out.println(\"TLSv1.1 is old\");\n"
                       "  }\n"
                       "}\n")
    assert {(3, "TLSv1.1"), (4, "TLSv1.2"), (4, "TLSv1.3"), (5, "SSLv3"), (5, "TLSv1.2")} <= got
    assert not any(line == 6 for line, _ in got)
    assert r["summary"]["deprecated_protocols"] == ["SSLv3", "TLSv1.1"]


def test_ruby_forced_version(tmp_path):
    r, got = _versions(tmp_path, "c.rb",
                       "ctx = OpenSSL::SSL::SSLContext.new\n"
                       "ctx.ssl_version = :TLSv1\n"
                       "other.ssl_version = :TLSv1_1\n")
    assert got == {(2, "TLSv1.0"), (3, "TLSv1.1")}


def test_rust_and_mbedtls_version_constants(tmp_path):
    (tmp_path / "a.rs").write_text(
        "fn f(b: &mut SslContextBuilder) {\n"
        "    b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();\n"
        "    b.set_max_proto_version(Some(SslVersion::TLS1)).unwrap();\n"
        "    let c = ClientConfig::builder_with_protocol_versions(&[&version::TLS13]);\n"
        "}\n")
    (tmp_path / "m.c").write_text(
        "void g(mbedtls_ssl_config *conf) {\n"
        "    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);\n"
        "    mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);\n"
        "}\n")
    r = scan_directory(tmp_path)
    got = {(p["path"], p["line"], p["version"]) for p in r["evidence"]["protocols"]}
    assert got == {("a.rs", 2, "TLSv1.2"), ("a.rs", 3, "TLSv1.0"), ("a.rs", 4, "TLSv1.3"),
                   ("m.c", 2, "TLSv1.2"), ("m.c", 3, "TLSv1.3")}
