"""PyNaCl's default signing key pair and Ruby's OpenSSL::PKey::DH (fix list rows 402, 412).

402: `nacl.bindings.crypto_sign_keypair()` gave nothing on 0.41.0. libsodium: "The
crypto_sign_keypair() function randomly generates a secret key and a corresponding public
key", single-part signature: Ed25519
(https://doc.libsodium.org/public-key_cryptography/public-key_signatures). Read through the
`nacl.bindings` prefix only: a bare `crypto_sign_keypair` is also the NIST signature API that
every post-quantum reference implementation exports (minimum: C with `<sodium.h>` not done).

412: `OpenSSL::PKey::DH.new(2048)` gave nothing. "The DH.new(size [, generator]) form is an
alias of DH.generate." https://docs.ruby-lang.org/en/master/OpenSSL/PKey/DH.html
"""

from qrp_mcp.scan import scan_directory


def test_pynacl_bindings_keypair_is_ed25519(tmp_path):
    (tmp_path / "b.py").write_text("import nacl.bindings\n"
                                   "pk, sk = nacl.bindings.crypto_sign_keypair()\n")
    r = scan_directory(tmp_path)
    assert any(e["line"] == 2 and e["algorithm"] == "Ed25519"
               for e in r["evidence"]["source_code"])


def test_a_bare_crypto_sign_keypair_stays_unread(tmp_path):
    (tmp_path / "api.c").write_text("int main(void) { crypto_sign_keypair(pk, sk); }\n")
    assert scan_directory(tmp_path)["evidence"]["source_code"] == []


def test_ruby_dh_new_is_dh_with_its_size(tmp_path):
    (tmp_path / "c.rb").write_text("require 'openssl'\ndh = OpenSSL::PKey::DH.new(2048)\n"
                                   "weak = OpenSSL::PKey::DH.generate(1024)\n")
    r = scan_directory(tmp_path)
    sizes = {e["line"]: e.get("key_size") for e in r["evidence"]["source_code"]
             if e["algorithm"] == "DH"}
    assert sizes == {2: 2048, 3: 1024}
