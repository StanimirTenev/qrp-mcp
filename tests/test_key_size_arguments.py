"""Rows 392-400 (04.11.2026): the size argument of each library's key generation.

Each line named the family and the size, and the size was not read, so a 1024-bit DSA key
was "weak_key: false" (row 392; now None where unread, row 391). The meaning of each argument:
- Node `modulusLength`: "Key size in bits (RSA, DSA)"; `createDiffieHellman(primeLength)`:
  "generates a prime of primeLength bits" (https://nodejs.org/api/crypto.html). WebCrypto
  `RsaKeyGenParams`: "The modulusLength member contains the length, in bits, of the RSA
  modulus" (https://w3c.github.io/webcrypto/).
- PHP `private_key_bits`: "Specifies how many bits should be used to generate a private key"
  (https://www.php.net/manual/en/function.openssl-csr-new.php).
- Ruby `OpenSSL::PKey::RSA.new(size)` / `.generate(size)`
  (https://docs.ruby-lang.org/en/master/OpenSSL/PKey/RSA.html), DSA likewise
  (https://docs.ruby-lang.org/en/master/OpenSSL/PKey/DSA.html).
- OpenSSL 3: "EVP_RSA_gen() generates a new RSA key pair with modulus size bits"
  (https://docs.openssl.org/3.0/man3/RSA_generate_key/); EVP_PKEY_Q_keygen: "If type is RSA,
  a size_t parameter must be given to specify the size of the RSA key"
  (https://docs.openssl.org/3.0/man3/EVP_PKEY_keygen/); EVP_PKEY_CTX_set_rsa_keygen_bits
  "sets the RSA key length for RSA key generation to bits"
  (https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_ctrl/).
- Java `RSAKeyGenParameterSpec(keysize, ...)`: "keysize - the modulus size (specified in number
  of bits)" (https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/RSAKeyGenParameterSpec.html);
  Kotlin's `.apply { initialize(2048) }` is KeyPairGenerator.initialize
  (https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyPairGenerator.html).
- pycryptodome `RSA.generate(bits)`: "Key length, or size (in bits) of the RSA modulus"
  (https://www.pycryptodome.org/src/public_key/rsa.html).
- Rust `openssl::rsa::Rsa::generate(bits)` (https://docs.rs/openssl/latest/openssl/rsa/struct.Rsa.html),
  `rsa::RsaPrivateKey::new(&mut rng, bits)` (https://docs.rs/rsa/latest/rsa/).
- wolfSSL `wc_MakeRsaKey(key, size, e, rng)`: "generates a RSA private key of length size (in
  bits)" (https://www.wolfssl.com/documentation/manuals/wolfssl/group__RSA.html).
Not here: mbedTLS `mbedtls_rsa_gen_key` and PSA `psa_set_key_bits` (the reference page could not
be read), and a size on another line than the family (Java `initialize` after `getInstance`)."""

from __future__ import annotations

import pytest

CASES = [
    ("k.js", "const k = crypto.generateKeyPairSync('dsa', { modulusLength: 1024 });", "DSA", 1024),
    ("k.js", "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });", "RSA", 3072),
    ("k.js", "const dh = crypto.createDiffieHellman(2048);", "DH", 2048),
    ("k.mjs", "const k = await subtle.generateKey({ name: 'RSA-PSS', modulusLength: 4096 }, true, ['sign']);",
     "RSA", 4096),
    ("k.php", '$k = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_DSA, "private_key_bits" => 1024]);',
     "DSA", 1024),
    ("k.rb", "dsa = OpenSSL::PKey::DSA.new(1024)", "DSA", 1024),
    ("k.rb", "rsa = OpenSSL::PKey::RSA.generate(3072)", "RSA", 3072),
    ("k.c", "EVP_PKEY *k = EVP_RSA_gen(3072);", "RSA", 3072),
    ("k.c", 'EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072);', "RSA", 3072),
    ("k.c", "EVP_PKEY_CTX_set_rsa_keygen_bits(c1, 4096);", "RSA", 4096),
    ("k.c", "wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, rng);", "RSA", 2048),
    ("K.java", "g.initialize(new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4));", "RSA", 4096),
    ("K.kt", 'val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }', "RSA", 3072),
    ("k.py", "from Crypto.PublicKey import RSA\nk = RSA.generate(3072)", "RSA", 3072),
    ("k.rs", "let rsa = Rsa::generate(3072).unwrap();", "RSA", 3072),
    ("k.rs", "let k = RsaPrivateKey::new(&mut rng, 3072).unwrap();", "RSA", 3072),
]


@pytest.mark.parametrize("name,text,family,size", CASES)
def test_size_argument_is_read(tmp_path, name, text, family, size):
    from qrp_mcp.scan import scan_directory
    (tmp_path / name).write_text(text + "\n")
    result = scan_directory(tmp_path)
    assert size in result["algorithm_key_sizes_observed"].get(family, []), result["evidence"]


def test_dsa_1024_through_an_option_is_weak(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "k.js").write_text(
        "const k = crypto.generateKeyPairSync('dsa', { modulusLength: 1024 });\n")
    [f] = [f for f in scan_directory(tmp_path)["findings"] if f["algorithm_family"] == "DSA"]
    assert f["weak_key"] is True and f["severity"] == "critical"
