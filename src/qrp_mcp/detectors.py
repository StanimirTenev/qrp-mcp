"""Detection patterns for classical crypto usage and CI signing commands."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .certificates import is_certificate_file, looks_like_key_file, scan_certificate_file

SOURCE_EXTENSIONS = {
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".php", ".c", ".cpp", ".cs", ".sh",
    # C and C++ headers. Declarations live here, and in a C codebase they are
    # roughly half the tree -- reading .c but not .h reports a fraction of the
    # file count as if it were the whole language.
    ".h", ".hpp", ".hh", ".cc", ".cxx",
    # Measured on five real trees: these carried 1,600 findings the scan never saw.
    # `.inc` holds the assembly and C fragments of implementations (OpenSSL's ML-DSA
    # among them), `.t` is a Perl test recipe -- tests are code, and skipping them
    # silently is the practice this scanner argues against -- and `.in`/`.cmake`
    # are build files that enumerate which algorithms the tree implements at all.
    ".inc", ".t", ".in", ".cmake",
    # PowerShell and Perl. .sh was already here, so leaving these out was an
    # oversight rather than a scope decision: a Windows estate keeps its
    # certificate handling in .ps1, and OpenSSL's build is Perl.
    ".ps1", ".psm1", ".pl", ".pm",
    # Smart contracts and chain tooling
    ".sol", ".rs", ".move", ".cairo",
}

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "dist", "build", ".tox", "target",
    # Test caches are generated, like the rest of this set. Counting them pads the
    # denominator with files no reader cares about, which weakens the one number
    # this scanner exists to state honestly.
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

CI_CONFIG_FILENAMES = {".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"}

IAC_EXTENSIONS = {".tf", ".tfvars"}

# Where cryptographic choices are configured rather than written. A TLS or SSH
# hybrid group -- X25519MLKEM768, mlkem768x25519-sha256 -- is almost never a
# string in code; it is a line in nginx.conf or sshd_config. Scanning only source
# meant the whole RFC 10024 vocabulary could be deployed and stay invisible.
CONFIG_EXTENSIONS = {".conf", ".cnf", ".ini", ".toml", ".properties", ".cfg",
                     # HCL configures Vault and Terraform; JSON carries cipher-suite
                     # lists and algorithm names in service configuration.
                     ".hcl", ".json"}

# The same files that carry no extension at all.
CONFIG_FILENAMES = {"sshd_config", "ssh_config", "ssl.conf", "krb5.conf",
                    # Build files list the algorithm sources a tree compiles.
                    "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt",
                    # SSH key inventories: the key type is named on every line.
                    "known_hosts", "authorized_keys"}

# (algorithm, description, compiled regex matched against a single source line)
ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA usage", re.compile(
        r"Crypto\.PublicKey\.RSA|Crypto\.PublicKey\s+import\s+RSA|"
        r"hazmat\.primitives\.asymmetric\.rsa|crypto/rsa|"
        # The same library imported the way Python actually writes it. The dotted
        # form above only reaches `asymmetric.rsa`; the common import is
        # `from ... asymmetric import rsa`, with the module name after a space
        # and often in a comma list. Measured on certbot: 5 lines used the
        # import form and 6 called the module, and every one of them was
        # invisible to this rule.
        r"asymmetric\s+import\s+[^\n#]*\brsa\b|"
        r"\brsa\.generate_private_key\b|"
        # Where the algorithm is actually used. Measured against Cryben: RSA
        # scored 0 of 11 on the exact line, because only the import was read.
        # Go's standard library, and the x509 helpers named after PKCS#1.
        r"\brsa\.(?:GenerateKey|GenerateMultiPrimeKey|EncryptOAEP|DecryptOAEP|"
        r"EncryptPKCS1v15|DecryptPKCS1v15|SignPSS|VerifyPSS|SignPKCS1v15|VerifyPKCS1v15)\b|"
        r"\bx509\.(?:Parse|Marshal)PKCS1(?:Private|Public)Key\b|"
        # Ruby, Java, Node, Rust, PKCS#11.
        r"OpenSSL::PKey::RSA\b|"
        r"\w*withRSA(?:andMGF1)?\b|Cipher\.getInstance\(\s*[\"']RSA[/\"']|"
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']rsa[\"']|"
        r"\bRsaPrivateKey\b|\bRsaPublicKey\b|"
        r"\bCKM_RSA_\w+|"
        # The names protocols and APIs use for the key type itself. OpenSSH's default
        # algorithm list, sshd_config, Vault's key types and AWS key specs name RSA
        # this way and nothing else here reached them: every other family on those
        # lines was reported and RSA was not.
        r"(?<![A-Za-z])ssh-rsa(?![A-Za-z])|(?<![A-Za-z])rsa-sha2-(?:256|512)(?![0-9])|"
        r"(?<![A-Za-z])rsa[-_](?:1024|2048|3072|4096|7680|8192|15360)(?![0-9])|"
        r"\bRSA_(?:1024|2048|3072|4096|8192)\b|"
        # .NET / PowerShell factory: RSA.Create() and [System.Security.Cryptography.RSA]::Create()
        r"\bRSA\]?(?:::|\.)Create\s*\(|"
        # OpenSSL's low-level accessors, which a C tree uses far more than the
        # constructors: RSA_get0_key, RSA_set0_crt_params, EVP_PKEY_get1_RSA.
        r"\bRSA_(?:get|set)[01]_\w+|\bEVP_PKEY_get[01]_RSA\b|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']|openssl\s+genrsa|-newkey\s+rsa|"
        # C / OpenSSL: the library's own API, which is what a C tree actually contains.
        r"\bRSA_new\b|\bRSA_generate_key\w*|\bRSA_public_encrypt\b|\bRSA_private_decrypt\b|"
        r"\bEVP_PKEY_RSA\b|\bEVP_RSA_gen\b|\bPEM_read_\w*RSA\w*|\bd2i_RSA\w*|"
        # .NET / PowerShell: a Windows estate keeps its certificate handling here.
        r"\bRSACryptoServiceProvider\b|\bRSACng\b|\bRSAOpenSsl\b|\bRSA\.Create\b|"
        r"\bRSACertificateExtensions\b|\bGetRSAPublicKey\b|\bGetRSAPrivateKey\b|"
        r"-KeyAlgorithm\s+[\"']?RSA",
        re.IGNORECASE,
    )),
    ("DSA", "DSA usage", re.compile(
        r"Crypto\.PublicKey\s+import\s+DSA|"
        r"hazmat\.primitives\.asymmetric\.dsa|crypto/dsa|"
        r"asymmetric\s+import\s+[^\n#]*\bdsa\b|\bdsa\.generate_private_key\b|"
        # The call sites, as for RSA above. "withDSA" cannot reach withECDSA:
        # that text has no "withDSA" in it.
        r"\bdsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\b|"
        r"OpenSSL::PKey::DSA\b|\w*withDSA\b|\bDsa::generate\b|\bDSA\.generate\b|"
        r"\bCKM_DSA_\w+|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']|openssl\s+dsaparam|"
        r"\bDSA_new\b|\bDSA_generate_key\w*|\bEVP_PKEY_DSA\b|"
        r"\bDSACryptoServiceProvider\b|\bDSACng\b|"
        r"(?<![A-Za-z])ssh-dss(?![A-Za-z])",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA usage", re.compile(
        r"crypto/ecdsa|(?<![A-Za-z])ECDSA|"
        # C / OpenSSL.
        r"\bECDSA_do_sign\b|\bECDSA_sign\b|\bECDSA_verify\b|\bECDSA_SIG_\w+|"
        r"\w*withECDSA\b|"
        # .NET spells it ECDsa, so \bECDSA\b does not reach ECDsaCng or
        # ECDsaCertificateExtensions -- the exact call our own Windows agent makes.
        r"\bECDsaCng\b|\bECDsaOpenSsl\b|\bECDsa\.Create\b|"
        r"\bECDsaCertificateExtensions\b|\bGetECDsaPublicKey\b|\bGetECDsaPrivateKey\b",
        re.IGNORECASE,
    )),
    ("EC", "Elliptic curve usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.ec\b|crypto/elliptic|"
        # The same library imported the way Python actually writes it. The dotted
        # form above only reaches `asymmetric.ec`; the common import is
        # `from ... asymmetric import ec`, with the module name after a space
        # and often in a comma list. Measured on certbot: 10 lines used the
        # import form and 16 called the module, and every one of them was
        # invisible to this rule.
        r"asymmetric\s+import\s+[^\n#]*\bec\b|"
        r"\bec\.(?:generate_private_key|derive_private_key|SECP\w+|SECT\w+)\b|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']|openssl\s+ecparam|"
        r"\bEC_KEY_new\w*|\bEC_KEY_generate_key\b|\bEC_GROUP_new\w*|\bEVP_PKEY_EC\b|\bEC_POINT_\w+|"
        r"OpenSSL::PKey::EC\b|\bgenerateKeyPair(?:Sync)?\(\s*[\"']ec[\"']|"
        r"\bx509\.(?:Parse|Marshal)ECPrivateKey\b|"
        r"\bECCurve\.|\bECParameters\b|"
        # IKE proposal syntax: ecp384 is NIST P-384 and lives in swanctl.conf,
        # where a scanner reading only library calls never meets it.
        r"(?<![A-Za-z])ecp(?:192|224|256|384|521)(?![0-9])|"
        # The same NIST curve under the name TLS configuration actually writes.
        # `ec.SECP256R1` is seen, but `prime256v1` in an nginx `ssl_ecdh_curve`
        # or an OpenSSL `Groups =` line is a different spelling of P-256 and was
        # invisible -- found missing against the Olewinski et al. (ARES 2026)
        # ground truth. `secp256r1` also reaches Java `ECGenParameterSpec`. The
        # explicit r1/v1 suffix is what keeps secp256k1 routed to ECDSA below.
        r"(?<![A-Za-z])(?:prime(?:192|256)v1|secp(?:192|224|256|384|521)r1)(?![0-9])|"
        # The bare names OpenSSH and Java write for the same curves.
        r"(?<![A-Za-z])nistp(?:256|384|521)(?![0-9])",
        re.IGNORECASE,
    )),
    ("DH", "Diffie-Hellman usage", re.compile(
        # Not the tail of ECDiffieHellman, which is elliptic-curve and handled there.
        r"hazmat\.primitives\.asymmetric\.dh\b|crypto/dh\b|(?<!EC)Diffie[- ]?Hellman|"
        r"asymmetric\s+import\s+[^\n#]*\bdh\b|\bdh\.generate_parameters\b|"
        r"\bDH_new\b|\bDH_generate_key\b|\bEVP_PKEY_DH\b|"
        # IKE modp groups: modp2048 is group 14, and Shor breaks it like any
        # finite-field Diffie-Hellman.
        r"(?<![A-Za-z])modp(?:1024|1536|2048|3072|4096|6144|8192)(?![0-9])",
        re.IGNORECASE,
    )),
    ("MD5", "MD5 usage", re.compile(
        r"hashlib\.md5|crypto/md5|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|"
        r"createHash\(\s*[\"']md5[\"']|openssl\s+dgst\s+-md5|"
        r"\bMD5_Init\b|\bMD5_Update\b|\bEVP_md5\b|"
        r"\bMD5CryptoServiceProvider\b|\bMD5\.Create\b|"
        # The idioms the comparison found in the wild: pyca objects, hashlib.new,
        # the BSD-style C calls and headers, and Go used without its import line.
        r"hashes\.MD5\s*\(|hashlib\.new\(\s*[\"']md5[\"']|"
        r"\bMD5(?:Init|Update|Final|Transform)\b|<md5\.h>|\bmd5\.(?:New|Sum)\b",
        re.IGNORECASE,
    )),
    ("SHA1", "SHA-1 usage", re.compile(
        r"hashlib\.sha1|crypto/sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|"
        r"createHash\(\s*[\"']sha1[\"']|openssl\s+dgst\s+-sha1|"
        r"\bSHA1_Init\b|\bSHA1_Update\b|\bEVP_sha1\b|"
        r"\bSHA1CryptoServiceProvider\b|\bSHA1Managed\b|\bSHA1\.Create\b|"
        r"hashes\.SHA1\s*\(|hashlib\.new\(\s*[\"']sha-?1[\"']|"
        r"\bSHA1(?:Init|Update|Final|Transform)\b|<sha1\.h>|\bsha1\.(?:New|Sum)\b",
        re.IGNORECASE,
    )),
    ("RC4", "RC4 usage", re.compile(
        # Not a release suffix: "1.0.0-rc4" is a version. A cipher suite such as
        # "EXP-RC4-MD5" also has a dash before it, so only a digit then a dash or dot
        # marks a version (an earlier, wider exclusion dropped 13 OpenSSL suites).
        r"crypto/rc4|(?<!\d[-.])\bRC4\b|\bRC4_set_key\b|\bEVP_rc4\b", re.IGNORECASE,
    )),
    # JOSE / JWT. The algorithm is named nowhere else: a service that signs its
    # tokens with RS256 has RSA in it, and the only trace is a four-character
    # string in a quoted argument. Measured: 35 such lines in Vault, 1 in certbot,
    # 9 in the qscan corpus. Quoted or as a library constant, so that the word in
    # a sentence stays what it is -- a word in a sentence.
    ("RSA", "RSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"'](?:RS|PS)(?:256|384|512)[\"']|"
        r"\bSigningMethod(?:RS|PS)(?:256|384|512)\b|\bAlgorithm::(?:RS|PS)(?:256|384|512)\b|"
        r"[\"']?RSA-OAEP(?:-(?:256|384|512))?[\"']?|[\"']RSA1_5[\"']",
    )),
    ("ECDSA", "ECDSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"']ES(?:256|384|512)K?[\"']|"
        r"\bSigningMethodES(?:256|384|512)\b|\bAlgorithm::ES(?:256|384|512)\b",
    )),
    ("3DES", "3DES (triple DES) usage", re.compile(
        # No word boundaries: the real spellings are glued into identifiers
        # (OPT_3DES_WRAP, OIDEncryptionAlgorithmDESEDE3CBC, NewTripleDESCipher).
        r"3DES|DES[-_]?EDE3?|TripleDES|EVP_des_ede3\w*",
        re.IGNORECASE,
    )),
    ("DES", "DES usage", re.compile(
        # Single DES only: the triple-DES spellings have their own rule above, and
        # the EVP_des_ede* family (two- and three-key) must not fall in here.
        r"crypto/des\b|\bDES_set_key\w*|\bDES_ecb_encrypt\b|"
        r"\bEVP_des_(?!ede)\w+|\bDESCryptoServiceProvider\b", re.IGNORECASE,
    )),
    # Blockchain / wallet signing. These map onto the same classical primitives -- a
    # secp256k1 signature is ECDSA, and Shor breaks it like any other elliptic curve.
    ("ECDSA", "secp256k1 (ECDSA) usage", re.compile(
        r"secp256k1|\bbtcec\b|bitcoinjs-lib|\bECPair\b|"
        r"\becrecover\s*\(|ECDSA\.recover|\bethers\b|\bweb3\b|"
        r"eth_sign|personal_sign|signTypedData",
        re.IGNORECASE,
    )),
    # RFC 8784. Quantum resistance with no post-quantum algorithm to find, so it
    # is matched by the configuration directives that turn it on rather than by a
    # scheme name. Bare "ppk" is deliberately not enough: .ppk is also PuTTY's key
    # format, and a key file is not a postquantum preshared key.
    ("PPK", "RFC 8784 postquantum preshared key", re.compile(
        r"(?<![A-Za-z])ppk_(?:id|required|secret|dynamic)(?![A-Za-z])|"
        r"@ppk(?![A-Za-z])|"
        r"(?<![A-Za-z])ppk[ \t]+(?:manual|dynamic)(?![A-Za-z])|"
        r"RFC[ \t-]?8784",
        re.IGNORECASE,
    )),
    # X25519 is the classical half of every RFC 10024 TLS hybrid. Without it,
    # "X25519MLKEM768" reports the post-quantum half only, and the component Shor
    # actually breaks disappears from the inventory.
    ("X25519", "X25519 key agreement usage", re.compile(
        r"(?<![A-Za-z])x25519|(?<![A-Za-z])curve25519", re.IGNORECASE,
    )),
    # Uppercase X448 is unambiguous. Lowercase x448 is not: Bitcoin Core lists
    # node service flags in hex -- "x1, x5, x9, x408, x448, xc08" -- and three of
    # those read as the curve. Lowercase therefore has to be attached to an
    # identifier (asymmetric.x448, ossl_x448, param.x448) rather than standing
    # alone in prose.
    ("X448", "X448 key agreement usage", re.compile(r"(?<![A-Za-z])X448(?![0-9])")),
    ("X448", "X448 key agreement usage", re.compile(
        r"(?<=[._/-])x448(?![0-9])|(?<![A-Za-z])x448(?=[._])",
    )),
    # Three families the classifier table has always been able to explain and no
    # rule could ever find: a scanner that answers "yes, I know Ed448" and then
    # reports nothing in a tree carrying 315 mentions of it is hiding
    # cryptography, which is the same defect as inventing it. Counts measured
    # across OpenSSL, OpenSSH and certbot: ECDH 679, Ed448 315, EdDSA 65, and 23
    # ecdh-sha2-nistp lines in SSH configuration where no library call appears.
    ("ECDH", "ECDH key agreement usage", re.compile(
        # ECDHE, the ephemeral form, is the one that actually appears in a cipher
        # list: 1329 mentions across the three repositories against 679 bare ECDH.
        # Excluding it would have left the most common spelling of the thing
        # invisible while claiming the family was covered.
        r"(?<![A-Za-z])ECDHE?(?![A-Za-z])|\bECDH_compute_key\b|\bEVP_PKEY_ECDH\b|"
        r"\bec\.ECDH\b|(?<![A-Za-z])ecdh-sha2-nistp(?:256|384|521)|"
        # .NET's elliptic-curve Diffie-Hellman; it was filed under finite-field DH.
        r"\bECDiffieHellman(?:Cng|OpenSsl)?\b",
        re.IGNORECASE,
    )),
    ("Ed448", "Ed448 usage", re.compile(
        r"(?<![A-Za-z])Ed448(?![0-9])|asymmetric\s+import\s+[^\n#]*\bed448\b|"
        r"\bNID_ED448\b|\bEVP_PKEY_ED448\b",
        re.IGNORECASE,
    )),
    ("EdDSA", "EdDSA usage", re.compile(
        r"(?<![A-Za-z])EdDSA(?![A-Za-z])|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EdDSA[\"']",
        re.IGNORECASE,
    )),
    ("Ed25519", "Ed25519 usage", re.compile(
        r"\bed25519\b|tweetnacl|\bnacl\.sign\b|@solana/web3\.js|solana_program::|"
        r"sodium_crypto_sign",
        re.IGNORECASE,
    )),
    ("Schnorr", "Schnorr signature usage", re.compile(
        r"\bschnorr\b|\bbip340\b|\btaproot\b", re.IGNORECASE,
    )),
    ("BLS", "BLS signature usage", re.compile(
        r"bls12[-_]?381|\bblst\b|@chainsafe/bls|\bbls_sig\b", re.IGNORECASE,
    )),
    # Post-quantum schemes. Without these, a codebase that has already adopted
    # ML-KEM scans as having no post-quantum cryptography at all, which reads as
    # "not started" rather than "migrating".
    # Where the scheme name is also an ordinary English word (falcon, bike, hawk,
    # frodo), the pattern requires a parameter set: a false positive on a bicycle
    # is worse than missing an unparameterised mention.
    # Neither end carries a plain \b. Real code writes the parameter set as a
    # suffix (slh_dsa_sha2_128s, ml_kem_768_keygen, mceliece348864), and RFC 10024
    # names the TLS hybrids by concatenation: X25519MLKEM768 puts a digit in front
    # of the scheme. A word boundary refuses both. What does the protective work is
    # the lookbehind for a LETTER -- it is why "FXMSS" still does not match XMSS.
    ("ML-KEM", "ML-KEM (Kyber) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?kem|(?<![A-Za-z])kyber(?![A-Za-z])|pqcrystals[-_]?kyber|crypto_kem_kyber", re.IGNORECASE,
    )),
    ("ML-DSA", "ML-DSA (Dilithium) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?dsa|(?<![A-Za-z])dilithium|pqcrystals[-_]?dilithium", re.IGNORECASE,
    )),
    ("SLH-DSA", "SLH-DSA (SPHINCS+) usage", re.compile(
        r"(?<![A-Za-z])slh[-_]?dsa|(?<![A-Za-z])sphincs", re.IGNORECASE,
    )),
    ("Falcon", "Falcon (FN-DSA) usage", re.compile(
        r"(?<![A-Za-z])falcon[-_]?(512|1024)|(?<![A-Za-z])fn[-_]?dsa", re.IGNORECASE,
    )),
    ("Classic McEliece", "Classic McEliece usage", re.compile(
        r"(?<![A-Za-z])classic[-_ ]?mceliece|(?<![A-Za-z])mceliece", re.IGNORECASE,
    )),
    # A trailing guard as well as a leading one: "ntrunc" (n truncated) is a
    # variable in Bitcoin Core and matched 22 times. The real parameter sets are
    # spelled ntruhps2048509 / ntruhrss701 / ntru_prime, so they are named rather
    # than left to a boundary that cannot tell them from an ordinary word.
    ("NTRU", "NTRU usage", re.compile(
        r"(?<![A-Za-z])ntru(?:hps|hrss|prime|[-_\d]|(?![A-Za-z]))|"
        r"(?<![A-Za-z])sntrup\d+",
        re.IGNORECASE,
    )),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])bike[-_]?l[135]", re.IGNORECASE)),
    ("HQC", "HQC usage", re.compile(r"(?<![A-Za-z])hqc[-_]?(128|192|256)", re.IGNORECASE)),
    ("XMSS", "XMSS usage", re.compile(r"(?<![A-Za-z])xmss", re.IGNORECASE)),
    # Stateful hash-based, SP 800-208. CNSA 2.0 requires LMS or XMSS for firmware
    # and code signing, so a firmware pipeline that had complied scanned as empty.
    ("HSS/LMS", "LMS/HSS stateful signature usage", re.compile(
        r"(?<![A-Za-z])lms[-_]?sha|(?<![A-Za-z])hss[-_/]?lms|(?<![A-Za-z])lms[-_]?(sha256|shake)|"
        r"(?<![A-Za-z])hsslms|lms_sha256_m\d+_h\d+",
        re.IGNORECASE,
    )),
    # The nine schemes NIST advanced to the third additional-signatures round on
    # 14 May 2026, plus CROSS, which it dropped. "mayo" and "cross" are ordinary
    # words, so those two need their parameter set, as falcon and bike do.
    ("FAEST", "FAEST usage", re.compile(r"(?<![A-Za-z])faest", re.IGNORECASE)),
    ("SQIsign", "SQIsign usage", re.compile(r"(?<![A-Za-z])sqisign", re.IGNORECASE)),
    ("SNOVA", "SNOVA usage", re.compile(r"(?<![A-Za-z])snova", re.IGNORECASE)),
    ("SDitH", "SDitH usage", re.compile(r"(?<![A-Za-z])sdith", re.IGNORECASE)),
    ("MQOM", "MQOM usage", re.compile(r"(?<![A-Za-z])mqom", re.IGNORECASE)),
    ("QR-UOV", "QR-UOV usage", re.compile(r"(?<![A-Za-z])qr[-_]?uov", re.IGNORECASE)),
    ("UOV", "UOV usage", re.compile(r"(?<![A-Za-z])uov[-_]?(i|ip|iii|v|s|pkc)", re.IGNORECASE)),
    ("MAYO", "MAYO usage", re.compile(r"(?<![A-Za-z])mayo[-_]?[1235]", re.IGNORECASE)),
    ("CROSS", "CROSS usage (dropped by NIST)", re.compile(
        r"(?<![A-Za-z])cross[-_]?r?[-_]?sdp", re.IGNORECASE,
    )),
    ("FrodoKEM", "FrodoKEM usage", re.compile(
        r"(?<![A-Za-z])frodokem|(?<![A-Za-z])frodo[-_]?(640|976|1344)", re.IGNORECASE,
    )),
    # Recognising these two is the point: both are post-quantum by design and
    # neither is safe to rely on. Unrecognised, they read as "nothing found".
    # Parameterised or hyphenated forms, case-insensitively. The bare word is
    # handled separately below: lowercase "sike" is a word in Venda, and matched
    # a translation string in Bitcoin Core -- which would have reported the one
    # broken scheme in the list as present in Bitcoin.
    ("SIKE", "SIKE usage (broken)", re.compile(
        r"(?<![A-Za-z])sikep?\d{3}|(?<![A-Za-z])sike[-_]", re.IGNORECASE,
    )),
    ("SIKE", "SIKE usage (broken)", re.compile(r"(?<![A-Za-z])SIKE(?![A-Za-z])")),
    ("HAWK", "HAWK usage (withdrawn)", re.compile(
        r"(?<![A-Za-z])hawk[-_]?(256|512|1024)", re.IGNORECASE,
    )),
]

# (command_type, compiled regex) for signing commands found in CI/build configs.
SIGNING_COMMAND_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("gpg_sign", re.compile(r"\bgpg\s+(--detach-sign|--sign|-s)\b")),
    ("openssl_sign", re.compile(r"\bopenssl\s+(dgst|smime|cms)\b.*-sign\b")),
    ("cosign_sign", re.compile(r"\bcosign\s+sign\b")),
    ("signtool_sign", re.compile(r"\bsigntool\s+sign\b", re.IGNORECASE)),
    ("jarsigner", re.compile(r"\bjarsigner\b")),
    ("codesign", re.compile(r"\bcodesign\b")),
]

# (algorithm, description, compiled regex) for key algorithms declared in IaC syntax
# (Terraform tls_private_key/aws_kms_key resources, cert-manager Certificate manifests) --
# distinct from ALGORITHM_PATTERNS, which target source-code import/API syntax that doesn't
# appear in HCL or YAML.
IAC_ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?RSA\"?|customer_master_key_spec\s*=\s*\"RSA_\d+\"|"
        r"key_algorithm\s*[:=]\s*\"?RSA\"?",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?ECDSA\"?|customer_master_key_spec\s*=\s*\"ECC_\w+\"",
        re.IGNORECASE,
    )),
]

# A TLS cipher suite names its families in one token: ECDHE-RSA-AES128-GCM-SHA256 is
# ECDH *and* RSA. Reading the suite as a word found ECDHE and missed the rest, so an
# Apache or nginx line reported elliptic-curve exchange and no RSA, DH, DSA or 3DES.
_SUITE_COMPONENT = {
    "DHE": "DH", "EDH": "DH", "ADH": "DH", "KDHE": "DH", "DH": "DH",
    "ECDHE": "ECDH", "ECDH": "ECDH", "EECDH": "ECDH", "AECDH": "ECDH",
    "RSA": "RSA", "ARSA": "RSA", "KRSA": "RSA",
    "DSS": "DSA", "ADSS": "DSA", "DSA": "DSA",
    "ECDSA": "ECDSA", "AECDSA": "ECDSA",
    "3DES": "3DES", "CBC3": "3DES", "EDE3": "3DES", "DES": "DES", "DES40": "DES",
    "RC4": "RC4", "MD5": "MD5",
}
# A line is read as a cipher list only when it carries a suite-shaped token: at least
# three dash-joined parts, or an IANA TLS_ name. "rsa-2048" is not a suite.
_SUITE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:TLS_[A-Z0-9_]+|[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,})(?![A-Za-z0-9])")


# What makes a dash-joined token a cipher suite rather than an ordinary hyphenated
# string: it names a bulk cipher AND a mode or MAC. Anything looser produced real
# false positives on real trees: "ML-DSA-65" read as DSA, "slh-dsa-sha2-128s" read as
# DSA, and a French translation ("Remplacer-par-des-frais") read as DES.
_SUITE_CIPHER = ("AES", "CAMELLIA", "CHACHA", "SEED", "IDEA", "RC4", "DES", "3DES", "NULL")
_SUITE_MODE_OR_MAC = ("CBC", "GCM", "CCM", "POLY1305", "SHA", "MD5", "UMAC")


# OpenSSL 3 names the algorithm in a string rather than in the function name:
# EVP_PKEY_Q_keygen(libctx, propq, "RSA", bits). The old rules knew RSA_new and
# EVP_PKEY_RSA, so a file called EVP_PKEY_RSA_keygen.c produced no findings at all.
_FETCH_CALL = re.compile(
    r"\bEVP_(?:PKEY_Q_keygen|PKEY_CTX_new_from_name|PKEY_is_a|PKEY_CTX_is_a|"
    r"SIGNATURE_fetch|KEYMGMT_fetch|KEM_fetch|KEYEXCH_fetch|MD_fetch|CIPHER_fetch|"
    r"ASYM_CIPHER_fetch)\s*\([^)\n]*?[\"']([A-Za-z0-9][A-Za-z0-9._\-]*)[\"']")

# Only names this scanner already claims as families. An unrecognised name is left
# alone rather than turned into a family nobody can check.
_FETCH_NAME_FAMILY = {
    "RSA": "RSA", "RSA-PSS": "RSA", "RSASSA-PSS": "RSA",
    "EC": "EC", "ECDSA": "ECDSA", "ECDH": "ECDH", "SM2": "EC",
    "ED25519": "Ed25519", "ED448": "Ed448", "X25519": "X25519", "X448": "X448",
    "DSA": "DSA", "DH": "DH", "DHX": "DH",
    "ML-KEM": "ML-KEM", "ML-KEM-512": "ML-KEM", "ML-KEM-768": "ML-KEM", "ML-KEM-1024": "ML-KEM",
    "ML-DSA": "ML-DSA", "ML-DSA-44": "ML-DSA", "ML-DSA-65": "ML-DSA", "ML-DSA-87": "ML-DSA",
    "SLH-DSA": "SLH-DSA", "LMS": "HSS/LMS", "XMSS": "XMSS",
    "SHA1": "SHA1", "SHA-1": "SHA1", "MD5": "MD5",
    "DES-EDE3-CBC": "3DES", "DES-EDE3": "3DES", "DES-CBC": "DES", "RC4": "RC4",
}


def scan_openssl3_names(line: str) -> list[tuple[str, int]]:
    """Families named as a string argument to an OpenSSL 3 fetch or keygen call."""
    out: list[tuple[str, int]] = []
    for m in _FETCH_CALL.finditer(line):
        family = _FETCH_NAME_FAMILY.get(m.group(1).upper())
        if family:
            out.append((family, m.start()))
    return out


def scan_cipher_suites(line: str) -> list[tuple[str, int]]:
    """Families named inside cipher-suite tokens, with the position that named them.

    The position matters: a component preceded by `!` is a ban, not a use, and that
    distinction is checked by the caller exactly as it is for ordinary matches.
    """
    out: list[tuple[str, int]] = []
    for token in _SUITE_TOKEN.finditer(line):
        text = token.group(0)
        pos = token.start()
        parts = re.split(r"[-_+]", text)
        upper = [part.upper() for part in parts]
        looks_like_suite = text.upper().startswith("TLS_") or (
            any(part.startswith(_SUITE_CIPHER) for part in upper)
            and any(part.startswith(_SUITE_MODE_OR_MAC) for part in upper))
        if not looks_like_suite:
            continue
        families = [_SUITE_COMPONENT.get(part.upper()) for part in parts]
        families = [family for family in families if family]
        # DES-CBC3-SHA decomposes to DES and CBC3. The suite is triple DES; the
        # bare DES part is the same cipher named twice, not a second one.
        if "3DES" in families:
            families = [family for family in families if family != "DES"]
        out.extend((family, pos) for family in families)
    return out


# --- key sizes named on the same line as the algorithm ---
_KEY_SIZE = re.compile(
    r"key_size\s*=\s*(\d{3,5})|(?<![A-Za-z])bits\s*=\s*(\d{3,5})|"
    r"(?<![A-Za-z])rsa[:\-_](\d{3,5})(?![0-9])|\bRSA_(\d{3,5})\b|"
    r"GenerateKey\([^)]*?(\d{3,5})\s*\)|"
    r"\bRSA_generate_key(?:_ex)?\(\s*[^,]*,\s*(\d{3,5})|"
    r"\bgenrsa\b[^\n]*?(\d{3,5})|"
    r"EVP_PKEY_Q_keygen\([^)]*?(\d{3,5})\s*\)",
    re.IGNORECASE)


def key_size_on_line(line: str) -> int | None:
    """The key size named on this line, if any. Only used for RSA, where a size below
    the minimum is itself the finding."""
    m = _KEY_SIZE.search(line)
    if not m:
        return None
    for group in m.groups():
        if group:
            return int(group)
    return None


# `ppk = ...` is a directive in a VPN configuration and an ordinary variable name in
# source code (a paramiko key), so it is matched in configuration files only.
PPK_CONFIG_ASSIGN = re.compile(r"(?<![A-Za-z])ppk[ \t]*=", re.IGNORECASE)

# PEM private key block header, embedded directly in an IaC file (e.g. a test key checked
# into a Terraform variable or a Kubernetes Secret manifest).
EMBEDDED_KEY_PATTERN = re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----")


def display_path(rel: str) -> str:
    """A relative path that can always be printed and serialised.

    A file name that is not valid UTF-8 comes back from the filesystem with
    surrogate escapes; JSON and MCP serialisation reject those, which used to fail
    the whole scan. The bytes are kept visible as backslash escapes instead.
    """
    return os.fsencode(rel).decode("utf-8", "backslashreplace")


def iter_repo_files(repo_path: Path, excluded_counter: dict[str, int] | None = None,
                    problems: list[tuple[str, str]] | None = None):
    """Every file under the path, minus the vendored and generated directories.

    The exclusion is counted rather than silent. A directory name dropped here
    never reaches the denominator, so a filter that shapes the number and does
    not declare itself is the same defect this scanner exists to refuse -- and
    git will not tell you it happened, because build output is usually ignored
    and an ignored file leaves the tree reporting clean.

    What the walk cannot see is reported in ``problems`` as ("dir", path) for a
    directory it could not enter or list, and ("file", path) for an entry that is
    not a readable regular file (a broken link, a permission error on stat).
    Before this, such directories vanished and the scan still said it had read
    every file. Only directory names exclude: a *file* called ``build`` is a file.
    """
    def rel(p: str) -> str:
        return display_path(Path(p).relative_to(repo_path).as_posix())

    def onerror(err: OSError) -> None:
        if problems is not None and err.filename:
            problems.append(("dir", rel(err.filename)))

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_path, onerror=onerror):
        dirnames.sort()
        dir_parts = Path(dirpath).relative_to(repo_path).parts
        hit = next((part for part in dir_parts if part in EXCLUDED_DIRS), None)
        for name in filenames:
            path = Path(dirpath) / name
            if hit is not None:
                if excluded_counter is not None:
                    excluded_counter[hit] = excluded_counter.get(hit, 0) + 1
                continue
            try:
                regular = path.is_file()
                broken = not regular and (path.is_symlink() or not path.exists())
            except OSError:
                # Listed but not stat-able: a directory that can be read but not entered.
                regular, broken = False, True
            if not regular:
                # Sockets, FIFOs and devices are not files the tool reads; a broken or
                # unreachable entry is a file it could not read, and says so.
                if broken and problems is not None:
                    problems.append(("file", rel(str(path))))
                continue
            found.append(path)
    yield from sorted(found)


def is_ci_config_file(path: Path, repo_path: Path) -> bool:
    rel = path.relative_to(repo_path).as_posix()
    if rel.startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"}:
        return True
    if rel.startswith(".circleci/") and path.suffix.lower() in {".yml", ".yaml"}:
        return True
    return path.name in CI_CONFIG_FILENAMES


def is_config_file(path: Path) -> bool:
    """A configuration file, by extension or by one of the extensionless names."""
    return path.suffix.lower() in CONFIG_EXTENSIONS or path.name in CONFIG_FILENAMES


def _read_lines(path: Path) -> list[str] | None:
    """Lines of the file, or None when it could not be read.

    None is not an empty file. A file the scanner cannot open -- no permission, an I/O
    error, a path it lacks the rights for -- yields no findings, and returning [] here
    would make that indistinguishable from a file that WAS read and is clean. scan_repo
    reports those paths separately, so a failed check cannot read as a pass.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    # Windows PowerShell 5 writes UTF-16 by default; read as UTF-8 it is noise and
    # the file would count as scanned-clean.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore").splitlines()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="ignore").splitlines()


def is_iac_file(path: Path, repo_path: Path, lines: list[str] | None = None) -> bool:
    if path.suffix.lower() in IAC_EXTENSIONS:
        return True
    if path.suffix.lower() in {".yaml", ".yml"}:
        # Content-sniff for a Kubernetes manifest shape rather than trusting the extension
        # alone -- most .yaml files in a repo are not IaC.
        lines = (_read_lines(path) or []) if lines is None else lines
        has_api_version = any(re.match(r"^apiVersion:\s*\S+", line) for line in lines)
        has_kind = any(re.match(r"^kind:\s*\S+", line) for line in lines)
        return has_api_version and has_kind
    return False


# A cipher suite names what it excludes as well as what it allows: an OpenSSL
# cipher string writes "!3DES !MD5 !RC4". Reporting those as usage does not pad
# the answer, it inverts it -- the one configuration that took the trouble to ban
# a primitive gets recorded as using it. Found in Certbot's Apache fixtures,
# where eight of nine DES findings were the string "!3DES".
#
# This applies to CONFIGURATION ONLY. In C, "!" is logical negation, and applying
# the rule to source deleted 190 real findings in OpenSSL alone -- if (!MD5_Init(&c)),
# if (!EC_POINT_set_affine_coordinates(...)), if (!ml_kem_has(key, selection)).
# A rule that hides real cryptography is the same failure as one that invents it.
def _is_excluded(line: str, start: int) -> bool:
    """True when the match is an exclusion in a cipher list, not a use of it."""
    i = start - 1
    # Step back over a leading digit, so "!3DES" is judged from the "!" and not
    # from the "3" that the DES pattern happens to start on.
    while i >= 0 and line[i].isdigit():
        i -= 1
    return i >= 0 and line[i] == "!"


# A long hexadecimal or base64 blob can spell an algorithm name by accident: a NIST
# test vector in OpenSSH contains "ed448" inside the message bytes. A match that
# starts inside such a run is an accident of the alphabet, not a use.
_BLOB = re.compile(r"(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2})")


def _blob_spans(line: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _BLOB.finditer(line)]


def _in_blob(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def scan_source_file(path: Path, rel_path: str,
                     lines: list[str] | None = None,
                     cipher_exclusions: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        # One line, one finding per algorithm. Several patterns can carry the same
        # name -- ECDSA is matched both by its own name and by secp256k1, X448 by
        # its upper and lower case forms -- and counting each pattern separately
        # inflates the headline number by however many ways the line could be
        # spotted, which is not a property of the code being scanned.
        seen_on_line: set[str] = set()
        blobs = _blob_spans(line)
        for algorithm, description, pattern in ALGORITHM_PATTERNS:
            if algorithm in seen_on_line:
                continue
            # Every match on the line, not the first: a cipher string can both ban
            # and allow the same family -- "ALL:!ECDH:ECDHE-RSA-AES256" -- and
            # judging the line by its first match would throw the real use away
            # along with the exclusion.
            matches = [m for m in pattern.finditer(line) if not _in_blob(m.start(), blobs)]
            if not matches:
                continue
            if cipher_exclusions and all(_is_excluded(line, m.start()) for m in matches):
                continue
            seen_on_line.add(algorithm)
            item = {
                "path": rel_path,
                "line": line_no,
                "algorithm": algorithm,
                "description": description,
                "excerpt": line.strip()[:200],
            }
            size = key_size_on_line(line) if algorithm == "RSA" else None
            if size:
                item["key_size"] = size
            findings.append(item)
        for family, pos in scan_openssl3_names(line):
            if family in seen_on_line or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named in an OpenSSL 3 fetch or keygen call",
                "excerpt": line.strip()[:200],
            })

        # Suite names appear in configuration and in code alike: OpenSSL's headers
        # define them as C constants. The `!` exclusion only means anything in a
        # cipher list, and _is_excluded already requires it.
        for family, pos in scan_cipher_suites(line):
            if family in seen_on_line or _is_excluded(line, pos) or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named in a cipher suite",
                "excerpt": line.strip()[:200],
            })
        if cipher_exclusions and "PPK" not in seen_on_line and PPK_CONFIG_ASSIGN.search(line):
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": "PPK",
                "description": "RFC 8784 postquantum preshared key",
                "excerpt": line.strip()[:200],
            })
    return findings


def scan_embedded_keys(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """PEM private-key headers in any text file. A key pasted into source code is
    as exposed as one in a Terraform variable."""
    return [
        {"path": rel_path, "line": line_no,
         "description": "Embedded private key material", "excerpt": line.strip()[:200]}
        for line_no, line in enumerate(lines, start=1)
        if EMBEDDED_KEY_PATTERN.search(line)
    ]


def _merge(into: list[dict[str, Any]], extra: list[dict[str, Any]],
           already: list[dict[str, Any]] | None = None) -> None:
    """Append findings not already reported for the same file, line and algorithm.
    A config line such as `algorithm: ECDSA` is matched by both rule sets; it is
    one occurrence, not two."""
    seen = {(f["path"], f["line"], f["algorithm"]) for f in into + (already or [])}
    for f in extra:
        key = (f["path"], f["line"], f["algorithm"])
        if key not in seen:
            seen.add(key)
            into.append(f)


def scan_ci_file(path: Path, rel_path: str,
                 lines: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for command_type, pattern in SIGNING_COMMAND_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "command_type": command_type,
                    "excerpt": line.strip()[:200],
                })
    return findings


def scan_iac_file(path: Path, rel_path: str,
                  lines: list[str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (algorithm_findings, embedded_key_findings) for a Terraform/Kubernetes IaC file."""
    algorithm_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for algorithm, description, pattern in IAC_ALGORITHM_PATTERNS:
            if pattern.search(line):
                algorithm_findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "algorithm": algorithm,
                    "description": description,
                    "excerpt": line.strip()[:200],
                })
        if EMBEDDED_KEY_PATTERN.search(line):
            embedded_key_findings.append({
                "path": rel_path,
                "line": line_no,
                "description": "Embedded private key material",
                "excerpt": line.strip()[:200],
            })
    return algorithm_findings, embedded_key_findings


def _sizes_by_algorithm(findings: list[dict[str, Any]]) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for f in findings:
        if isinstance(f.get("key_size"), int):
            out.setdefault(f["algorithm"], []).append(f["key_size"])
    return out


def scan_repo(repo_path: Path) -> dict[str, Any]:
    source_findings: list[dict[str, Any]] = []
    ci_findings: list[dict[str, Any]] = []
    iac_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    files_scanned = {"source": 0, "ci_config": 0, "iac": 0, "config": 0, "certificate": 0}

    unreadable: list[str] = []
    # The denominator. files_scanned says how much was read; on its own it does not
    # say how much there was. A file skipped because the tool does not claim its
    # type is not a failure, but leaving it uncounted turns coverage into a number
    # with no base -- which is the thing this scanner exists to refuse.
    files_present = 0
    skipped_kinds: dict[str, int] = {}
    present_kinds: dict[str, int] = {}
    excluded_dir_counts: dict[str, int] = {}

    walk_problems: list[tuple[str, str]] = []
    unreadable_dirs: list[str] = []
    for path in iter_repo_files(repo_path, excluded_dir_counts, walk_problems):
        files_present += 1
        # The composition of the denominator, not just its size. A coverage figure
        # is a property of the tool crossed with what the corpus is made of: the
        # same scanner over a tree of Go and over a tree of Ruby reports different
        # numbers with nothing in the scanner changing. Size makes a figure
        # reproducible; composition is what makes it interpretable.
        kind = path.suffix.lower() or "(no extension)"
        present_kinds[kind] = present_kinds.get(kind, 0) + 1
        rel_path = display_path(path.relative_to(repo_path).as_posix())
        is_ci = is_ci_config_file(path, repo_path)
        # Every comparison is lowercased, and the reason is a defect this line
        # produced. OpenSSL carries thirteen files with upper-case extensions --
        # twelve .H and one .PL -- which failed a case-sensitive `in` against a
        # lower-case set, were skipped, and were then reported under
        # `path.suffix.lower()` as .h and .pl: types this tool does claim. So the
        # declared boundary and the real one differed, the count said the tool
        # does not claim these, and the lower-casing in the report concealed the
        # case-sensitivity in the match.
        claimed = (is_ci or path.suffix.lower() in IAC_EXTENSIONS
                   or path.suffix.lower() in SOURCE_EXTENSIONS
                   or path.suffix.lower() in {".yaml", ".yml"} or is_config_file(path)
                   or is_certificate_file(path))
        # Only a file no declared type claims is peeked at for key material; a .py or
        # a .tf that happens to contain a PEM block stays source and infrastructure.
        peeked_key = False if claimed else looks_like_key_file(path)
        if not (claimed or peeked_key):
            kind = path.suffix.lower() or "(no extension)"
            skipped_kinds[kind] = skipped_kinds.get(kind, 0) + 1
            continue

        # Read once, here: classification and scanning must see the same content, and a
        # file that cannot be read has to leave a mark rather than pass as scanned-clean.
        lines = _read_lines(path)
        if lines is None:
            unreadable.append(rel_path)
            continue

        if is_certificate_file(path) or peeked_key:
            # Certificates and keys are read as bytes, not lines: a .der carries no
            # lines at all, and a .pem that fails to decode must still be counted.
            files_scanned["certificate"] += 1
            algo_findings, key_findings = scan_certificate_file(path, rel_path)
            source_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
        elif is_ci:
            files_scanned["ci_config"] += 1
            ci_findings.extend(scan_ci_file(path, rel_path, lines))
            # A pipeline also names algorithms (`openssl req -newkey rsa:2048`).
            source_findings.extend(
                scan_source_file(path, rel_path, lines, cipher_exclusions=True))
        elif is_iac_file(path, repo_path, lines):
            files_scanned["iac"] += 1
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            # Terraform and manifests also carry Ed25519 keys, ML-DSA key specs and
            # embedded TLS configuration; the two IaC rules alone missed them.
            _merge(algo_findings,
                   scan_source_file(path, rel_path, lines, cipher_exclusions=True))
            iac_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
        elif path.suffix.lower() in SOURCE_EXTENSIONS:
            files_scanned["source"] += 1
            source_findings.extend(scan_source_file(path, rel_path, lines))
            embedded_key_findings.extend(scan_embedded_keys(rel_path, lines))
        else:
            # Configuration: the extensions above, and any YAML that is not a
            # manifest. This branch exists so that nothing can be opened and then
            # dropped: reaching here used to fall off the end of the loop, leaving
            # a file that was read, counted nowhere, and listed nowhere -- which is
            # the one thing this scanner is not allowed to do.
            #
            # Both pattern sets run, because a config file carries both shapes: a
            # cipher list reads like source, a key algorithm declaration reads like
            # infrastructure.
            files_scanned["config"] += 1
            src = scan_source_file(path, rel_path, lines, cipher_exclusions=True)
            source_findings.extend(src)
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            _merge(iac_findings, algo_findings, already=src)
            embedded_key_findings.extend(key_findings)

    # Entries the walk could see but not read count as present and unreadable, so the
    # invariant still holds. Directories it could not enter have an unknown number of
    # files in them; they are listed separately and the scan cannot claim to account
    # for every file.
    for kind, rel in walk_problems:
        if kind == "file":
            files_present += 1
            present_kinds["(unreadable entry)"] = present_kinds.get("(unreadable entry)", 0) + 1
            unreadable.append(rel)
        else:
            unreadable_dirs.append(rel + "/")

    return {
        "files_scanned": files_scanned,
        # Directories that could not be entered or listed; their files are unknown.
        "unreadable_directories": sorted(set(unreadable_dirs)),
        # Files found under the path, excluding the vendored and build directories in
        # EXCLUDED_DIRS. present = scanned + unreadable + skipped, always.
        "files_present": files_present,
        "files_present_by_extension": present_kinds,
        # Not read because this tool does not claim the file type, counted by
        # extension. Not a gap in the scan -- a boundary of it, stated rather than
        # left for the reader to assume away.
        "files_skipped_by_type": dict(
            sorted(skipped_kinds.items(), key=lambda kv: kv[1], reverse=True)
        ),
        # Attempted and NOT read. files_scanned counts only files actually read, so
        # "0 findings" can be checked against a denominator instead of trusted.
        "unreadable_files": unreadable,
        # Files removed by EXCLUDED_DIRS before files_present counted anything,
        # by the directory name that removed them. Counted so the denominator
        # can state what it left out instead of leaving it in the source.
        "files_excluded_by_dir": dict(
            sorted(excluded_dir_counts.items(), key=lambda kv: kv[1], reverse=True)
        ),
        "source_code_findings": source_findings,
        "ci_pipeline_findings": ci_findings,
        "iac_findings": iac_findings,
        "embedded_key_findings": embedded_key_findings,
        "detected_algorithms": sorted({f["algorithm"] for f in source_findings + iac_findings}),
        # The smallest size seen for a family, so a weak key anywhere is visible. A
        # size is a property of the key, not of the name, and without it every RSA
        # reads the same whether it is 1024 or 4096 bits.
        "algorithm_key_sizes": {
            alg: min(sizes)
            for alg, sizes in _sizes_by_algorithm(source_findings + iac_findings).items()
        },
    }
