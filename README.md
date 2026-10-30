# qrp-mcp

<!-- mcp-name: eu.quantumreadiness/qrp-mcp -->

**A local cryptographic inventory for developers and AI agents that carries verifiable coverage
and its own limits inside the CBOM.**

Every signature in your wallet, contract and validator rests on elliptic-curve cryptography, and
a large quantum computer breaks it. Plenty of tools will tell you what they found. This one also
tells you what it read, what it could not read, and which question it is not answering — in the
document itself, where an auditor can check it rather than take your word.

An MCP server that scans a local directory for cryptography that Shor's algorithm defeats —
secp256k1, Ed25519, BLS, Schnorr, RSA — plus weak primitives and CI signing commands, and
classifies each one: broken by a quantum computer, post-quantum, or neither.

**Everything runs on your machine.** No network calls, no account, no API key, nothing
uploaded. A tool that reads your keys' surroundings has no business phoning home, so this one
makes zero outbound connections — enforced by a test, not promised in a paragraph. The only process it
starts is a local `git`, to pin what it read, with the scanned repository's own hooks and filters disarmed.

Need a cryptographic inventory (a CBOM) for a post-quantum migration or an audit, without
uploading your code? One command, no install step:

```
uvx qrp-mcp scan ~/code/my-project --out result.json
```

What comes back, run on this repository's own test fixtures -- the findings, and next to them
what the scan did not read:

```text
"verdict": "This scan read 24 of 27 files (88.89%); the remaining 3 (1 of 1, by extension
            — .b64 — being 100.0% of them) are listed with a reason each."
"summary": { "total_findings": 10, "quantum_vulnerable_count": 6, "pqc_ready_count": 1,
             "weak_count": 1, "pqc_readiness": "hybrid_partial", ... }
```

## Why this matters for chains and wallets

Bitcoin and Ethereum authenticate with **ECDSA over secp256k1**. Solana, Cardano and Polkadot
use **Ed25519**. Ethereum's consensus layer aggregates with **BLS12-381**. Taproot adds
**Schnorr**.

All four are public-key schemes whose security rests on discrete-log hardness — and all four
fall to the same quantum algorithm. The practical consequence is specific: **once a public key
is exposed, the private key becomes derivable.** Reused addresses, on-chain public keys,
and long-lived validator keys are where that exposure already exists today.

None of this is a prediction about dates. It is an inventory question: *which of my code paths
sign with what?* That question has an answer right now, and this tool gives it.

## Quick start

Add it to your MCP client — no installation step, `uvx` fetches and runs it:

```json
{
  "mcpServers": {
    "qrp": {
      "command": "uvx",
      "args": ["qrp-mcp"]
    }
  }
}
```

Then ask your agent:

> Scan ~/code/my-protocol for quantum-vulnerable cryptography.

### As a Claude Code plugin

The same server, packaged with a skill, so there is no config file to edit:

```
/plugin marketplace add StanimirTenev/qrp-mcp
/plugin install qrp@quantumreadiness
```

Then `/qrp:pqc-scan` in any project. Both routes need [`uv`](https://docs.astral.sh/uv/) on
your PATH, since `uvx` is what fetches and runs the server.

### Without an agent: write the result to a file

```
uvx qrp-mcp scan ~/code/my-protocol --out result.json
```

This produces the same result as the `scan_repo` tool, written to a file you can read
before it goes anywhere. Nothing is sent. `--level masked` stars out everything in the quoted
line but the algorithm name, and `--level trimmed` removes the line altogether; both keep each
file and line number. The SHA-256 of the written bytes is printed,
so anyone you send the file to can quote back exactly what they received.

That digest is the file's integrity, and the file holds its read times, so two runs over one
commit print different ones. Beside it, `findings sha256` is the fingerprint of the findings
alone (`findings_fingerprint` in the JSON, in SARIF's run properties and in the CBOM as
`qrp:findings_fingerprint:sha256`): the same on every run and at every `--level` that finds the
same, different when a finding is added or removed. Its normalisation rules are written into the
output beside it: each finding as family, raw value, classification and severity; each
occurrence as category, path, line, family, role and key size; excerpts, confidence, owners,
baseline state, mandate clauses, suppressed rows, coverage and the read window left out; both
lists sorted, serialised as compact JSON with sorted keys, SHA-256 in hex. It says the result
repeats; it says nothing about whether the result is complete.

```
uvx qrp-mcp cbom ~/code/my-protocol --out cbom.json
uvx qrp-mcp closure before.json after.json --out closure.json
```

`cbom` writes the same CycloneDX document as the `export_cbom` tool, masked by default because
it is the document built to be sent. `closure` writes the `prove_closure` verdict for two saved
scans, and names both inputs by their SHA-256, so the three files can be tied together by
whoever receives them. Both print the SHA-256 of what they wrote.

## Tools

| Tool | What it does |
| --- | --- |
| `scan_repo(path, level, profile)` | Scans a directory's source, CI/CD configs and infrastructure-as-code; returns findings, a summary, and the coverage block below |
| `export_cbom(path, level)` | The same reading as a CycloneDX 1.6 CBOM, with the coverage block inside it |
| `compare_coverage(first, second)` | Whether two scans produced numbers that can be compared at all |
| `prove_closure(before, after)` | Which findings a change actually closed, from two saved scans of one tree — only if the two runs can be compared for it |
| `list_algorithms()` | The algorithm families the server recognises and how each is classified |

## What it looks at

**Chain and wallet code** — `secp256k1`, `ecrecover`, ethers, web3, bitcoinjs, `ECPair`,
`btcec`, tweetnacl, `@solana/web3.js`, `solana_program`, `bls12-381`, blst, `@chainsafe/bls`,
BIP340/Taproot Schnorr. Solidity (`.sol`), Rust (`.rs`), Move and Cairo are scanned alongside
Python, Go, Java, Kotlin, Scala, Groovy, JS/TS, Ruby, PHP, C/C++/C# — headers included — PowerShell,
Perl and shell.

**Classical crypto anywhere else** — RSA, DSA, DH, ECDSA and elliptic-curve usage, plus MD5,
SHA-1, RC4 and DES/3DES. Not only through library calls: the names the protocols themselves use
(`ssh-rsa`, `rsa-sha2-512`, `ssh-dss`, key types such as `rsa-2048` and `RSA_4096`), the modern
OpenSSL 3 form where the algorithm is a string argument (`EVP_PKEY_Q_keygen(libctx, propq,
"RSA", bits)`, the `EVP_*_fetch` calls), and the hash idioms people actually write
(`hashes.MD5()`, `hashlib.new('md5')`, `MD5Init`, `<sha1.h>`, Go `sha1.Sum`). Since 0.26.0 also the
classes a key is loaded through (`jose.JWKRSA.load(...)`, `jose.ComparableRSAKey(...)`) and the
signature OIDs of Python's `cryptography` (`SignatureAlgorithmOID.RSA_WITH_SHA1`): certbot creates
its ACME account key as `jose.JWKRSA(...)`, and that line, with 28 more like it, was no finding.

Since 0.27.0 also RSA without padding -- `RSA_private_encrypt`, `RSA_public_decrypt`,
`RSA_padding_add_none`, `RSA_NO_PADDING`, the raw oracle the 2026 forgery of 1024-bit signatures
needs (ePrint 2026/2131); until then the four were found only when something else on the line
named RSA. And the type and enum vocabularies of the libraries that carry the algorithm in a name:
Java's `RSAPublicKeySpec`, `DSAPrivateKey`, `DSAParams`; auth0's `Algorithm.RSA256`; the WebCrypto
and JOSE names `"RSASSA-PKCS1-v1_5"` and `"RSA-PSS"`; Mbed TLS's `mbedtls_rsa_*` and
`MBEDTLS_PK_RSA`; `OPENSSL_KEYTYPE_RSA`, `TPM_ALG_RSA*`, `x509.DSAWithSHA256`, `KeyType.RSA`;
Go's `*rsa.PublicKey`; .NET's `RSASignaturePadding.Pss`; and a JWK's `"kty": "RSA"`. These are
case-sensitive: `rsaKey` is a variable, `RSAKey` is a type.

From 0.32.0 also OpenSSL's RSA signing calls — `RSA_sign`, `RSA_verify`, their
`_ASN1_OCTET_STRING` forms, `RSA_verify_PKCS1_PSS(_mgf1)`, `RSA_padding_add/check_PKCS1_PSS`,
`_PKCS1_type_1`, `_X931` and `RSA_PKCS1_PSS_PADDING` (names from `include/openssl/rsa.h`), with
role `signature`. A secure-boot verifier is often one `RSA_verify` against a key fused at
manufacture, and that line scanned as nothing (raised by Ken Camp).

**DNSSEC** (from 0.32.0, raised by Georgi Ivanov). The algorithm a zone is signed with, by its
IANA mnemonic as BIND (`dnssec-policy … algorithm rsasha256 2048`, `dnssec-keygen -a RSASHA256 -b
2048`), Knot (`algorithm: rsasha512`) and PowerDNS (`default-ksk-algorithm=rsasha1-nsec3-sha1`)
write it: `RSAMD5`, `RSASHA1`, `RSASHA1-NSEC3-SHA1`, `RSASHA256`, `RSASHA512` → RSA, with the size
where the line gives one; `DSA-NSEC3-SHA1` → DSA; `ECDSAP256SHA256`, `ECDSAP384SHA384` → ECDSA with
`curve` P-256 / P-384; `ED25519`, `ED448`, `MLDSA44` by their own rules. And by number (IANA
DNSSEC Algorithm Numbers, read 22 Oct 2026), only in the shape of a record — `DNSKEY`/`CDNSKEY`
`flags 3 alg`, `DS`/`CDS` `tag alg digest-type digest`, `RRSIG type alg`, and BIND's
`static-key`/`initial-key`/`static-ds`/`initial-ds` trust anchors: 1, 5, 7, 8, 10 RSA; 2 DH;
3, 6 DSA; 13, 14 ECDSA with the curve; 15 Ed25519; 16 Ed448; 17 SM2; 18 ML-DSA. A bare `8`
is a number, not RSA. ECC-GOST (12, 23) is GOST R 34.10 from 0.36.0 (before, it was left unnamed). `.zone` files are
read. Not read: PowerDNS's `ecdsa256`/`ecdsa384` as DNSSEC names — they are found as ECDSA by the
ordinary rule, without a curve, because the same word is a variable name in OpenSSH; a bare `DSA`
(algorithm 3) as a mnemonic; the `.private` files `dnssec-keygen` writes; zone files saved under
other names (`db.example`).

Where they came from, and what they did. An independent labeller read 34,967 chunks of
185 public repositories; 45 of them were set aside before labelling and not read while the rules
were written. Chunks where the labeller sees an algorithm named in the text and the scanner reports
nothing of that family: **1,068 → 967 (-9%) on the 140 the rules were written from, 167 → 155 (-7%)
on the 45 they had never seen.** The two move together, so the rules carry over rather than fit;
both are modest, because most of what remains is a bare word or a name without an operation, which
this tool does not count on purpose. The labeller is a model, not ground truth: these are counts of
disagreement, not recall.

**Cipher suites, decomposed** — `ECDHE-RSA-AES128-GCM-SHA256` is ECDH *and* RSA, and
`DHE-DSS-…` and `DES-CBC3-SHA` name families that reading the suite as one word never sees.
IANA `TLS_*` names are read the same way. A banned component is not a use: `!MD5` and `!3DES`
in a cipher list are exclusions, and they are treated as such.

**Protocols and dependencies, counted without inventing an algorithm** — a pinned TLS version
(`MinVersion: tls.VersionTLS12`, `ssl_protocols`, `SslProtocols.Tls12`, `SSL3_VERSION`), an SSH
transport line, and a cryptographic library declared in `package.json`, `go.mod`,
`requirements.txt`, `Cargo.toml`, `pom.xml` or a `Gemfile`. These are real facts about a
repository and they are reported — in their own buckets, never in `detected_algorithms`. Each
carries a `basis`: `configured_protocol` or `declared_dependency`, never `observed_call`, because
an installed library is not a line of code that calls it. A version is not a verdict either:
TLSv1.0 is marked deprecated, and quantum vulnerability is not claimed from a version number,
since TLS 1.3 is vulnerable over X25519 and is not over X25519MLKEM768. `-SSLv3` in an
`SSLProtocol` line is a ban, and is recorded as one. Manifests are parsed structurally, so a
library named in a comment is not a dependency.

**Key sizes** — a size named on the line (`key_size=1024`, `rsa:1024`, `genrsa 1024`,
`GenerateKey(..., 1024)`, `-newkey rsa:3072`, `ssh-keygen -b 4096`, `rsa-key-size = 4096`,
`KeyPairGenerator.initialize(2048)`; for DSA and DH `key_size=`/`bits=`) travels with the family,
and only a size a modulus can have — `CKM_RSA_9796` is ISO/IEC 9796 padding, not a 9796-bit key —
so a weak RSA key is reported as weak rather
than as one more RSA. `algorithm_key_sizes` holds the **smallest** size seen per family — the
figure that answers *is anything weak here* — and `algorithm_key_sizes_observed` holds **every**
size seen, which is a different question and became the operational one when RSA-896 was factored
on a data-centre fleet: *where is RSA-1024 still in use?*

The size reaches the CBOM as one algorithm component **per observed size, curve or parameter
set** — `RSA-2048` apart from `RSA-4096`, `ECDSA-P-256` apart from `ECDSA-P-384`, `ML-KEM-768`
apart from `ML-KEM-1024` — each with its own occurrences and the number in
`cryptoProperties.algorithmProperties.parameterSetIdentifier`, the field whose own examples in the
schema are a key length and a digest length. The family's own component (`RSA`) holds only the
sightings that name no size, and is **not emitted** when there are none; a certificate's key, a
hybrid's half and a self-signed certificate's signature then point at the sized component. A
family whose name fixes the number carries it (MD5 128, SHA-1 160, SHA-224 224, DES 56,
X25519/Ed25519 256, X448 448, Ed448 456 — the key sizes a parsed key gets), and so does a TLS group
or SSH key exchange offered alone (`prime256v1` 256, `diffie-hellman-group14-sha256` 2048). Nothing
else gets a number: `rsa-sha2-256` names a hash, not a modulus, and a sizeless sighting stays
sizeless rather than inheriting a size seen elsewhere in the tree.

**Hybrids and composites** — the RFC 10024 TLS groups `X25519MLKEM768`,
`SecP256r1MLKEM768` and `SecP384r1MLKEM1024`, OpenSSH 10's default `mlkem768x25519-sha256`,
and the composite certificate algorithms of draft-ietf-lamps-pq-composite-sigs such as
`id-MLDSA44-RSA2048-PSS-SHA256`. A hybrid holds if either half holds, so the post-quantum
scheme leads — and the classical half is carried in `also_present` rather than dropped, since
it is the component Shor breaks.

**Post-quantum schemes, by family** — ML-KEM, ML-DSA, SLH-DSA, Falcon (FN-DSA), NTRU,
Classic McEliece, BIKE, HQC, FrodoKEM, XMSS, and the stateful LMS/HSS of SP 800-208 that
CNSA 2.0 requires for firmware signing. The nine schemes NIST advanced to its third
additional-signatures round in May 2026 — FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA,
SQIsign, UOV — are recognised, the eight other than HAWK as candidates and HAWK as withdrawn
(below), and CROSS as dropped from that process.

Each carries the mathematical family it rests on (structured or unstructured lattice,
code-based, hash-based, isogeny-based, multivariate, symmetric-based) and where it stands:
standardised, selected, candidate, superseded, research, withdrawn, eliminated or broken. SIKE is reported
as broken and HAWK as withdrawn rather than counted as quantum-resistant — "post-quantum" is a
category, not an assessment.

**Only a published standard is `pqc_ready`.** A selected or candidate scheme — HQC, Falcon
(FIPS 206 not yet listed as published here), Classic McEliece, BIKE, FrodoKEM, NTRU including
OpenSSH's `sntrup761`, and the additional-signature candidates — is `pqc_pre_standard`: found,
post-quantum, and not counted as ready, because an implementation of today's specification need
not match the standard when it comes (FIPS 203's own 2023 draft differs from the final text).
Until 0.28.0 these counted as `pqc_ready`; raised in public by Bill Buchanan about HQC.

**Round-3 Kyber is not ML-KEM.** FIPS 203, Appendix C: ML-KEM uses a different Fujisaki-Okamoto
variant from the round-3 submission, and the two do not interoperate. Until 0.28.0 every Kyber
spelling was reported as standardised ML-KEM (raised by Mehrdad Daei). Now the identifiers round-3
code carries — `pqcrystals_kyber…`, `crypto_kem_…kyber…`, `PQCLEAN_KYBER…`, `pqcrypto.kem.kyber…`
and the `pqcrypto-kyber` crate, `OQS_KEM_alg_kyber_…`, CIRCL's `kem/kyber`, `pqc_kyber`, and the
draft hybrids such as `X25519Kyber768Draft00` — are family `Kyber`, status `superseded`,
`pqc_pre_standard`. **The word `kyber` alone** is reported the same way: it is the round-3 name
and also an old name people still use for ML-KEM, the line does not say which, and claiming a
standard for code that may not interoperate with it is the worse error. A line that names ML-KEM
as well (`ML-KEM (Kyber)`) resolves the old name and is ML-KEM only. Whether code that says
`pqcrystals_kyber` was updated to FIPS 203 under the old name is not visible from the name, and the
finding says so.

**OpenSSH's experimental ML-DSA key is not the one that replaced it.** OpenSSH 10.4 shipped a
composite of ML-DSA-44 and Ed25519 as an experiment, as `ssh-mldsa44-ed25519@openssh.com`; 10.6
enabled the scheme without the suffix, and its release notes say keys generated with the
experimental support must be regenerated and/or removed. Until 0.30.0 both read as ML-DSA,
`pqc_ready`. Now the suffixed type — in a key or certificate file, or named in configuration such as
`HostKeyAlgorithms` — is family `ML-DSA-44-Ed25519 experimental`, status `superseded`,
`pqc_pre_standard`, and the ML-DSA rule does not count it a second time. The unsuffixed composite
stays ML-DSA and now names its classical half: `also_present: ["Ed25519"]`. Whether a given server
still accepts an experimental key is not visible from the file. On OpenSSH's own tree, four test
keys under `regress/` still carry the experimental type while the source uses the new name.

**The summary does not reassure past a broken scheme.** `summary.pqc_readiness` is one of
`broken_pqc_present` (a broken, withdrawn or eliminated post-quantum scheme is present — first,
whatever sits beside it), `hybrid_partial`, `hybrid_pre_standard` (classical beside post-quantum
schemes none of which is standardised), `mechanism_protected`, `classical_only`,
`pqc_pre_standard`, `pqc_ready` (every post-quantum scheme found is standardised and nothing
classical is), `no_quantum_vulnerable_detected`, `not_established` (one of the reassuring values,
withheld because the scan did not read or determine everything — from 0.34.0) or `unknown`. Until 0.28.0 a file holding only
SIKE read `no_quantum_vulnerable_detected` (raised by Larisa Ghazaryan). `pqc_pre_standard_count`
and `broken_pqc_count` sit beside `pqc_ready_count`, and `list_algorithms` answers with the same
classification a scan gives. From 0.35.0 `summary.by_role` gives the same value for key
establishment and for signatures apart, with the families in each (`none_found` for a part with
none).

**Which module implements it, where the file says.** Validation belongs to a module, not to an
algorithm, and `@noble/post-quantum` and Go's `crypto/mlkem` used to give identical findings
(raised by Jesone Sam). Now a line that uses a family carries `provider` when the file names the
module unambiguously — `@noble/post-quantum`, the Go standard library (`"crypto/mlkem"`),
Cloudflare CIRCL, liboqs, pqcrypto, PQClean, the pq-crystals reference code, Bouncy Castle,
BoringSSL (`MLKEM768_…`, `MLDSA65_…`, `KYBER_…`) and OpenSSL 3 (`EVP_PKEY_Q_keygen`,
`EVP_PKEY_CTX_new_from_name`, `EVP_KEM_fetch`…) — and each finding lists its `providers`. The
module is usually named on the import line and used on another, so a call line takes the module
its file imports for that family; two modules in one file and none on the line leave it absent.
An unknown provider is **absent, never guessed**: a header such as `<openssl/evp.h>` is shared by
OpenSSL, BoringSSL and LibreSSL and names no one. What is named is the API, not the build — a fork
that keeps the API reads the same — and **nothing here claims CMVP or FIPS 140-3 validation**.

From 0.32.0 (raised by Paul J. Lilly, extending a point Solahuddin Shamsuddin made): Python's
`cryptography` is a provider too (`pyca/cryptography`, by `from cryptography.hazmat…`), and **a
version pinned in a manifest is joined to the provider whose package it is**: `cryptography==44.0.0`
in requirements.txt gives every line that imports it `provider_pin: {"package": "cryptography",
"version": "44.0.0", "pinned_in": "requirements.txt:1"}`, and the finding `provider_pins`. Read
from `requirements.txt` (`==` only) and `go.mod`, from the nearest manifest above the file, for
pyca/cryptography, Cloudflare CIRCL and pqcrypto. A range (`>=42`) is a request, not a version, and
gives nothing; two pins that disagree at the same level give nothing. `pyproject.toml`, `Pipfile`
and the lockfiles are not read for this. "Pinned" is what the manifest asks for, not what is
installed.

And **OpenSSL's FIPS provider, activated in `openssl.cnf`**, is `evidence.fips_provider`, one item
per line that brings it in, from OpenSSL's `config(5)` and `fips_module(7)`: `.include
…/fipsmodule.cnf`, `fips = <section>` in the section `providers =` names (when that section's
`activate` is yes/on/true/1, or the section is in the included file), and `default_properties =
fips=yes` or the deprecated `fips_mode = yes`. Each says "FIPS provider activated in
openssl.cnf:8 … Activated in configuration, not validated". Every finding whose provider is
OpenSSL 3 then carries `fips_provider_configured_in` — the same ML-KEM line read "OpenSSL 3"
whether it ran through the FIPS provider or the default one. Which process loads which
configuration file is not in the files, and is not claimed; neither is validation.

**Isogeny key exchange in no standardisation process: MIKE, CSIDH, CTIDH.** Until this release
code doing either read as having no post-quantum cryptography at all (raised by John Preuß
Mattsson). Matched by the implementations' own identifiers — MIKE's `mike_keypair(` /
`mike_exchange(`, `MIKE_BUILD_TYPE` and the other CMake options, its six primes (`p308_633` …),
the `mike_rs` crate, `from mike.mike import`, `tensor-MIKE/mike_*`; CSIDH/CTIDH as `csidh`,
`ctidh`, `highctidh`, `secsidh`, CIRCL's `dh/csidh` — and reported with status **`research`**,
`pqc_pre_standard`: not ready, and not broken. The SIKE attack does not carry over (it needs the
torsion-point images MIKE and CSIDH do not publish). CSIDH-512 is below its claimed level against
quantum attack (Peikert; Bonnetain–Schrottenloher), which the finding says — a cost estimate, not
a classical break. **The word `mike` alone never matches**: it is a person, the MkDocs versioning
tool on PyPI, and MIKEY (RFC 3830); `import mike` cannot be told apart from MkDocs and is not read
as MIKE either. Through the classifier API `MIKE` matches only as the whole value.

**Merkle Tree Certificates are named, never counted as post-quantum.** The three OIDs IANA
assigned on 28 Sep 2026 (`1.3.6.1.5.5.7.6.67`, `.1.38`, `.25.3`), Cloudflare's experimental arc
`1.3.6.1.4.1.44363.47` (in dotted and Go integer-list form), the draft's ASN.1 names
(`id-alg-mtcProof`, `MTCProof`, `MTCLogEntry`, `MerkleTreeCertEntry` …) and the BoringSSL and
Chrome identifiers (`X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05`, `NID_alg_mtcProof_draft`,
`MTCAnchor`, `kVerifyMTCs`, `verify-mtcs`) give family `MTC`, classification `unknown`. They live
in CA, TLS-library and browser code, not in an origin's configuration, and a hit means "this
code issues or verifies MTCs" — the authentication rests on the CA's and the cosigners' signature
algorithms, and the leaf keeps an ordinary key (ECDSA-P256 in Cloudflare's experiment). So it
is neither `pqc_ready` nor a mechanism, and stays out of `pqc_readiness`. Trust Anchor IDs
(`TLSEXT_TYPE_trust_anchors`, `0xca34`) are a prerequisite, not MTC, and are not matched; nor is
`merkle` alone. Raised by Delta Li.

**Certificates and keys** — `.pem`, `.der`, `.crt`, `.cer`, `.cert`, `.csr`, `.key`, `.pub`,
`.p12`, `.pfx`, and from 0.35.0 the Java keystores `.jks` and `.keystore`. Algorithms are resolved from the object identifiers inside the DER and from
PEM labels and OpenSSH key types, and private key material is reported separately. This does
not parse X.509: it matches the object identifiers already in the classifier against the bytes.
A file that is not a certificate but contains an identifier's bytes **is** reported, and the
finding says so — "observed in the file; the file was not decoded as a certificate". An earlier
version of this paragraph promised that a malformed certificate yields nothing; an independent
analysis put a valid RSA identifier into arbitrary bytes and got a finding, which is what the
code measures. For a certificate register — issuer, validity, the device — this tool is the wrong
instrument and says so: that data comes from a structural parser or an external inventory.

From 0.32.0 an EC key's **curve is named** from its named-curve identifier — P-256
(`1.2.840.10045.3.1.7`), P-384 (`1.3.132.0.34`), P-521 (`1.3.132.0.35`) from RFC 5480 §2.1.1.1,
secp256k1 (`1.3.132.0.10`) from SEC 2 v2.0 — as `curve` and `key_size` on the EC finding. Before,
the curve identifier was swallowed by `id-ecPublicKey`, and a P-384 key read as "EC".

From 0.33.0 an RSA key's **size** is read the same way, from its public key: the modulus in a
SubjectPublicKeyInfo whose algorithm is `rsaEncryption` (RFC 3279 §2.3.1, RFC 8017 A.1.1) and in
an `RSA PUBLIC KEY` block, as `key_size` on the RSA finding, so it reaches `algorithm_key_sizes`
and the CBOM. Before, a certificate's RSA key was named and never sized. An issuer's RSA
signature on a certificate whose own key is EC gets no size — the issuer's key is not in it — and
a private key is not read for its size. On certbot the smallest RSA size becomes 512 bits (test
certificates in `acme/…/testdata`, checked with `openssl x509 -text`); on OpenSSH nothing moves.

And **a private key recoverable from its public key is a finding of its own**, under
`evidence.weak_keys` ("private key recoverable"), with the curve and the scalar: every
uncompressed EC public point the scan can locate is compared with k·G for every k ≤ 256. The
eight keys in a post of 22 Oct 2026 all had k < 256, one of them 4·G on P-384, and before this
release that certificate scanned exactly like one with a random key (raised by Bill Buchanan;
the check is Israr Ahmed's). Where the point is located, without parsing X.509: a DER BIT STRING
`00 04 X Y` of the key's curve size (SubjectPublicKeyInfo in a certificate, a public key, SEC 1
`EC PRIVATE KEY`, PKCS#8) and OpenSSH's `nistp256/384/521` encoding (a `.pub` line, an
`openssh-key-v1` private key file). P-256, P-384, P-521 and secp256k1; curve parameters from SEC 2
v2.0, agreeing with RFC 5903 §3. **Not checked**: compressed points, keys inside encrypted
containers (PKCS#12, encrypted PEM), other curves (brainpool, Ed25519 and X25519 keys), points
quoted in source code or in a `known_hosts`/`authorized_keys` line read as configuration, and any
scalar above 256 — the bound is the finding's, and a key with scalar 257 is not reported.
Debian's weak OpenSSL keys and ROCA are a different family of weak key and are not checked. The
table is built once per curve (four curves: 39 ms) and a key costs a lookup: on OpenSSH's 130 key
and certificate files the check took 3 ms. In the CBOM each weak key is a
`related-crypto-material` component, `EC key on P-384 with private scalar 4`.

**Configuration** — `nginx.conf`, `sshd_config`, `openssl.cnf`, `swanctl.conf`, `.ini`,
`.toml`, `.properties`, `.hcl`, `.json`, and any YAML that is not a manifest. This is where a TLS or SSH hybrid
group is chosen: `X25519MLKEM768` and `mlkem768x25519-sha256` are almost never strings in code.
IKE proposal syntax is read here too — `ecp384` is NIST P-384, `modp2048` is group 14.
From 0.32.0 also `.zone` files, and the DNS size budget of a BIND configuration: `max-udp-size`
(the largest UDP response BIND sends) and `edns-udp-size` (the buffer it advertises for responses
it receives) are protocol assets with `protocol: "dns"`, `udp_setting` and `udp_size`. Both
default to 1232 bytes (BIND 9 ARM); a file with a `dnssec-policy` that does not set
`max-udp-size` gets that default as an asset with `default_applied: true`, at the
`dnssec-policy` line.

**OPC UA SecurityPolicies.** Each of the 30 SecurityPolicy URIs in the OPC Foundation profile
database (UACore 1.05, read 7 Oct 2026) names the algorithms it rests on — RSA, ECDSA+ECDH,
Ed25519/X25519, Ed448/X448 or RSA with finite-field DH; SHA-1 for Basic128Rsa15 and Basic256 —
and no post-quantum one exists. A URI (`http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`)
or a stack's own identifier — .NET `SecurityPolicies.X`, open62541 `UA_SecurityPolicy_X(` /
`UA_ServerConfig_addSecurityPolicyX(`, asyncua `SecurityPolicyType.X_Sign…` and
`set_security_string("X,…`, Milo/node-opcua `SecurityPolicy.X`, gopcua `SecurityPolicyURIX`,
Node-RED `"secpol"` — gives those families, and the policy itself as a protocol asset
(`protocol: "opcua"`) with `policy_status` and `deprecated`: ten are `Deprecated` in the database
(Basic128Rsa15, Basic256, the six un-suffixed ECC policies and two interim names). For the six ECC
ones the .NET stack disagrees (`IsDeprecated = false`) and the asset says so; a policy without the
attribute is "not marked deprecated", not "released". Stack-only names (`Https`, `Basic192` …) are
named with no algorithm claimed. A bare `Basic256Sha256` or `None` never matches. **`.xml` and
`.json5` are read only when the file contains a SecurityPolicy URI** — a .NET `*.Config.xml`, an
open62541 `*.json5` — and declared as `claimed_types.config_when_naming_opcua_security_policy`;
every other XML stays `type_not_claimed`, so coverage on trees without OPC UA does not move.
Raised by Ogochukwu Friday Ikwuogu.

**AWS load-balancer TLS policies, and the one you get by writing none.** An `ELBSecurityPolicy-…`
name — Terraform `ssl_policy`, CloudFormation `SslPolicy`, CDK `elbv2.SslPolicy.X` — is read
against the 45 policies on AWS's ALB and NLB pages: every one offers classical (EC)DHE (`ECDH`),
the 13 `…PQ-2025-09` ones add hybrid ML-KEM, and those with RSA key-transport suites name `RSA`;
the policy is a protocol asset with `allows_versions`, `post_quantum` and `deprecated` (TLS 1.0 or
1.1 allowed). **A Terraform `aws_lb_listener`/`aws_alb_listener` or a CloudFormation
`AWS::ElasticLoadBalancingV2::Listener` that serves HTTPS or TLS and names no policy gets
`ELBSecurityPolicy-2016-08`**, AWS's documented default for the CLI, CloudFormation, the CDK and
the API (Terraform sends none) — TLS 1.0–1.2, RSA key transport, no post-quantum group — with
`default_applied: "default applied because ssl_policy is absent"`, `basis: provider_default` and
evidence kind `default`. The console default is a PQ policy; that difference is the point (raised
by Vladimir Mikhalev, whose probe — explicit `2016-08`, and no `ssl_policy` — gave 0 findings
both ways until this release). Only a top-level `protocol` counts: the `redirect { protocol =
"HTTPS" }` inside an HTTP listener does not make it an HTTPS listener, and `ssl_policy = var.x` is
not absent. An unknown name, and CDK `LEGACY` (on neither AWS page), claim no algorithm; from
0.38.0 an unknown `ELBSecurityPolicy-*` name set as a listener's policy is named as a TLS asset
with `policy_known: false`, so the listener does not drop out.

**IKEv2 fragmentation, where the configuration carries post-quantum.** An ML-DSA signature lands
in IKE_AUTH, and draft-ietf-ipsecme-ikev2-pqc-auth makes RFC 7383 fragmentation a MUST for it;
RFC 9370 puts additional key exchanges in IKE_INTERMEDIATE so they can be fragmented. So where a
strongSwan, Libreswan, Cisco, FortiOS, Junos or OpenBSD iked configuration carries a post-quantum
family, a protocol asset (`protocol: "ike"`) names `fragmentation` — `enabled`, `disabled`, the
value as written, or `not_found` in the files read — and `fragmentation_default` as each product
documents it: strongSwan yes since 5.5.1, Libreswan yes (5.4), FortiOS enable (7.6.6), Junos
enabled, iked `nofragmentation`. A file rarely carries the version, so a default is said as
documented, never as what the box does. **Cisco's is "default not confirmed"**: IOS XE and ASA
document opposite defaults and the platform is not in the file. FortiOS's numeric `set addkeN 36`
is read as ML-KEM (35–37), and 1080–1094 as Kyber, FrodoKEM, BIKE and HQC. Raised by Saqib Ahmad.

**Quantum-resistant mechanisms, not only algorithms** — RFC 8784 mixes a postquantum preshared
key into IKEv2 key derivation, so a tunnel resists a quantum adversary with no post-quantum
algorithm present. A scanner matching algorithm names cannot see that by construction, and
would report a protected deployment as `classical_only`. PPK is matched by the directives that
switch it on and classified as `quantum_resistant_mechanism` — deliberately not `pqc_ready`,
because a preshared key is not ML-KEM. Whether it holds depends on the entropy of the key and
on out-of-band distribution, neither of which is visible in a file, and the finding says so.

**CI/CD pipelines** — signing commands such as `gpg --sign`, `cosign sign`, `signtool`,
`jarsigner`, `codesign`. From 0.32.0 also Secure Boot, kernel-module and IMA/EVM signing, each
from its own manual: `sbsign`, `pesign -s`/`--sign`, `kmodsign`, `evmctl sign`/`ima_sign`/
`sign_hash` and the kernel's `scripts/sign-file`; and signing commands in any `.sh` file, not
only in the pipeline files — a pipeline often only calls the release script. A step that names
its key (`openssl dgst -sign KEY`, `-inkey KEY`, `--key KEY`, signtool's `/f FILE`, the key
argument of `kmodsign` and `sign-file`) carries `signing_key`: the path, `in_tree` — whether the
scan read a key or certificate file there, from the tree's root or the script's directory — and
the families it found in it. A path written with a variable is left alone. In the CBOM the steps
are still only counted. Raised by Ken Camp. Whether a trust anchor can be rotated in the field is
not in any file and is not inferred: that is the platform owner's statement.

**Infrastructure as code** — Terraform and Kubernetes key algorithms, and private key material
committed by mistake.

**Build files, includes, test recipes and key inventories** — `Makefile`, `CMakeLists.txt`,
`.in`, `.cmake` (a build file enumerates which algorithms a tree implements at all), `.inc`
(the assembly and C fragments of implementations — OpenSSL keeps its ML-DSA there), `.t` (Perl
test recipes: tests are code, and skipping them quietly is exactly what this tool argues
against), and `known_hosts` / `authorized_keys`, where the key type is named on every line.

**Not read, on purpose** — documentation: `.txt`, `.md`, `.pod`, `.rst`. Measured across five
real repositories, reading them would have added more than 11,000 "findings" from help texts
and changelogs. An algorithm mentioned in prose is not a deployment. The boundary is pinned by
a test, so it is a declared scope rather than a silent skip — the same standard this tool asks
of others. Binaries and images are not read either.

**Accidents of the alphabet are not findings** — a match inside a long hexadecimal or base64
run does not count. A NIST test vector in OpenSSH spells `ed448` inside its message bytes.

Real run against [OpenZeppelin's contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)
(711 files, about five seconds):

```json
{
  "detected_algorithms": ["ECDSA", "RSA"],
  "summary": {
    "quantum_vulnerable_count": 2,
    "pqc_ready_count": 0,
    "highest_severity": "high",
    "pqc_readiness": "classical_only"
  }
}
```

### Very long lines

A test-vector line can carry tens of thousands of hex digits. Until 0.25.0 every pattern searched
through such a run before the match was thrown away as sitting inside a blob, and the cost grew
with the square of the run's length: one 9,272-digit ML-DSA vector took 2.8 s for the 48 patterns,
and a scan of BoringSSL (12,921 lines over 2,000 characters) did not finish. Now the inside of a
blob is blanked before searching — positions and the blob's edge characters stay — and BoringSSL
takes 18 minutes. On nine corpora (certbot, OpenSSH, Vault, OpenSSL, curl, Mbed TLS, wolfSSL,
s2n-tls, rustls) every piece of evidence is identical before and after.

## What the coverage block says

Every scan carries one, because a coverage figure without its conditions is not comparable to
another coverage figure. Four things, each answering something the percentage cannot:

- **instrument** — the version *and the emitter's own commit*. Two runs of this package once
  reported the same version from code that differed by a commit, so the version alone does not
  identify what did the reading. Where the tool runs from an installed wheel built from a git
  checkout (from 0.37.0), `source_commit` names the commit it was **built from**, with
  `basis: built_from` — recorded at build time, not a checkout it runs from, and the installed
  files are not compared with it. A wheel built without git has no commit, and the field says
  which absence (`no_checkout`) rather than going quiet.
- **corpus** — the commit that was read, whether the tree was dirty, and whether the clone was
  shallow. A commit identifies a tracked tree; a scanner walks a filesystem, and the two are not
  the same thing.
- **window** — when it was read.
- **scope** — the denominator, the numerator, and *every file that was in the first and not the
  second, with a reason*. The reasons are a closed set: `type_not_claimed` is a boundary this
  tool declares, `unreadable` is a failure it hit, and they are never collapsed. A reason with no
  instances is reported at zero rather than omitted. From 0.27.3 every reason that carries a
  count also carries the `paths` it counts, `type_not_claimed` included: a count alone is not an
  accounting (R1 of the Coverage Attestation Profile, `draft-hillier-coverage-attestation-00`).
  On certbot that names 379 files that were until then only a number by extension.
  In the CBOM each list of names is one property holding a JSON array (`["a,b.c", "d.c"]`,
  `[]` when empty) from 0.28.0. Until then the names were joined by commas, and switched to one
  indexed property per name when any name held a comma: nothing was lost, but where the names
  sat depended on what they were called. Lists of objects (linked entries) stay indexed field
  by field.
  The declared boundary (`instrument.claimed_types`) names every way a file is read. Until
  0.29.1 it left out `.yaml`/`.yml`, the dependency manifests (`requirements.txt`, `pom.xml`,
  `packages.config`, `*.csproj`…) and a file of any type that begins with key material: a CAP-1
  examiner run by Joel Hillier over the certbot CBOM counted 44 such files examined outside the
  declared types. They were read all along; only the declaration was narrower than the scan.

Measured across five real repositories (certbot, OpenSSH, Vault, Bitcoin, OpenSSL) at this
release, the scan reads **67% of the files present** — 74% of OpenSSL, 85% of OpenSSH, 66% of
certbot, 77% of Bitcoin, 58% of Vault. The rest is counted and
named with a reason. A directory that cannot be entered or listed is reported in
`unreadable_directories`; its files cannot be counted, so the scan then says it cannot account
for every file instead of claiming it read them all.

It also states **which kind of claim the numbers are**. Coverage is a claim about reading, not
about finding: a file can be opened, counted, and still be one this tool was blind in. Reaching
a file is something a scanner can measure about itself; whether it found what was there is not,
because a silent rule and an absent algorithm produce the same output. So the block reports
`claims.axis: reached`, and declares that it holds no control — the corpus with independently
established contents that would license the second claim — naming the absence rather than
implying the stronger reading.

### What the number is, and what it is not

A coverage figure here is the overlap between the file types this tool claims and what the corpus
is made of. It is not a discovery rate. A scanner claiming 32 extensions cannot reach 100 % against
a tree holding 79 kinds, so a lower number means more file types left unclaimed rather than more
cryptography left unfound — and the two read identically unless the page says which it is.

The denominator stays conservative anyway: you cannot know a `.txt` holds no PEM block without
opening it, and key files often carry no extension at all.

### Concentration, and the partition it is measured over

The block reports **where the mass sits**, not only how large a total is — because an aggregate
over a lopsided population describes its largest members and reads as describing all of them.
Measured across five open-source repositories: three file kinds account for **52 % to 89 %** of
everything not read, and the two largest kinds present are **43 % to 55 %** of everything counted.

Three values travel with every share, and the third is the one most tools omit:

- **share** — how much the largest members are.
- **cardinality** — how many kinds that share is out of. Three of 24 kinds at 69 % is five and a
  half times a flat split; three of 63 at 68 % is fourteen times one. Without it the same share
  means different things and cannot be read as high or low at all.
- **partition** — what a kind *is*. A concentration is not a property of an aggregate but of the
  aggregate crossed with the partition it was measured over: the same tree split by extension, by
  directory, or by language gives different shares with nothing changing on disk. This block
  partitions by file extension and says so beside every figure.

The signer's sentence carries the same three inside the bracket holding the count, because a
figure lifted out of a document without them is the failure the block exists to prevent
(certbot at `56ee049`, 0.30.0):

```
This scan read 823 of 1250 files (65.84%); the remaining 427 (3 of 22, by extension —
files with no extension, .rst and .txt — being 73.09% of them) are listed with a reason each.
```

The published measurement, with the raw artefacts:
[quantumreadiness.eu/evidence/scan-coverage](https://quantumreadiness.eu/evidence/scan-coverage/)

## The CBOM it emits

`export_cbom` produces a CycloneDX 1.6 document, validated against the published schema; from
0.20.0 `qrp-mcp cbom PATH --out FILE` writes the same document to a file. Three things travel in
it that a component list alone cannot say:

- `compositions.aggregate` — `incomplete` where files were not examined, and `unknown` where
  the tool cannot account for its own reading. Reading every file is *not* enough for
  `complete`: that word claims every asset present was found, which is the second axis, and
  only a held control licenses it. The document used to say `complete` on the strength of the
  denominator alone; comparing against other scanners showed findings missed inside files that
  had been read.
- `properties` — the whole coverage block. It travels there because the root object is
  `additionalProperties: false` and the format has no field for it; the awkwardness is the point
  rather than something to hide.
- `evidence.occurrences` — file, line and matched text for every asset.

A policy or an IKE configuration is a `protocol` component whose `qrp:` properties carry what it
says — `qrp:security_policy` and `qrp:policy_status` (OPC UA, protocol type `other`, which is
CycloneDX's word for a protocol it has no name for), `qrp:policy`, `qrp:allows_versions`,
`qrp:post_quantum` and `qrp:default_applied` (AWS), `qrp:product`, `qrp:fragmentation` and
`qrp:fragmentation_default` (IKE) — because the matched text is masked by default and cannot carry
them.

Where the scan named the module, an algorithm component carries `qrp:providers` (a JSON array)
and `qrp:provider_validation`, which says that validation is not claimed and has to be checked
against the CMVP list for the deployed version. `certificationLevel` is never written: it states
a validation, and nothing in a file establishes one. From 0.32.0 the same component carries
`qrp:provider_pins` (a JSON object, provider → "version (manifest:line)") where a manifest pins
the provider's package, and `qrp:provider_configuration` where an `openssl.cnf` in the tree
activates the FIPS provider for a component whose provider is OpenSSL 3. A DNS size-budget asset
carries `qrp:udp_setting`, `qrp:udp_size` and, for BIND's default, `qrp:default_applied`; a weak
EC key is a `related-crypto-material` component with `qrp:curve`, `qrp:scalar` and `qrp:bound`.

Output is deterministic where it matters. The serial number is derived from the target, the two
pins and a digest of what was found, so the same code over the same corpus that finds the same
things gets the same serial, and a different result gets a different one. The whole CBOM is
byte-identical across two runs over one unchanged tree: the timestamp is the tree's commit time
(or `SOURCE_DATE_EPOCH`, or absent when neither exists), and the read window stays in the scan
result's `coverage.window`, named in the CBOM rather than carried.

## What kind of place a finding sits in

Two things about a match are not the match itself, and both now travel with it — in the
scan result and in the exported CBOM.

**Evidence kind.** `scan_repo` grades every match: `call`, `declaration`, `import`,
`reference`, `ban`, `comment`, and `default` -- a value the provider applies because the file
wrote none (an AWS listener with no `ssl_policy`), counted as in use, never as a comment or a
ban. Comment evidence is kept out of the inventory: a sentence that names an algorithm is
not a use of it. (An earlier version of this paragraph gave precision figures here with the
two tools swapped; the measured figures are under "Measured on a corpus this project did not
write" below.) The exported document
used to drop that grade, so a sentence about certificates reached an auditor looking
exactly like a signature: **78 of 465 occurrences on certbot (17%) and 1174 of 7142 on
OpenSSH (16%)**, including 493 ML-DSA and 429 ML-KEM mentions in OpenSSH, which is a lot
of prose to present as post-quantum adoption. An occurrence whose evidence is a comment
now says `[comment]`.

⚠️ A banned algorithm is not marked, it is **absent**: `!RC4` in a cipher list never
becomes a component. What the line forbids is not inventory; what it enables is.

**Test code.** A finding says whether it sits in test code, and the scan declares the
rule it used:

```json
"test_code": {
  "rule": "a path component named test/tests/testing/spec/specs/fixtures/testdata, or a file named test_*, conftest, *_test, *.test.*, *Test, *Tests, *_spec, *.spec",
  "meaning": "whether the finding sits in test code; named, not excluded",
  "findings_in_test_code": 144,
  "findings_in_other_code": 301
}
```

Components whose every sighting is test code also carry the **standard** field —
`component.scope: "excluded"`, which the schema has defined since 1.6 as documenting
"component usage for test and other non-runtime purposes". ⚠️ v0.18.0 shipped the per-occurrence
marker and no scope at all, which was a private spelling of a field the standard already had.

⚠️ And the honest measurement of that field: on certbot, **not one of the 31 components is
confined to test code** — every family that appears in a fixture also runs in production. At
component granularity `excluded` almost never fires on a real repository, which is exactly why
the per-occurrence marker is not redundant: `scope` is a property of the component, `[test]` is
a property of one sighting, and 144 of 445 findings need the second.

Those are certbot's real numbers: **almost a third of its findings are in fixtures.**
Nothing is dropped — a fixture's RSA key is real RSA. Whether it belongs in a particular
migration plan is the reader's call, and they can only make it if the document says which
is which. Occurrences in test code carry `[test]`, and a comment inside a fixture carries
both.

⚠️ **There is no external convention for this, which is why it is declared rather than
decided.** The two public corpora that could settle it — qscan's recall benchmark and the
cryben corpus of Näther & Hirsch — are 100% synthetic fixtures with no test/production
distinction. The rule here is a path convention, not a fact, so it is printed with the
numbers it produced; a reader who disagrees with the rule can see exactly what it caught.

## How sure the scan is of each occurrence

Every occurrence carries `confidence` — `high`, `medium` or `low` — and `confidence_basis`, the
reason in words. It is derived from what the scan read, not from a score it makes up:

- **What the line is.** A call, a parsed certificate or key, the value of a setting the scan
  parsed (a cipher list, a TLS group, a protocol version): `high`. A declaration or reference in
  source code, a protocol version named by a constant: `medium`. An import, a type in a Go
  function signature, a declared package: `low` — the line names the algorithm and does not use it.
- **Whether the family was read whole or inferred.** A family read from a piece of an identifier
  (`EC_KEY_free`), from an object identifier in a file that was not decoded, through a properties
  file, or through an alias, a constant in another file or literals concatenated on the line is
  one step lower. The fallback of a `getProperty` lookup, read because no properties file in the
  tree sets the key, is `low` whatever the line.
- Comments and bans are `low` and are not uses anywhere. The role is **not** an input. A row
  with a role is one that carries the `role` field (`signature`, `key_establishment` or
  `undetermined`). On Cryben, comments and bans left out, rows with one were 27/31 on a truth line
  and rows without one 42/45 (39/43 in release E), so it separated nothing. Counting only a known
  role (`signature`, `key_establishment`) gives 13/13 against 56/63: 13 rows, too few to build on.

It travels in the scan JSON, in SARIF (`rank` 90 / 60 / 30 and `properties.confidence`; `level`
stays the severity) and in the CBOM: CycloneDX 1.6 gives an occurrence no properties, so each
component carries `qrp:confidence`, a JSON array with one level per occurrence in the order of
`evidence.occurrences`. The coverage block counts the occurrences per level and carries the
measured precision of each level, so the figure travels with the document it describes.

**Precision by confidence level, measured on Cryben and the OWASP Benchmark 1.2, 25.10.2026**
(release E; comments and bans left out). The low row was re-measured on 26.10.2026 on 0.37.0's
detection; the high and medium rows did not move:

| level | Cryben (authors' truth, a row on a truth file:line) | OWASP Benchmark crypto + hash, with `benchmark.properties` | pooled |
|---|---:|---:|---:|
| high | 60/60 | 348/348 | **1.000** (408 rows) |
| medium | 2/3 | 73/73 | **0.987** (76) |
| low | 7/13 | — | **0.538** (13) |

On OWASP a row is graded when its family is one of the Benchmark's weak families for the case's
category: right when the case is true. On the OWASP subset **without** `benchmark.properties`
(the 2026-10-25 06-propusnato layout) the 27 `getProperty` fallbacks to `AES/ECB` are all wrong
— the property file sets AES/CCM — which is why a fallback is `low` (it was `medium` in release
E as first measured; the table above has no fallback row and did not move when it changed).

⚠️ What the table is not. Both corpora were used to choose the mapping, so it is a regression
figure, not a blind one. The medium and low buckets on Cryben are small (3 and 13 rows), OWASP is
Java only and separates nothing (every graded row there is right), and Cryben's truth does not
label Go signature lines, which decides part of `low`. 3 of the 7 right low rows are identifier
rows, which round 3 added, and a row is right when it sits on a truth line, whatever its family:
two of the three, `ec.dsa_sign_asn1` and `ec.dsa_verify_asn1` in `cinv-ruby-0014.rb`, say DSA
where Ruby's method on an EC key is ECDSA. Three other tools in this class print a confidence,
and none publishes its precision. Scored the same way on Cryben (05-novi-merki, 25.10.2026): CryptoScan 1.5.0 `HIGH` 0/10, `MEDIUM` 69/122, `LOW` 2/27; qScan 0.12.0 `high`
30/33, `medium` 11/11 (inverted); PostShor 0.1.0 one bucket, 27/40.

## What a TLS line does not establish

A line that configures TLS — `ssl_ecdh_curve`, `SSLOpenSSLConfCmd Curves`, `ssl_protocols`,
`MinVersion` — is what this server **asks for**, not what a connection **got**. The group is
settled where TLS terminates, together with the client, and that may be a proxy, a load
balancer or a CDN that is not in the tree. A CDN that upgrades origins on its own makes a
domain show `X25519MLKEM768` that nobody in the organisation configured; a classical
terminator in front of a post-quantum origin does the reverse.

This scanner reads files, so on the first case it reports the origin as classical: right
about the file, silent about the wire. Since 0.27.1 it says so, wherever it read TLS
configuration and nowhere else:

```json
"tls_termination": {
  "statement": "These files configure TLS. This scan reads files, not connections. ...",
  "configured_in": [
    {"path": "certbot/src/certbot/_internal/plugins/apache/tls_configs/current-options-ssl-apache.conf", "line": 11, "basis": "configured_group"}
  ]
}
```

`basis` is `configured_group` for a setting that chooses key-exchange groups,
`configured_protocol` for a pinned version and, from 0.32.0, `configured_cipher_suite` for a
setting that chooses cipher suites; from 0.33.0 `configured_listener` for an HAProxy `bind … ssl`. `null` when the tree configures no TLS; SSH configuration is
not counted here. On certbot: 42 places (25 protocol pins, 16 cipher-suite settings, 1 group
setting; 23 before 0.32.0, 39 before 0.33.0; measured on 0.34.0 and 0.35.0); on OpenSSH: none. The statement stays out of the CBOM, like
`files_read`.

From 0.31.0 the caveat is also beside every TLS setting, not only once per scan. Every evidence
item at one of those places — a pinned version under `evidence.protocols`, the source, CI or IaC
item on a group-setting line, and each classical group offered alone under `evidence.tls_groups`
— carries one short field that points at the statement:

```json
"tls_termination": "Configured, not negotiated: a terminator outside the files can negotiate otherwise. See tls_termination.statement."
```

It is the same in `scan --out`, in `scan_repo` at every level, and in `prove_closure`'s inputs,
where it is not part of an occurrence's identity, so a result written before 0.31.0 compares
with one written after. In the CBOM every TLS protocol component and every `(TLS group offered
alone)` component carries it as `qrp:tls_termination`; the long statement stays out. An algorithm
component (`X25519`, `ML-KEM`) is not marked: it gathers occurrences from TLS and non-TLS lines
alike, so a line setting only hybrid groups is marked in the scan result and not in the CBOM. On certbot:
54 evidence items at the 23 places; on OpenSSH: none. Nothing else changes: the same files read,
the same evidence and findings as 0.30.0. SSH settings and commented-out lines carry nothing.

From 0.32.0 that sentence is true of cipher suites as well. In 0.31.0 "every TLS setting" meant
protocol pins and group settings; a cipher-suite line — nginx `ssl_ciphers
ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA`, HAProxy `ssl-default-bind-ciphers` — gave its ECDH and
RSA without the pointer and was not in `configured_in` (we said so in public on 22 Oct 2026). A
suite is negotiated where TLS terminates, like a group, so a line that **sets** cipher suites is
now a place: nginx `*ssl_ciphers`, Apache `SSLCipherSuite`/`SSLProxyCipherSuite`, HAProxy's
`ssl-default-bind/server-ciphers(uites)` and `ciphers`/`ciphersuites` on a `bind` or `server`
line, OpenSSL's `CipherString`/`Ciphersuites` (and through `ssl_conf_command` /
`SSLOpenSSLConfCmd`), `SSL_CTX_set_cipher_list`, `set_ciphersuites`, Python's `set_ciphers`,
Envoy's `cipher_suites`, Go's `CipherSuites`, Java's `setEnabledCipherSuites`. A suite name on its
own is not: OpenSSL's headers define every suite as a C constant, and those configure nothing.
On certbot this adds 16 places and 50 evidence items with the pointer (104 in all); OpenSSH is
unchanged at none. In the CBOM nothing new is marked, for the reason above: the algorithm
components gather TLS and non-TLS lines alike.

**HAProxy** (from 0.32.0, raised by Kiran Murthy: "validate runtime negotiation points such as
load balancers"). Until then an `haproxy.cfg` with `ssl-default-bind-curves
X25519MLKEM768:X25519` and `ssl-default-bind-options ssl-min-ver TLSv1.2` gave its algorithms and
nothing else — no TLS place, no pin, no classical group offered alone, all three of which the same
settings in nginx got. Now `ssl-min-ver`/`ssl-max-ver` and `ssl-default-bind/server-options` are
read as protocol pins, and `ssl-default-bind/server-curves` and `curves` on a `bind` or `server`
line as group settings; the names are HAProxy's own (Configuration Manual 3.5,
`doc/configuration.txt`, read 22 Oct 2026). `ecdhe <curve>` is not read: ECDHE is in nearly every
cipher suite. Of the other terminators, Envoy (`tls_minimum_protocol_version: TLSv1_2`,
`ecdh_curves`, `cipher_suites`) was already read; **Traefik** (`minVersion: VersionTLS12`, a
`curvePreferences` list over several lines) and **Caddy** (a `Caddyfile` has no extension and was
not read; from 0.35.0 it is, and `x25519` in it is found as X25519, but `protocols tls1.2` and
the `curves` line are still not recognised as a TLS place) are not, tested on 22 Oct 2026.

**From 0.33.0**, after a local probe of 22 Oct 2026 that put a network scan of three TLS
endpoints beside a scan of the repository that configures them, five things that probe showed
the code scan missing:

- **An HAProxy listener that terminates TLS is a place.** `bind :8443 ssl crt edge.pem` is a
  protocol asset with `basis: configured_listener` and is in `configured_in`, and it names what
  neither its line nor the file's `ssl-default-bind-*` sets — `library_defaults: ["protocol
  versions", "TLS 1.2 cipher list", "TLS 1.3 cipher suites", "groups"]`, as many of them as are
  absent. There HAProxy's and the TLS library's defaults apply, and which they are depends on the
  versions that run, which the file does not say; the one default stated is HAProxy 3.2's own
  manual's (`ssl-min-ver`: "The default value is TLSv1.2"), named as that. The probe's edge
  listener said nothing in 0.32.0 and took TLS 1.2 with 13 suites on the wire.
- **RSA key exchange is named.** OpenSSL calls TLS_RSA_WITH_AES_256_CBC_SHA `AES256-SHA`: no
  word in the name says RSA, so `SSLCipherSuite HIGH:!aNULL:AES256-SHA:DES-CBC3-SHA` gave 3DES and
  nothing else. On a cipher-suite setting the 30 `TLS_RSA_WITH_*` names of `openssl-ciphers(1)`
  (OpenSSL 3.5), the `kRSA` keyword and the IANA spelling are now `evidence.static_rsa_kex` —
  RSA key exchange: no forward secrecy, and a recorded session opens to whoever later recovers
  the server's RSA key — with RSA on the line and a CBOM component `RSA key exchange (static RSA
  cipher suites)`. `ECDHE-RSA-…` stays RSA by authentication only; a suite struck out with `!` or
  `-`, a comment, a C constant and a lower-case strongSwan proposal are not counted. On certbot: 2
  lines (an Apache options file in the integration-test assets and a test vhost).
- **`SSLProtocol all` enables what it does not strike out.** mod_ssl's manual (2.4): `all` is
  `+SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3` with OpenSSL 1.0.1 and later (TLSv1.3 with 1.1.1,
  SSLv3 not where OpenSSL was built with `no-ssl3`). So `SSLProtocol all -SSLv3`, which 0.32.0
  reported only as "SSLv3 is forbidden here", now also gives TLSv1.0 to TLSv1.3, each with
  `included_by: "all"`, the two old ones `deprecated`. Whether the TLS library still allows them
  at run time is not in the line. On certbot: 60 protocol assets more (TLS places 39 → 42).
- **A backend whose certificate is not verified.** HAProxy `verify none` on a `server` or
  `default-server` line, its global `ssl-server-verify none`, and nginx `proxy_ssl_verify off`
  are protocol assets with `peer_verification: "off"` (`basis: configured_verification`): the hop
  is encrypted and not authenticated, and it is the one thing a scan from outside cannot see.
  They are not termination places. `verify` on a `bind` line is the client-certificate check and
  is left alone. ⚠️ nginx's default is also off (ngx_http_proxy_module: "Default:
  proxy_ssl_verify off"); a file without the line is not reported, and that is a boundary.
- **A hybrid group beside the image that has to negotiate it.** `evidence.library_support`: for
  each `image:` line (compose, Kubernetes) naming a TLS server image — nginx, haproxy, httpd,
  traefik, caddy, envoy, openresty — in a tree that configures a hybrid group (the IANA TLS
  Supported Groups names: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, the ML-KEM-512
  drafts, X25519Kyber768Draft00 …), whether that image can negotiate it. `support:
  "not_supported"` only where every step was read at a source: OpenSSL added the three RFC 10024
  hybrids in 3.5.0 (`CHANGES.md`), and `nginx:1.24.0` is docker-nginx's Debian image, `FROM
  debian:bullseye-slim`, whose openssl is 1.1.1w. That is the one image in the table; every other
  one, an `-alpine` tag included, is `"not_established"`, and says so. A compose service is joined
  to the configuration it mounts from the tree (`serves`, `serves_group_places`); without a mount
  the pin and the groups are named side by side, not joined. In the probe the repository set
  X25519MLKEM768 for a service that ops ran on nginx:1.24.0 with a classical hotfix mounted
  instead; nginx refused the repository's configuration. A `Dockerfile` is read from 0.35.0 for
  the algorithms it names, but its `FROM nginx:1.24.0` is not read as a pin, and a package pin is
  not read for this. The
  places and the mounts are not part of the finding's identity in `closure`; in the CBOM it is a
  `container` component. On OpenSSH and certbot: none.

The same probe said that two comments were counted as uses — `# … classical X25519 as fallback.`
above HAProxy's curves line, and `# … hybrid ML-KEM group preferred.` in an nginx file whose
server did not offer ML-KEM on the wire. Reproduced against 0.32.0, that is not so here: both are
`evidence_kind: comment`, outside `detected_algorithms` and the TLS places, and `[comment]` in the
CBOM (a test now pins it).

The statement says the same of authentication: a Merkle Tree Certificate is issued by the CA,
verified by the browser and often served from an edge, so an origin whose files name an ECDSA key
can be served with one — and its own key is still ECDSA, and reported as such. An AWS listener
policy is a TLS terminator in the tree, and counts as a place here.

**From 0.34.0**, after a systematic probe of 22 Oct 2026 that set the summary beside what the scan
had actually read, and four points raised in public the same day, the output stops being confident
where the evidence beside it was not:

- **`pqc_ready` is withheld past what was not read.** A value that says nothing classical is
  present — `pqc_ready`, `pqc_pre_standard`, `mechanism_protected`,
  `no_quantum_vulnerable_detected` — becomes `not_established` when files in the tree were not
  read (or a directory not entered, a linked directory not followed), or when a private key's
  algorithm was not determined (PKCS#8 embedded in source, an encrypted key file).
  `summary.readiness_not_established` says what it would have read and why not, e.g.
  `"1 of 2 files were not read (50.0% read); see coverage.not_examined"`. A value that warns is
  never withheld. In practice nearly every real repository has a file the scanner does not
  read (a `README.md`, a `LICENSE`), so on a real tree these four values give way to
  `not_established`, with the would-be value beside it. The case: ML-KEM in a module and a `Caddyfile` with `curves x25519`, which was not
  read (it is from 0.35.0, and the same tree now reads `hybrid_partial`); the summary said `pqc_ready` about the one file it had not opened (raised by Chandra
  Devadass). Files removed by the directory exclusions do not withhold it; they are named in the
  verdict instead (below).
- **The verdict names what the directory exclusions removed.** The directories left out before
  anything is counted are `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `vendor`, `dist`,
  `build`, `.tox`, `target`, `.pytest_cache`, `.mypy_cache` and `.ruff_cache`
  (`coverage.instrument.excluded_dirs`). A file under `vendor/` said "read every one of the 3
  files" of a 4-file tree; now the sentence ends "Left out before counting, by directory name: 1
  file in vendor/." `.git` is not named there (raised by Muhammad Atif).
- **A post-quantum family is not counted as ready where the evidence says it does not hold.**
  Where every use is a TLS place that a pinned image cannot negotiate (`evidence.library_support`,
  `not_negotiable`), the finding names the image in `not_negotiable_by` (also
  `qrp:not_negotiable_by` on the CBOM component) and the summary leaves it out of
  `pqc_ready_count` and the readiness. Where every use is test code, the finding carries
  `in_test_code: true` and the same applies; the CBOM already marked it `scope: excluded`. The
  classification is unchanged — ML-KEM is standardised — and test-only classical code still counts
  as vulnerable: the summary does not reassure from what it set aside, and never warns less.
- **What an RFC 8784 PPK protects.** One PPK line made a whole tree `mechanism_protected` with RSA
  signing in another file. The PPK finding now lists `protects`: the families used in the files
  that configure it. `mechanism_protected` needs every quantum-vulnerable family among them;
  otherwise the readiness is what it would be without the mechanism. Per family, not per
  occurrence: EC in the IKE file and EC elsewhere are one family. A PPK whose file says
  `ppk_required = no` (or switches it off) protects nothing and its reason says it is optional.
  ⚠️ strongSwan's default for `ppk_required` is also `no`; a `ppk_id` with no `ppk_required`
  line is not yet read as optional.
- **A recoverable private key raises its finding.** Where `evidence.weak_keys` finds k·G, the
  finding of that family is `weak_key: true`, severity `critical`, with the place in its reason,
  so `weak_count` and `highest_severity` say it too (raised by Sagar A.).
- **A denial block governs names, not calls.** `if (err.code === 'ERR_UNSUPPORTED') {` or
  `except UnsupportedAlgorithm:` opened a "denial block", and the classical fallback generated
  inside it read as a ban. A call is now a use wherever it sits; names listed under
  `forbiddenAlgorithms:` stay bans. A *declaration* in such a block (`curve = 'P-256'`) is still
  read as a ban.
- **A group removed with OpenSSL's `-` is a ban on the algorithm path too.** `Groups =
  DEFAULT:-X25519MLKEM768` switches the hybrid off; ML-KEM was detected from it. The algorithm
  rule now asks the same group-setting test as the TLS group rule.
- **LMS through its API.** wolfSSL `wc_LmsKey_*` (its `lms.h`), hash-sigs'
  `hss_validate_signature` and the other `hss_*` entry points for generating, loading and
  signing, and Bouncy Castle's `LMSSigner`/`HSSSigner` are HSS/LMS (raised by Dhiraj S.). XMSS through
  `wc_XmssKey_*`, `xmss_sign_open` and `XMSSSigner` was already matched and is now pinned.
- **`prove_closure` does not call a skipped file removed.** A key file the second run skipped by
  type was "removed — the file is not in the second tree" while it was there; every path in
  `coverage.not_examined` is now unread, so such an occurrence is `unverifiable`.

- **UTF-16 without a byte-order mark is read as UTF-16.** A `.ps1` saved by a Windows tool as
  UTF-16-LE with no BOM was decoded as UTF-8, gave nothing, and counted as read. One NUL in every
  byte pair, on the same side, over the first 4 KiB now selects UTF-16; text with more than about
  a tenth non-ASCII characters is not recognised this way.
- **Deprecated TLS versions reach the summary.** `summary.deprecated_protocols` lists the
  deprecated versions enabled in the tree (`TLSv1.0`, `TLSv1.1`, `SSLv3` …); a version struck out
  is not listed. `weak_count` still counts keys and algorithms only.
- **The coverage identity has four terms.** A linked file is in `files_present` and in
  `symlinks_not_followed`, not in the other three (below).

Not changed by any of this: what is detected, apart from the LMS names, the two ban rules and
UTF-16 above, and the coverage figures. On OpenSSH the files read, the evidence, the findings, the
summary's readiness and the verdict are the same as in 0.33.0. On certbot the same, but for one
evidence line: `make_key(elliptic_curve="nothere", key_type='ecdsa')` under `with
pytest.raises(…, match='Unsupported elliptic curve…'):` in a test is now a call, not a ban (ECDSA
was found elsewhere anyway); its summary gains `deprecated_protocols`. No file in OpenSSH,
certbot or wolfSSL is UTF-16 without a BOM.

**From 0.35.0**, after three probes of 22 and 23 Oct 2026 — a swarm that wrote each library's
own spellings as tests, a corpus probe with the expected inventory written before the scan,
and points raised on LinkedIn — what is read and named grows, and the summary says more:

- **Library spellings, each checked against the library's source.** OpenSSL's `DSA_sign`,
  `DH_compute_key`, `NID_ffdhe*`, `EVP_PKEY_CTX_set_rsa_*`, `RSA_size`, `MD5()`/`SHA1()`,
  `DES_ecb3_encrypt` and the `rsa.h`/`dsa.h`/`dh.h`/`md5.h` headers; Ed25519 glued into an
  identifier (`ED25519_sign`, `EVP_PKEY_ED25519`, `Ed25519PrivateKey`, `ed25519_dalek`,
  `x509.PureEd25519`); libsodium and PyNaCl (`crypto_sign_detached` is Ed25519, `crypto_box_*`,
  `crypto_kx_*`, `crypto_scalarmult*` and `nacl.public` are X25519 — not the
  `crypto_sign_keypair`/`crypto_sign_open` every post-quantum reference implementation also
  exports); JCA names by a table (`KeyFactory`/`KeyAgreement`, `DH`, `XDH` — X25519 unless
  initialised otherwise — `DES`, `DESede`, `ARCFOUR`, `SHA`, BCPQC `Falcon`) and the JCA EC types
  (`ECGenParameterSpec`, `ECPublicKey` …); Node's `'rsa-pss'`/`'dsa'`/`'dh'` key types,
  `crypto.publicEncrypt` and friends, `'des-cbc'`, node-forge `pki.rsa`; .NET `DSA.Create`,
  `DES.Create`, `SHA1/MD5.HashData`, `HashAlgorithmName.SHA1`, `CngAlgorithm.Rsa`;
  pycryptodome (`ECC`, `pkcs1_15`, `pss`, `PKCS1_OAEP`, `DES`, `DES3`, `Hash.MD5/SHA1`), python-rsa
  `newkeys`, paramiko `DSSKey`; wolfCrypt's whole classical API (`wc_*Rsa*`, `wc_ecc_*`,
  `wc_Dh*`, `wc_Md5*`, `wc_Sha*`, `wc_Des3_*`, `wc_falcon_*`) and headers; Mbed TLS `dhm`, `ecp`,
  `md5`, `sha1`, `des`, `des3` and the PSA RSA/DH/ECC key types; Bouncy Castle's `RSAEngine`,
  `DESEngine`, `RC4Engine`, `MD5Digest`, `SHA1Digest`, `FalconSigner`; ring/aws-lc-rs
  `RsaKeyPair` and `RSA_PKCS1_*`, rustls `SignatureScheme::RSA_PSS_*`, RustCrypto `Md5`/`Sha1`,
  `p256::`, `@noble/curves`; strongSwan's `KEY_RSA`, `SIGN_RSA_*`, `ENCRYPT_RSA_*` and `MODP_*`
  (OpenSSH's `KEY_RSA` too); liboqs's HQC by level (`hqc_1`) and UOV as `uov_ov_*`/`OV_*`;
  Falcon's padded variant; X-Wing (ML-KEM-768 + X25519, both halves) and CIRCL's
  `eddilithium2/3` (with their Ed25519/Ed448 halves); the classical half of oqs-provider's
  hybrids (`p384_mlkem768` is ECDH + ML-KEM, `p256_mldsa44` ECDSA + ML-DSA, `rsa3072_*` RSA).
  Three deliberate differences from the probe's expectation: pycryptodome's
  `Crypto.Protocol.DH` takes only ECC keys and is ECDH, not DH; `Crypto.Signature.DSS` signs
  with a DSA or an ECC key, so its import names neither; Go's `tls.CurveP256` is ECDH, as the
  TLS group table already files it.
- **Four lookalikes are not the algorithm.** `LMS_SHARED_SECRET` (not HSS/LMS),
  `personal_signature` (not the `personal_sign` call), Node's `createSign('SHA256')` (the key
  decides; `createSign('RSA-SHA256')` is still RSA) and `ml_dsa.sign` (not DSA).
- **Files that were "no extension" or "type not claimed".** `Dockerfile`, `Dockerfile-*`,
  `*.Dockerfile`, `Containerfile`, `Kconfig*`, a `Caddyfile`, extensionless files under
  `mods-available`/`mods-enabled`/`sites-available`/`sites-enabled` (FreeRADIUS's EAP-TLS module,
  Debian's nginx sites), `.jsx`/`.tsx`, and the Java keystores `.jks`/`.keystore`, whose
  certificates are clear DER. A lockfile is still read for its packages and no longer matched as
  source: `ecdsa-sig-formatter` in a `package-lock.json` was "ECDSA usage".
- **A TLS group offered alone is a finding of its family.** `Groups = x448:mlkem768` put X448 in
  `evidence.tls_groups` and nowhere else, and the summary said `pqc_ready`; `ffdhe2048` likewise
  gives DH.
- **What a PKCS#12 file says in clear.** Its bag encryption (`pbeWithSHAAnd40BitRC2-CBC` → RC2,
  `…3-KeyTripleDES-CBC` → 3DES, the RC4 forms) and its SHA-1 MAC are named from the unencrypted
  wrapper; the file is still `claimed_but_not_decoded`, because the bags were not read. RC2 is a
  new weak family.
- **COSE algorithm identifiers** on a WebAuthn or COSE line (`{"type": "public-key", "alg": -7}`
  is ES256), from IANA's registry. A bare `"alg": -7` stays a number.
- **RFC 8784, two narrowings.** strongSwan's `ppk_required` defaults to `no` (its swanctl.opt),
  so a `ppk_id` without `ppk_required = yes` is an optional PPK and protects nothing; and a family
  is protected only when every use of it sits under a required PPK — EC in a second tunnel
  without one was counted protected by the first.
- **Two shapes of the denial block.** A block a condition opens (`} catch
  (UnsupportedAlgorithmError) {`) is the code that runs then, not a list of banned names, so a
  declaration inside it is a use; a `pytest.raises`/`assertRaises` block whose line says
  "unsupported" is a test that the call inside is rejected, so the call is a ban.
- **Who owns a place.** `.github/CODEOWNERS`, `CODEOWNERS` or `docs/CODEOWNERS` (GitHub's order;
  then `.gitlab/CODEOWNERS`) is read, never matched for algorithms, and every evidence item gets
  `owners` and `owners_source` (`.github/CODEOWNERS:3`) from the last matching line — per place,
  not per component, because one algorithm sits in many teams' code. In the CBOM it is an
  `[owners: … per FILE:N]` tag on the occurrence: the schema has no field for it. It is the
  file's assumption, not a fact about who runs the code; `codeowners` says which file was used.
- **Key establishment and signatures apart.** `summary.by_role` gives each its families and its
  own readiness: nginx offering X25519MLKEM768 with an ECDSA certificate is `hybrid_partial` for
  key establishment and `classical_only` for signatures, where the whole read only
  `hybrid_partial`. RSA and EC go where their lines' roles put them and are listed under
  `role_not_determined` where a line's role could not be read; a reassuring part is withheld
  with the whole.
- **de-bsi follows the 2026 documents.** TR-02102-1 2026-01 recommends FrodoKEM-976/1344 and
  Classic McEliece beside ML-KEM, each in hybrid; the BMDS/BMI/BSI Leitlinie of 11 Sep 2026 asks
  for the initial cryptographic inventory by the end of 2026 (§4.3) and high-risk use cases by
  2030. A McEliece or FrodoKEM finding under `de-bsi` keeps NIST's `candidate` and says, in
  `profile_standing`, that the BSI recommends it.
- **A DNSSEC algorithm number with no family is named.** A `DNSKEY 257 3 253` record
  (PRIVATEDNS) was dropped without a word; it is now a protocol asset with `dnssec_algorithm` and
  IANA's mnemonic, no family is invented, and it withholds `pqc_ready` like an unread file.
- **FreeRADIUS's `tls_min_version = "1.0"`** is TLS 1.0, deprecated.
- **SHA-224, SHA3-224 and AES-ECB are seen**, with what NIST SP 800-131A Rev. 3 proposes —
  quoted from its initial public draft of October 2024 and said as a draft (no final revision
  on CSRC on 23 Oct 2026). Their classification is unchanged (hash, symmetric).

On OpenSSH the files read, the coverage (84.77%), the findings, the readiness and the verdict are
the same as in 0.34.0; the evidence gains 865 lines (761 Ed25519 identifiers such as `KEY_ED25519`
and `ed25519_pk`, 85 `KEY_RSA`, 11 DH headers and `DH_compute_key`, 8 more RSA) and loses none.
On certbot 9 more files are read (four Dockerfiles, four nginx `sites-*` files, `CODEOWNERS`):
coverage 65.84% → 66.56%; the findings, the readiness and the 42 TLS places are the same; one
evidence line moves from a call to a ban (`make_key(… key_type='ecdsa')` under
`pytest.raises(… 'Unsupported elliptic curve …')`).

**From 0.36.0**, after a measurement of 23 Oct 2026 that took the names each crypto library
publishes in its own public headers (OpenSSL, BoringSSL, Mbed TLS, wolfSSL, libsodium, liboqs,
NSS, GnuTLS, libgcrypt, libssh2) and from registries and language APIs (JCA/Bouncy Castle, Go,
.NET, Rust, Python, IANA TLS/SSH/DNSSEC/JOSE/COSE), and ran every name through the scanner. Rules
written from examples found the examples; the names below were missed:

- **An algorithm as a whole part of a library identifier.** A name that starts with a prefix the
  library owns is split at `_` and case changes, and each part that names an algorithm reports
  its family: `GNUTLS_SIGN_DSA_SHA256`, `GCRY_MD_SHA1`, `LIBSSH2_HOSTKEY_HASH_MD5`,
  `PSA_WANT_ALG_*`, `OPENSSL_NO_DSA`, `RSA_R_*` error codes, `d2i_DSAPublicKey`,
  `PEM_write_bio_RSAPrivateKey`, `gnutls_pubkey_export_rsa_raw`. Without a prefix only OpenSSL's
  module API counts, and only where it is called or declared (`DSA_free(`, `SHA224_Init(`):
  `DH_STATUS_OK`, `DESCRIPTION` and `rsa_logo_draw` stay silent, and `ML_DSA` is not DSA.
- **OIDs, by name and by number.** `NID_`/`SN_`/`LN_`/`OBJ_`/`SEC_OID_` names, X.509 object names
  as strings (`sha1WithRSAEncryption`, `id-ecPublicKey`), and the well-known dotted OIDs from their
  RFCs (`"1.2.840.113549.1.1.5"` is RSA with SHA-1), also as Go `asn1.ObjectIdentifier{…}`.
- **PKCS#11:** `CKK_*`, `CKM_*` and `CKA_*` name the algorithm (`CKK_RSA`, `CKM_ECMQV_DERIVE`).
- **Cipher suites name what they imply:** OpenSSL's `TLS1_CK_*`/`SSL3_CK_*`, JSSE `SSL_*`, and
  OpenSSL strings such as `DES-CBC-SHA` and `EXP-RC4-MD5` now report the RSA or DH they leave
  unspoken, and the SHA-1 of the record MAC.
- **Headers, C types and classes:** `<openssl/ec.h>`, `<mbedtls/dhm.h>`, `EC_GROUP`, `MD5_CTX`,
  `RC4_KEY`, Bouncy Castle and JCA classes such as `DSASigner`, `ECDHBasicAgreement`,
  `RSAKeyGenParameterSpec`.
- **JCA and Bouncy Castle spellings:** `SHA256WithRSAEncryption`, `SHA256/RSA`,
  `…inP1363Format`, PSS/OAEP/`PKCS1v15()`, ECIES/ECMQV/det-ECDSA, PBE names with their digest
  and cipher, ElGamal.
- **Families that were not in the vocabulary:** GOST R 34.10, SM2 (reported as EC before),
  ElGamal — all quantum-vulnerable; MD2, MD4 and RC2 as weak; HAETAE, SMAUG-T and AIMer as
  candidates, never `pqc_ready`; BIKE, NTRU LPRime, XMSS^MT and LMS/HSS class names.
- **Language qualifiers:** Go `dsa.`, `elliptic.`, `crypto.SHA1`, `x509.DSA`, `ssh.KeyAlgoRSA`;
  Rust `k256::`, rustls and ring constants; .NET Cng types, padding modes and CryptoConfig
  names; pycryptodome `RSA.generate`, python-rsa.
- **Protocol settings:** TLS SignatureScheme `rsa_pss_*`/`rsa_pkcs1_*`; sshd `des-cbc`,
  `hmac-md5`, `curve448`; strongSwan proposals; rare `Groups =` curves; DNSSEC `dsa`, GOST and
  SM2; JOSE/COSE `RS1`, `HPKE-*` and numbers; JWK `"kty":"EC"`.
- **Both halves of a hybrid:** `MLDsa65WithECDsaP256`, `ssh-mldsa87-p384`,
  `KeyExchangeMLKEM768X25519`, `SHA512WITHMLDSA65`.
- **SHA-1 joined to something** (`HmacSHA1`, `SHA1_`, `-SHA1`), never `sha1sum` or a sentence;
  X448 in camelCase, all `efrodokem_*`, the LMS constants of wolfSSL, liboqs and Mbed TLS.

Two policies decided with it. **MD5, SHA-1 or DES used as a MAC, PRF or KDF is reported**, under
the hash or cipher, and its description says the use and that a quantum computer does not break
it: an inventory that drops a use silently is the defect we would name in another tool. **An
algorithm named in prose is not a finding** — in a comment, as before, and now in a sentence
inside a string (`"supports Ed25519 and ML-KEM"`: three or more words, one of them a word
only prose uses); it goes to `named_but_not_used`. A name as
a whole part of an identifier is a finding.

On OpenSSH the files read (740 of 873, 84.77%), the readiness by role and the verdict are the same
as in 0.35.0; the findings grow from 65 to 70 (DES, GOST R 34.10 from the bundled `pkcs11.h`,
RC4, SHA-224, SHA3-224 are new families) and the evidence from 8,016 to 8,659 lines; no family
loses a line. On certbot the files read (832 of 1,250), the findings and the readiness are the
same; the evidence grows from 628 to 656 lines (TSIG `HMAC-SHA1`, `-SHA` suites in server
configs, pyca `ec.EllipticCurve*`). No family loses an evidence line in either. A scan of OpenSSH
took 28 s against 26 s for 0.35.0 on the same machine (one run each).

⚠️ What is not claimed: recall on real code. The rules were written against the measured names;
how much of a real codebase's cryptography is named this way was not measured. Still not seen:
the inside of a certificate (a PEM file is reported, not what signed it) and TPM 2.0 names.

**From 0.38.0**, the fixes promised in public comments and the rows of the fix list since 0.37.0:
- **`--mandate nist-ir-8547` follows the final NIST IR 8547 (October 2026).** Every
  quantum-vulnerable signature and key establishment is deprecated after 2030 and disallowed
  after 2035, whatever its strength; the November 2024 draft spared RSA-3072, P-256 and Ed25519
  the 2030 date. X25519 and X448 get their strength from their names. The classical half of a
  hybrid group on the line that names it (`X25519MLKEM768`) is `composite_allowed` (section
  3.2.1) and not HNDL-exposed; a classical group offered on its own in the same list
  (`X25519MLKEM768:X25519`) keeps its dates. The block names the date the gate counts
  (`gate_counts`, `next_gate_deadline`) beside `next_deadline`, the earliest date of any clause.
  The gate itself still counts the disallowance, as before.
- **A fingerprint of the findings beside the file's digest** (row 178, from Mark McGovern's
  reply): see *Without an agent*. Two scans of one commit now print the same `findings sha256`
  and, as before, different file digests.
- **The pinned version travels** (row 165, Daniel Stokes). A dependency row has `version` where
  the manifest pins one (`cryptography==45.0.4` in requirements.txt or go.mod, a single `==` in
  pyproject.toml or a Pipfile); a range is not a version and gives none. The CBOM `library`
  component carries it as `version`, or `qrp:versions_pinned` with every pin where manifests
  disagree. Which default key exchange a library version brings is not resolved.
- **Python's `ssl.TLSVersion`** (row 166): `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` is a
  protocol row and a TLS place, as pyOpenSSL's `set_min_proto_version` already was.
- **A TLS default is said, not left blank** (rows 164, 167, Daniel Stokes). Where the tree
  configures TLS and no file sets a group or curve, `tls_termination.key_exchange` says the
  library's default applies and is not resolved, with the library versions the manifests pin;
  each TLS protocol asset says `key_exchange: "library default, not resolved"` (in the CBOM,
  `qrp:key_exchange`). Where no key-establishment family was found either, the headline is
  `not_established` with that reason instead of `unknown`, which now means only that nothing was
  found; `by_role.key_establishment` says `not_established` too. The default is not computed from
  the version: OpenSSL 3.5 offers a hybrid first, earlier versions a classical group, and what a
  deployed build does is not in the files.
- **An occurrence nobody owns is said** (row 174, Michael Wegger). With a CODEOWNERS file, each
  occurrence in a path no line covers carries `unowned_by: <that file>`, `codeowners.unowned`
  counts and lists them, and the CBOM occurrence reads `[owners: none per <file>]`. Owners are
  still the file's assumption, not a fact.
- **An AWS TLS policy the table does not hold is named** (row 175, Tokunbo Taiwo). An
  `ELBSecurityPolicy-*` name set as `ssl_policy`/`SslPolicy` that is not in the table is a TLS
  protocol asset with `policy_known: false` and "not determined" versions and groups; the
  listener is a TLS place, and the headline is `not_established` naming the policy. It claims
  no algorithm. Before, the listener dropped out: 0 findings, "read every one of the 1 files".
- **A declaration says where it is imported** (row 157, Caleb Montour, Magpie Projects). A PyPI
  or npm dependency row gets `imported_in` (the first ten `path:line`) and its description says
  where; it stays `declared_dependency`, because an import does not say which algorithm a call
  uses. `dependencies_not_in_table` lists the packages requirements.txt, pyproject.toml, Pipfile
  or package.json declare that the library table does not hold: whether they carry cryptography
  (a provider's SDK doing TLS inside) is not determined. Lockfiles are not listed there.
- **The size beside the algorithm, and a choice made outside the files** (rows 156, 176, Peter
  van Walsem). `algorithm: RSA` with `key_size: 2048` in the same YAML block, or Terraform's
  `algorithm = "RSA"` with `rsa_bits = 4096`, now gives the size. A cryptographic setting whose
  value is read at run time -- `set_ciphers(os.environ[...])`, `JWT_ALGORITHM: ${{ vars.X }}`,
  `$VAR` or `${VAR}` in a file -- is listed in `chosen_outside_files` with the setting and where
  the value comes from (counted in the CBOM as `qrp:chosen_outside_files:count`); no family is
  claimed for it, and what the environment holds is not read. Its quoted line follows `--level`.
- **RSA-OAEP encryption is key establishment** (row 161, Joeri Barbier). pyca's
  `pub.encrypt(k, padding.OAEP(...))` was `role: undetermined`, because the rule's description
  ("signature or padding name") was read as a signature signal beside the line's OAEP; it no
  longer is, so the line is key transport and, under `--mandate`, HNDL-exposed. On the four
  control trees one line moved the other way: paramiko's `padding=padding.PKCS1v15(),` is now
  `undetermined` (PKCS#1 v1.5 pads both encryption and signatures; it was `signature` only by
  that description).
- **A group setting's family comes from its values** (row 172a). `ssl_ecdh_curve MLKEM768;`, a
  post-quantum group alone, reported ECDH because the directive is called `ecdh_curve`, and read
  `hybrid_partial`. On a group setting whose values name no classical elliptic-curve group, ECDH
  is not reported; `secp384r1` and `X25519MLKEM768` keep it.

**From 0.37.0**, the work of releases A to E and of round 3 (the commits after `v0.36.0`):

- **For CI.** `qrp-mcp scan PATH --format sarif` writes SARIF 2.1.0; every file not read is a
  notification with its reason. `qrp:ignore <family> <reason>` and
  `qrp:ignore-next-line <family> <reason>` suppress a row, which is listed and counted, never
  dropped; a marker without a family and a reason does not apply and is listed. `--write-baseline`
  / `--baseline` mark rows new or baselined, and the counts are in `coverage.baseline`. A
  `.qrp.toml` (profile, level, exclude, baseline, mandate, lead_months) is read unless
  `--no-config`; the command line wins. `--mandate cnsa-2.0|nist-ir-8547` gives each
  quantum-vulnerable occurrence its dated clause and `hndl_exposed`, and with `--lead-months`
  the run exits 1 when a deadline falls inside the lead time. On Python 3.10 `tomli` is a
  dependency, so `.qrp.toml` is read there too.
- **The document names the code that ran.** `version` is the running code's, and a disagreeing
  installed distribution is said beside it; `instrument.revision` gives the commit or the absence
  of one in words; `dirty` looks at the package directory only. The CBOM is byte-identical across
  two runs over one tree: its timestamp is `SOURCE_DATE_EPOCH`, else the commit time of a clean
  checkout, else absent. Every file the evidence cites carries its SHA-256. An installed wheel
  built from a git checkout names the commit it was built from (`source_commit.basis:
  built_from`, `revision: "<commit> (built from)"`); one built without git still says
  `no_checkout`. Two runs of wheels built from one commit can be compared by `prove_closure`.
- **Reports in the tree are not cryptography.** A CycloneDX document, a qrp-mcp result, a SARIF
  log, a baseline and a `.qrp.toml` are named as report documents and not matched; a CycloneDX
  document another tool wrote is listed as a supplier's declaration, for `--ingest`.
- **The CBOM carries more.** OID, NIST and classical security levels, `cryptoFunctions` and the
  curve on algorithm assets; one component per key size or parameter set, with the key length
  wherever the files give one; a hybrid as a component that depends on its two halves; one
  library component per bom-ref however the manifests spell it; certificates, parsed with
  `cryptography`, as certificate assets with their subject key nested; `non_security_use` on the
  occurrence.
- **Every occurrence carries a confidence** (high, medium, low) and its basis, in the scan
  JSON, SARIF (`rank`) and the CBOM; see *How sure the scan is of each occurrence*.
- **Detection.** Algorithm names from the IANA SSH, TLS, JOSE and COSE registries, OpenSSH's
  and OpenSSL's own name lists and PEM labels; a family as a component of an identifier, in a
  file with other cryptography, at low confidence; XML-DSig URIs, pyOpenSSL types, DH-parameter
  calls, key specs, COSE constants and SSH key-exchange messages; Jinja templates, SSH key file
  names, key types in tasks, DH parameters and sshd RSA options in configuration; Rust types and
  variants; cipher strings split at `+`, GnuTLS priorities and C suite tables; curl's crypto API
  by its prefix; OpenSSL's curves API as EC key agreement and `ffdhe*` as DH; dependencies in
  `pyproject.toml` and `Pipfile`, as requested; `crypto-js`; algorithm settings in `.properties`
  joined to `getProperty` (a fallback default is low); key-type values in a key-type context;
  `usedforsecurity=False` as the role `non_security_use`; sops, age and OpenPGP secrets at rest,
  with HNDL; uses reached through an alias, folded literals or another file's constant.
- **Read as what they are.** A Go `func` signature is a type reference; a suite part or key-type
  value in a comment is a comment; libcrux's `DsaXof` and an ML-DSA component are not DSA, a
  KEM's DH is not DH; the JDK's `EdECKey` is EdDSA; a Python test whose docstring says an option
  is removed or disabled is a rejection test, and an expected error message is text; an OpenSSH
  `.cert` and a DER request are not unparsed certificates. ECDSA and EdDSA names are not DSA:
  .NET's `eCDsa`, `testEcDsa256`, `EdDSA25519`; nor is the signature encoding DSA and ECDSA
  share, pyca's `encode_dss_signature`, `DssRawSignatureVerifier`, .NET's `DSASignatureFormat`.
- **Identifier rows never move the headline.** A family whose every use is an identifier row
  stays a finding, marked `identifier_only`, and is not counted in `pqc_readiness` or `by_role`;
  identifier rows set no RSA or EC role. In SARIF an identifier row is a `note`, as a comment
  is, and `--mandate` gives it no clause, so it counts in no block and trips no gate.
- **Speed.** One search per file finds the lines a rule could match; files are read in parallel
  (`QRP_MCP_JOBS`); a compiled line gate, `qrp-mcp-core`, is used when installed
  (`QRP_MCP_CORE=0` turns it off; the answers are the same); the rules' compiled form is cached on
  disk (`QRP_MCP_CACHE=0` turns it off); the MCP SDK and pydantic are no longer imported on the
  scan path. `qrp-mcp-core` installs with qrp-mcp, as a wheel, on CPython for Linux x86_64 and
  aarch64, macOS x86_64 and arm64, and Windows AMD64 and ARM64; elsewhere qrp-mcp is pure Python.
  On an Intel i5-3340M (warm median): with the core, curl takes 1.35 s and OpenSSH 2.20 s, faster
  than qScan 0.12.0 (4.16 s, 2.32 s) and slower than cipherscope 0.3.0, which is compiled (0.94 s,
  1.10 s). Without it, curl takes 3.48 s and OpenSSH 4.02 s: still faster than qScan on curl, and
  slower than qScan on OpenSSH. How it was timed is in *How it is measured*.

⚠️ What is not claimed here: a detection figure. The rules of round 3 were written against corpora
read for that purpose; what they do on code nobody has read is what the final judgement of 0.37.0
measured, and its results are in *How it is measured*.

### A classical group offered on its own

From 0.28.0 a classical group named as a group of its own in a group setting — `X25519` in
`ssl_ecdh_curve X25519MLKEM768:X25519`, `prime256v1` in `SSLOpenSSLConfCmd Curves`, `tls.CurveP256`
in Go's `CurvePreferences`, `ffdhe2048` in `jdk.tls.namedGroups` — is a finding of its own, under
`evidence.tls_groups`, with `offered: "alone"` and `basis: "configured_group"`. A hybrid's name
(`X25519MLKEM768`) is one token and is never counted here; a group removed with OpenSSL's `-`
prefix is not an offer; a name the table does not hold (`auto`) yields nothing.

Before, removing the classical fallback was invisible: the X25519 inside the hybrid is the same
family as X25519 alone, so the scan before and after was identical and `closure` called the
one-line change "3 closed, 3 new". The new finding carries no excerpt — its identity is file,
setting and group — so removing the fallback shows as **closed**, and editing the line around a
fallback that stays leaves it **still open**. `per_family_before_after` counts it apart, as
`X25519 offered alone`. In the CBOM it is a component, `X25519 (TLS group offered alone)`. The
three source findings on the edited line still close and reopen, because their identity includes
the line's text; that is how every edited line has always been compared. On certbot: 3 (X25519,
prime256v1, secp384r1 in the Apache options file); on OpenSSH: none.

⚠️ What is not claimed: that a connection ever uses the fallback. That is settled where TLS
terminates, as above; the finding is about the file.

### A classical SSH key exchange offered on its own

The same defect existed in OpenSSH until 0.31.0: `KexAlgorithms mlkem768x25519-sha256,curve25519-sha256` and `KexAlgorithms
mlkem768x25519-sha256` scanned the same, because the X25519 inside the hybrid's name is the family
of `curve25519-sha256` too, and removing the classical fallback from `sshd_config` closed nothing.
Now a classical algorithm in a `KexAlgorithms` list (`sshd_config`, `ssh_config`, `ssh -o
KexAlgorithms=…`) is a finding of its own, under `evidence.ssh_kex`, with `offered: "alone"`,
`setting: "KexAlgorithms"` and `basis: "configured_kex"`. The names are OpenSSH's own — every
algorithm `sshd_config(5)` lists that `kex-names.c` marks as not post-quantum (OpenSSH at
`7fe3b24`): `curve25519-sha256` (and `@libssh.org`), `ecdh-sha2-nistp256/384/521` and the
`diffie-hellman-group*` names. The hybrids (`mlkem768x25519-sha256`, `mlkem768nistp256-sha256`,
`sntrup761x25519-sha512`) are never counted. OpenSSH's prefix applies to the whole list: a list
beginning with `-` removes what it names, so nothing in it is an offer; `+` (appended to the
default) and `^` (placed at its head) still offer it, and the finding says the default set is
not named on that line.

It is kept apart from `tls_groups` because an `sshd_config` is not a TLS configuration: it adds no
place to `tls_termination`. In `closure` removing the fallback is **closed**
(`curve25519-sha256 offered alone`), and in the CBOM it is a component,
`curve25519-sha256 (SSH key exchange offered alone)`. On OpenSSH: 3, all in `regress/` test
scripts; on certbot: none. Nothing else in either scan changes: the same files read (740 of 873,
823 of 1,250) and the same evidence and findings as 0.30.0.

⚠️ What is not claimed: which algorithm a connection uses. The client chooses from what the
server offers, and an sshd built without a hybrid, or a jump host in front, is not in the files.

⚠️ What is not claimed: that the tree's TLS settings are all listed, or which terminator is in
front. The scanner cannot see a connection; the field says that, not what the connection is.
Raised in public on 1 October 2026, where a measurement at the front door met the same gap
from the other side.

## Whether a fix closed it

A finding missing from the second scan has not necessarily been fixed. It may have moved down
the file, moved to another file, landed in a directory the second run could not open, or
stopped matching because the scanner changed. Each of those looks exactly like a fix when the
only question is "is it still in the list".

`prove_closure(before, after)` takes two saved results (`qrp-mcp scan PATH --out FILE`) and
answers in two steps:

1. **Can these two runs be compared for closure?** Same instrument commit, version, rules, file
   types and exclusions; both trees pinned to a commit and clean; both results quoting lines at
   the same level. Run from an installed release (`uvx qrp-mcp`, `pip install`) there is no
   commit to name; two runs of the **same installed release** are accepted on its version, and
   the result says so in `basis` — weaker than a commit, since a locally modified install would
   carry the same version string. The trees may differ — that is what is measured. If the runs cannot be
   compared, **nothing is reported as closed**, the reasons are listed, and the repair is named:
   scan the first commit again with the instrument that did the second.
2. **Only then, occurrence by occurrence, without line numbers:** `closed`, still open (and how
   many only moved lines), `relocated` to another path (a rename is not a fix), moved into or
   out of test code (neither is a fix), `new`, `unverifiable` — in a file the second run did
   not read — and `removed`: the whole file is gone from the second tree. A deleted file does
   remove its code, but it is also the cheapest way to make a finding disappear, so it is named
   apart and **not counted as closed**. A file the second run could not open is never counted
   as fixed. An occurrence's `provider` is shown but is not part of its identity: it can come
   from the file's import line, and editing that line does not close the calls below it.

From 0.20.0 every scan lists `files_read` by name, beside the counts. That is what tells a fixed
line from a deleted file; it stays out of the CBOM. Two results without it (0.19.0) are reported
as `unestablished`, not compared on a weaker rule.

Checked on a copy of certbot (521 occurrences): removing one RSA call closed exactly that one;
inserting blank lines closed none and reported two moved; renaming a file closed none and
reported two relocated; a masked scan against a full one was refused. Two scans of OpenSSH
with the same instrument: 7,143 still open, 0 closed. A second run with an emitter that had
uncommitted changes was refused as `instrument_dirty`. With 0.20.0 installed in a clean
environment, deleting one RSA line in `client.py` and the whole of `challenges.py` gave
`1 closed, 1 removed`, each on the right file and line.

⚠️ What is not claimed: that the fix is correct, only that the occurrence is gone from every
file the second run read. Other scanners close findings between scans too — Semgrep, SonarQube,
GitHub code scanning, and Keyfactor AgileSec ("Deleted findings are automatically resolved",
3.4 release notes). Semgrep marks a finding "Removed" rather than "Fixed" when its rule changed
or its path went away, and GitHub records the tool version to track changes it caused; both do
this as a status after the fact. What was not found in the sources read is a **refusal, before**
calling anything fixed, when the reader changed between the two scans. SonarQube documents that
a file dropped from scope is counted as fixed. They keep a history across many scans; this
compares two documents. A statement about the sources read on 2026-09-27, not a survey of
every tool.

## What to replace it with

Each finding that is quantum-vulnerable or deprecated carries a `replacement`: what to use,
for which role, and the standard that says so, with its address. It is a suggestion; nothing is
applied, nothing leaves the machine, no model is asked.

| Found | Suggested | Source |
| --- | --- | --- |
| ECDH, X25519, X448, DH | ML-KEM | FIPS 203 (final, 13 Aug 2024) |
| ECDSA, EdDSA, Ed25519, Ed448, DSA | ML-DSA or SLH-DSA; LMS/XMSS for firmware signing | FIPS 204, FIPS 205, SP 800-208 |
| RSA, EC | by the role read from each line (below); both where a line does not show it | as above |
| RSA below 2048 bits | two steps: ≥ 2048 now, post-quantum next | SP 800-131A Rev. 2 |
| BLS, Schnorr | **no approved drop-in replacement** — the aggregation property has none; a redesign | FIPS 204/205 as the nearest |
| MD5, SHA-1 | SHA-256 or SHA3-256 | RFC 6151, SP 800-131A Rev. 2 |
| RC4, DES, 3DES | AES (AES-GCM for RC4's place) | RFC 7465, FIPS 46-3 (withdrawn), SP 800-131A Rev. 2 |
| a post-quantum scheme that is not a NIST standard | a standardised one | FIPS 203/204/205 |

Transition dates come from the final NIST IR 8547 (October 2026): every quantum-vulnerable
signature and key-establishment scheme deprecated after 2030 and disallowed after 2035, whatever
its strength. Until 0.38.0 they came from the November 2024 draft, which spared the 128-bit rows
(RSA-3072, P-256, Ed25519) the 2030 date. Hybrids are named as NIST names them — accommodated, and
temporary. The CBOM is not changed: CycloneDX has no standard field for a recommendation, and
this project does not add a private one.

### Whose rules: national profiles

The table above is NIST's. Other authorities disagree with it and with each other, so from
0.22.0 `--profile` (`qrp-mcp scan`) and `profile` (the `scan_repo` tool) choose whose words fill
the options. The CBOM carries no replacement, so it has no profile. Detection is byte-for-byte the same under every
profile; only `replacement` changes, and the result names the profile in `replacement_profile`.

| profile | authority · document | key establishment | signatures | hybrid |
| --- | --- | --- | --- | --- |
| `nist` (default) | NIST · FIPS 203/204/205 | ML-KEM | ML-DSA, SLH-DSA; LMS/XMSS for firmware | accommodated, temporary |
| `us-cnsa2` | NSA · CNSA 2.0 FAQ v2.1 (Dec 2024), CNSSP 15 | ML-KEM-1024 only | ML-DSA-87 only; SLH-DSA not approved; LMS/XMSS single-tree | not required |
| `uk-ncsc` | NCSC · Next steps v2.0 (Aug 2024) | ML-KEM-768 recommended | ML-DSA-65 recommended | allowed, at a cost |
| `au-ism` | ASD · ISM (Sep 2026) | ML-KEM-1024; 768 not beyond 2030 | ML-DSA-87; 65 not beyond 2030; no hash-based | not recommended, not prohibited |
| `ca-cccs` | CCCS · ITSP.40.111 v5 (May 2026) | ML-KEM-512/768/1024 | ML-DSA-44/65/87, SLH-DSA; LMS/HSS/XMSS/XMSS^MT | not addressed |
| `de-bsi` | BSI · TR-02102-1 (2026-01) | ML-KEM-768/1024, **hybrid** | ML-DSA-65/87 hedged, **hybrid**; hash-based alone | lattice schemes recommended only in hybrid form |
| `fr-anssi` | ANSSI · PG-083 v3.00 (Mar 2026) | ML-KEM-768 (512 conformant), **hybrid** | ML-DSA **hybrid** only; SLH-DSA alone | required for ML-KEM, ML-DSA |
| `nl-ncsc` | AIVD/CWI/TNO · PQC Migration Handbook, 2nd ed. (Dec 2024) | ML-KEM-1024/768 | ML-DSA-87/65 | recommended |
| `eu-eccg` | ECCG · Agreed Cryptographic Mechanisms v2.0 (Apr 2025) | ML-KEM-1024/768, combined | ML-DSA-87/65 combined; hash-based alone | lattice not standalone |
| `bg` | — · no Bulgarian guidance found | NIST's | NIST's | EU roadmap: end-2026 / 2030 / 2035 |

⚠️ **What a profile is not.** Each is one document read on 2026-09-27, and each says whom that
document addresses — CNSA 2.0 is written for US National Security Systems, the ECCG list for EU
product certification, the NCSC paper for OFFICIAL-tier and enterprise data. Choosing one does
not make it law for the reader, and the tool makes no legal finding. For the weak algorithms
(MD5, SHA-1, RC4, DES, 3DES) and for the first step of an RSA key under 2048 bits, an
authority's own minimum replaces NIST's row where it has been checked against the text:

| profile | weak hash → | weak cipher → | RSA under 2048, now → |
| --- | --- | --- | --- |
| `us-cnsa2` | SHA-384 or SHA-512 | AES-256 | (CNSA 2.0 admits no RSA; NIST's step) |
| `de-bsi` | SHA-256/384/512, SHA-512/256, SHA3 (Table 4.1) | NIST's | at least 3000 bits |
| `fr-anssi` | ≥ 256-bit output; ≥ 384 for post-quantum security | AES-128; AES-192/256 for post-quantum security | 2048 until 2030, 3072 from 2031 (3072 recommended now) |
| `au-ism` | SHA-384 or SHA-512 (224/256 not beyond 2030) | AES-128/192/256, preferably 256 | at least 2048, preferably 3072; RSA not beyond 2030 |
| `ca-cccs` | NIST's | NIST's | at least 2048, at least 3072 by the end of 2030 |

Where a cell says NIST's, the result says so in `follows` or `first_step_follows`. A role an authority does not fill is left out
rather than filled with NIST's answer: the ISM names no hash-based signature, so `au-ism` offers
none. Documents change — the ISM quarterly, TR-02102-1 yearly — and each profile carries its
version and address so a stale one can be recognised.

### The role of an RSA or EC line

From 0.21.0 every RSA and EC occurrence carries a `role`, read from its own line: `signature`
(`RS256`, `rsa-sha2-256`, `SignPSS`, `sha256WithRSAEncryption`, `ECDHE-RSA-…` in a cipher list),
`key_establishment` (OAEP, `EncryptPKCS1v15`, `TLS_RSA_WITH_…`, a `kex` table) or
`undetermined`. A key generated or declared on a line is used somewhere else, and this reads one
line, so such a line stays `undetermined`; so does a line with signals for both, and a cipher list
longer than the 200-character excerpt. The finding's `replacement` counts the roles of its lines
of code (comments carry a role but are not counted) in `roles_seen`, and drops a path only when
no line showed that role **and** no line was undetermined. Every path says how many lines it is for.

⚠️ **Against this:** on every corpus measured, both paths stayed. Undetermined lines of code:
certbot 208 of 229, OpenSSH 172 of 456, Vault 361 of 656, OpenSSL 3,354 of 3,893. The count is
the gain, not a shorter list.

**Role-assignment precision on a sample** (not detection; judged from the source ±5 lines, not
from the excerpt the rule saw; rules frozen at `3287c1c` before these corpora were opened; seed
20260927):

| corpus | `signature` correct | `key_establishment` correct | `undetermined` with the role visible nearby |
| --- | --- | --- | --- |
| Vault `41e571b` | 30 / 30 | 17 / 20 | 5 / 20 |
| OpenSSL `223e04f` | 25 / 30 (5 should have been undetermined) | 14 / 20 | 4 / 20 |
| Bitcoin Core `33a363e` | none to sample | none to sample | 0 / 8 |

The nine wrong `key_establishment` lines had two causes, both in TLS names: `TLS_ECDHE_RSA_WITH_…`
written with underscores was read as ECDH, and in `ECDH_RSA` suites RSA only signs the certificate
of a fixed ECDH key. **Fixed in 0.23.0**, together with lines that name PSS beside the generic RSA
key type (a table of both uses, now `undetermined`); on Vault and OpenSSL 13 of the 14 are now
right. Measured again on two corpora these rules had not seen (rules frozen at `8ab8e9c`, seed
20260928, same method):

| corpus | TLS-name lines | `key_establishment` | `signature` | `undetermined` with the role visible nearby |
| --- | --- | --- | --- | --- |
| curl `b3640b0` | 17 / 17 | 20 / 20 | 30 / 30 | 13 / 20 |
| Mbed TLS `c0748be` | 20 / 20 | 8 / 8 | 30 / 30 | 17 / 20 |

No wrong role in 125 assigned. ⚠️ The samples are concentrated in tables of cipher suites (47 of
70 curl lines from one test file), which is the easiest case for a rule that reads one line. And the
misses are systematic: `TLS_RSA_PSK_WITH_…` (RSA transports the key) and TLS groups for EC
(`groups=secp256r1`) are left `undetermined` although the role is plain.

**0.24.0** reads both: RSA-PSK as key establishment, and a TLS group as key establishment in its
TLS spellings only (`groups=`, `set1_groups_list`, `+GROUP-`, `selected_group`, `IANA_TLS_GROUP_`) —
`EC_GROUP_new` and `ecp_group` are the curve's mathematical group and say nothing about the role.
Measured on two more corpora these rules had not seen (frozen at `b2eb73b`, seed 20260929):

| corpus | psk/group lines assigned | `key_establishment` | `signature` | `undetermined` with the role visible |
| --- | --- | --- | --- | --- |
| wolfSSL `3c5eead` | 1 / 1 | 15 / 20 (5 should have been undetermined) | 30 / 30 | 4 / 20 |
| s2n-tls `e691294` | 3 / 3 | 20 / 20 | 30 / 30 | 5 / 20 |

Still no wrong role. ⚠️ **But the group fix reached little:** 4 of 40 psk/group lines. s2n-tls names
its groups `Group::secp384r1`, `"group.supported.secp256r1"`, `kem_group`; wolfSSL `ctx->group[0]` —
the rule was written from Mbed TLS's spellings, and 15 of 17 s2n-tls group lines stay undetermined.
And in C `RSA_public_decrypt` verifies a signature; a switch that handles it together with
`RSA_PUBLIC_ENCRYPT` was called key establishment (the five above).

**0.25.0** reads the raw RSA signature operations of C (`RSA_public_decrypt`, `RSA_private_encrypt`)
as signature (a role is only put on a finding, and until 0.27.0 those two lines were found only when
something else on the line named RSA), and the other group spellings (`Group::`, `NamedGroup`, `kx_group`, `kem_group`,
`group.supported`, `supported_groups`, `negotiated_curve`). Measured on BoringSSL and rustls, which
these rules had not seen (frozen at `b8bd5ce`, seed 20260930):

| corpus | crypt/group lines assigned | `key_establishment` | `signature` | `undetermined` with the role visible |
| --- | --- | --- | --- | --- |
| rustls `99f2358` | 18 / 18 | 20 / 20 | 30 / 30 | 2 / 20 |
| BoringSSL `5112448` | **1 / 3** | **14 / 20** | 30 / 30 | 2 / 20 |

🔴 **Seven wrong roles in BoringSSL, one cause, and it was in 0.24.0 as released:** the rule for
`group(` — written for Mbed TLS's `psk_ephemeral group(secp256r1)` — also took BoringSSL's C++
accessor `group()`, which returns the curve's mathematical group, as a TLS group
(`EC_POINT_mul(group(), …)` → key establishment). 0.25.0 accepts `group(` only with a curve or group
name inside. That narrows the rule and cannot add a role: on BoringSSL exactly 95 lines change, all
from key establishment to undetermined, all `group()`. The seven are among them. The fix itself was
not measured on a corpus it had not seen.

## How it is measured

From 0.37.0 detection is measured one way, against the free scanners we compared against, so
that a reader can see what was done and repeat it. These are our measurements: the corpora were
chosen here, the labels are a model's judgement checked by hand here, and the scripts were run
here. No outside party has repeated them.

**Corpora.**

- **A blind corpus**: public repositories, each pinned to a commit, frozen before any rule was
  tuned and never opened by anyone writing rules.
- **A second hold-out**, frozen the same way. Repositories later found to overlap with data the
  rules were tuned on are excluded, and the exclusion is stated beside the result.
- **Cryben** (Näther & Hirsch, arXiv 2608.04857), scored with its authors' own `compare.py`.
- **A recall corpus published by another scanner's authors**, scored with its own metric.
- **The OWASP Benchmark** 1.2, its crypto and hash categories, with its own scorer.
- **liboqs** at commit `e1f480f3`: its own `docs/cbom.json` is the declared list of post-quantum
  families, and each tool's rows on `src/` are scored against it by family.

**Labels.** Chunks of the blind corpora are sampled with a fixed seed. Truth is labelled by an
LLM judge: a chunk counts as cryptographic at a score of T = 0.6 or more, and a chunk in the grey
band below it is drawn again before its mean is kept. Labels are spot-checked by hand and frozen
before any tool is scored; no label is changed after a tool's output has been seen.

**Units.** Precision, recall and F1 at the chunk level and at the line level, each with its own
denominator. On the blind corpus and the second hold-out only the nine quantum-vulnerable public-key
families are scored: RSA, DSA, DH, ECDH, ECDSA, EdDSA, X25519, X448 and secp256k1. Hashes, ciphers
and post-quantum rows are not scored there, so they are never a false positive. A generic `EC`
row counts for ECDH, ECDSA and secp256k1, and an `ECDSA` row for secp256k1, for every tool alike.

**Comparison.** Two tools are compared by a paired bootstrap over files (chunks of one file are
correlated) of ΔF1, 2,000 resamples, fixed seed 20261025. A tool is beaten when the 95% interval of
ΔF1 is above 0, loses when it is below 0, and otherwise it is a tie, reported as a tie. A resample
whose ΔF1 is undefined is dropped. The blind corpus's frozen `paired.py` then reads the interval at
positions 50 and 1949 of the sorted list, which are the 2.5 % and 97.5 % points only when all
2,000 resamples are kept; the hold-out's copy takes `int(0.025 · n)` of the n kept.

**Other measures.**

- **A negative corpus** of files with no quantum-vulnerable cryptography: the count of findings
  there must be 0.
- **Rewrite robustness**: the same use written another way (an alias, folded literals, a
  constant from another file) must still be found.
- **Near misses** — cryptography named, banned, discussed or tested against, but not used — read
  as a Pareto pair (hits on the near misses, recall on the corpus), never as one number.
- **Timing**: the warm median of interleaved rounds (one untimed warm-up, then each tool in turn,
  round after round, so drift in load hits every tool alike; a run waits while the machine is
  busy). A container tool's time includes the container's start; qrp-mcp runs on the host. The
  machine is named: for 0.37.0 an Intel Core i5-3340M (2 cores, 4 threads, 2.70 GHz). On it a
  scan of curl takes under 10 s. With the compiled core, qrp-mcp is faster than qScan 0.12.0 on
  curl and OpenSSH (20 of 20 paired rounds) and slower than cipherscope 0.3.0. Without the core
  it is faster than qScan on curl and slower on OpenSSH (0 of 10 rounds). qScan's time includes
  its container's start (0.4 to 0.6 s); timed inside the container, outside the method, qScan
  takes 1.85 s on OpenSSH, less than qrp-mcp's 2.20 s with the core.

**The tools run.** Every other tool ran offline in a throwaway container
(`docker run --rm --network none`, the corpora mounted read-only, `ubuntu:24.04` unless named);
qrp-mcp ran on the host from a virtualenv, with `SOURCE_DATE_EPOCH=1761350400`. The other tools
got no `SOURCE_DATE_EPOCH`: they ran with their defaults. JSON is the timed call; a CBOM, where
the tool writes one, is a second untimed call. Outside the timing rounds the other tools ran at
`nice -n 19` (the container's default), and so did qrp-mcp in the blind and hold-out judges'
runs; in the scoreboard's runs qrp-mcp ran at normal priority.

Not every tool is scored on every corpus. The table lists the eleven tools the scoreboard ran, on
certbot, Mbed TLS, curl, OpenSSH, the negative corpus and the probes (hyperion on certbot, the
OWASP Benchmark and the reproductions only). The
blind corpus scores qrp-mcp, CryptoScan, qScan, cipherscope, PostShor, QuantumSeal, RivicQ and
hyperion; the second hold-out the same without RivicQ and hyperion; neither scores foxguard,
snoot or cdxgen. Two readings are scored as tools of their own: `ours-code`, qrp-mcp without its
comment, ban and `named_but_not_used` rows, and QuantumSeal read by its component id beside
QuantumSeal read by the text it matched. The blind corpus's frozen `paired.py` bootstraps against
QuantumSeal, CryptoScan and qScan only; the judges' wrapper adds the others.

| tool | version | what was run |
|---|---|---|
| qrp-mcp | the candidate's commit | `qrp-mcp scan PATH --no-config --out FILE`, `qrp-mcp cbom PATH --no-config --out FILE`; with the compiled core and with `QRP_MCP_CORE=0`. The earlier releases the blind judge scores as references (`relall-re`, `v036-re`) ran without `--no-config` and with `QRP_MCP_CORE=0`; the blind and hold-out corpora hold no `.qrp.toml` |
| CryptoScan | 1.5.0 | `cryptoscan scan PATH --no-config --format json --stream=false --no-color -o FILE`; `--format cbom` |
| qScan | 0.12.0 | `node dist/cli.js PATH --format json --no-config-file --severity-threshold critical -o FILE`; `--format cbom`; the host's node v22.23.3, mounted into `ubuntu:24.04` |
| cipherscope | 0.3.0 | `cipherscope --roots PATH --gitignore=false -o FILE.jsonl` |
| RivicQ | build of 23.10.2026 | `rivicq scan PATH --format json --fail-on NONE`; `rivicq cbom PATH --format json` |
| QuantumSeal | build of 23.10.2026 | `quantumseal scan PATH --format json --output FILE` |
| PostShor | 0.1.0 | `postshor scan PATH -q -o FILE.json -o FILE.cdx.json` (in `python:3.12-slim`) |
| foxguard | 0.14.1 | `foxguard pqc PATH -f json --output FILE -q`; `-f cbom` |
| snoot | 0.1.0 | `snoot scan PATH --format json --output FILE --quiet --no-color`; `--format cbom` |
| cdxgen | 13.5.0 | `cbom -o FILE --no-install-deps --spec-version 1.6 --json-pretty PATH`, `FETCH_LICENSE=false`, `CDXGEN_TEMP_DIR=/tmp`; a 700 s limit on the probes and the four corpora, 300 s on the reproductions |
| CBOMkit-hyperion | `ghcr.io/cbomkit/cbomkit-action:edge` (digest `sha256:7dfc905c614549fdb630d41a33b34a039af7f60c982501c6d74dfc63ef700512`) | `nice -n 19 java -Xmx4g -jar CBOMkit-action.jar` with `CBOMKIT_LANGUAGES=java,python,go`, `CBOMKIT_GENERATE_MODULE_CBOMS=false`, `CBOMKIT_EXCLUDE=zz_nomatch_zz` |

**Reproducing it.** The scanner side is the two `qrp-mcp` commands above, run on each corpus
at its pinned commit with `--no-config` and `SOURCE_DATE_EPOCH=1761350400`. The scripts that
sample the chunks, call the judge, score each tool, run the bootstrap and time the rounds are
**not yet published**: they are not in this repository. Until they are, a reader can repeat the
runs, not the scoring.

**What it does not show.** These are our measurements, not an independent evaluation. The
truth of the blind corpora is a model's judgement, checked by hand on a sample, not a human
label of every chunk. Cryben, the OWASP Benchmark and the recall corpus were seen while rules
were written, so on them a result is a regression figure, not a blind one. A tie is a tie: it
is not reported as a win.

**Results.** The final judgement of 0.37.0, 26.10.2026. The figures are for 0.37.0's detection
as the judges ran it, commit `a0c391f`, re-measured after the DSA fix (ECDSA and EdDSA names,
the signature encoding DSA and ECDSA share). The last commit before the release narrows that
fix so dropbear's `DROPBEAR_SIGNATURE_DSS` stays DSA; the two rows it restores lie outside every
sampled chunk, and the output on certbot, Mbed TLS, curl and OpenSSH is unchanged.
The best other tool is the one with the highest F1 on that corpus and unit; ΔF1 = qrp-mcp − that
tool.

| corpus (exclusions) | unit | qrp-mcp 0.37.0 P / R / F1 | best other tool: P / R / F1 | ΔF1 (95% CI) | verdict |
|---|---|---|---|---|---|
| second hold-out, 9 repositories (cfssl and mina-sshd excluded: both are in the development corpus at the same commit, and cfssl is named in the source) | chunk | 0.944 / 0.864 / 0.902 | QuantumSeal (by matched text): 0.912 / 0.896 / 0.904 | −0.002 (−0.055, +0.047) | tie |
| | line | 0.716 / 0.835 / 0.771 | QuantumSeal (by matched text): 0.764 / 0.832 / 0.797 | −0.026 (−0.079, +0.029) | tie |
| blind corpus, 18 repositories (`ansible-collections/community.crypto` excluded: named in `detectors.py`) | chunk | 0.916 / 0.878 / 0.897 | QuantumSeal (by matched text): 0.922 / 0.763 / 0.835 | +0.062 (+0.026, +0.101) | beat |
| | line | 0.723 / 0.851 / 0.782 | QuantumSeal (by matched text): 0.726 / 0.740 / 0.733 | +0.049 (+0.010, +0.090) | beat |
| blind corpus, 18 repositories, configuration files only (24 truth pairs, 45 lines: low power) | chunk | 0.818 / 0.708 / 0.759 | QuantumSeal (by matched text): 0.909 / 0.750 / 0.822 | −0.063 (−0.222, +0.073) | tie |
| | line | 0.725 / 0.733 / 0.729 | QuantumSeal (by matched text): 0.800 / 0.778 / 0.789 | −0.060 (−0.226, +0.097) | tie |
| Cryben, full (197 occurrences; the authors' `compare.py --no-restrict`, location mode) | occurrence | 0.613 / 0.249 / 0.354 | CryptoScan 1.5.0: 0.428 / 0.345 / 0.382 | −0.028 (−0.108, +0.049) | tie |
| Cryben, source only (166 occurrences; certificate, key-material and negative-control folders left out by a fixed path rule, for every tool) | occurrence | 0.672 / 0.235 / 0.348 | CryptoScan 1.5.0: 0.426 / 0.361 / 0.391 | −0.043 (−0.134, +0.052) | tie |
| qScan's recall corpus (176 file-level labels; qScan's own metric; recall only) | label | R = 0.926 (163/176) | qScan 0.12.0: R = 0.847 (149/176) | sign test: 22 wins, 8 losses, p = 0.016 | beat |

- "By matched text": QuantumSeal's family read from the text it reports matching with each
  occurrence, the reading on which it scores higher; both readings were fixed before labelling.
  Read by its own component id it scores F1 0.659 / 0.577 (hold-out, chunk / line) and 0.610 /
  0.475 (blind), and qrp-mcp beats it on both corpora and both units.
- With the excluded repositories put back (11 on the hold-out, 19 on the blind corpus) the verdicts
  are the same, except the blind corpus's configuration files at chunk level: a loss to
  QuantumSeal by matched text, −0.138 (−0.288, −0.029).
- Every other tool (CryptoScan, qScan, cipherscope, PostShor, and on the blind corpus RivicQ and
  hyperion) loses to qrp-mcp on the hold-out and the blind corpus, on both units. On Cryben,
  PostShor loses to it, and qScan and cipherscope tie.

**The scoreboard** (certbot, Mbed TLS, curl, OpenSSH, the negative corpus and the probes; the
same commit, the same day) against the ten other tools:

| measure | qrp-mcp 0.37.0 | best other tool | verdict |
|---|---|---|---|
| true rows only one side has, per pair of tools | more than the other tool on every pair | — | beat |
| named CBOM fields (of 9) | 9 | hyperion 5 | beat |
| CBOM schema validity | 8/8 | 8/8 (four tools) | tie |
| a hybrid as a component depending on its two halves | 3 linked | 0 | beat |
| CISA item 4: service / key length / certificate expiry | 1.00 / 0.67 / 1.00 | 1.00 / cdxgen 0.56 / 1.00 | tie / beat / tie |
| CI: SARIF, inline suppression, baseline, configuration, accounted (of 5) | 5 | CryptoScan, PostShor 4.5 | beat |
| PEM bundle | 3/3 with key, signature and validity | PostShor 3/3 | tie |
| dependency manifests read (of 12) | 11 | qScan 7 | beat |
| dated mandate clause, gate, HNDL (of 3) | 3 | qScan 3 | tie |
| coverage inside the CBOM | 8 compositions | 0 | beat |
| liboqs post-quantum families (of 17) | 16, plus XMSS and LMS | qScan 5 | beat |
| findings on the negative corpus | 0 | 0 (every tool) | tie |
| near misses: hits, recall | (102, 0.92) | none dominates it | tie (Pareto); on the hit count alone, lose |
| silent truncation | 0 silent, 1 named | — | beat |
| SHA-256 of every evidence file | 628/628 | 0 | beat |
| byte-identical CBOM across runs | yes | snoot yes | tie |
| OWASP Benchmark crypto / hash | 1.000 / 1.000 | hyperion 0.759 / 0.690 | beat |
| speed, warm median, curl / OpenSSH | 1.35 s / 2.20 s with the compiled core; 3.48 s / 4.02 s without | cipherscope 0.94 s / 1.10 s; qScan 4.16 s / 2.32 s | under 10 s; faster than qScan with the core (20 of 20 paired rounds); slower than cipherscope |

Five of six functions checked are in none of the ten other tools: a hybrid's two halves, the
SHA-256 of every evidence file, `usedforsecurity=False` read as `non_security_use`, calibrated
confidence levels, and a report document recognised and named. The key-length win is on the
pre-registered column; on the open-size families (RSA, DSA, DH) qrp-mcp has 19/30 = 0.63 against
cdxgen's and hyperion's 2/2.

## Measured against the other scanners

⚠️ **Outdated.** This section and the next describe comparisons made in September 2026 on
0.8.0 to 0.11.0. Their figures were not re-measured with the method of *How it is measured*,
and they will be replaced by its results, not carried forward.

In September 2026 three free tools that do the same job — CryptoScan, CBOMkit-hyperion
(sonar-cryptography) and CBOMkit-theia — were run over the same repositories and the findings
compared line by line. What they found and this tool did not became the 0.8.0, 0.8.1 and
0.9.0 releases. Of what this tool does that they did not, one claim needed narrowing when a wider
survey was done, and it is corrected here:

- **Coverage inside the document.** Several tools do report what they skipped: QuantaKrypto's
  `qscan` counts scanned and unread files, IBM Quantum Safe Explorer logs each excluded file
  with a reason, SandboxAQ shows missed locations. What we have not found elsewhere is the
  coverage travelling **inside the CycloneDX CBOM** — a reason per group of unread files, the
  paths that could not be read, the directories that could not be entered, and
  `accounts_for_every_file`. `qscan` computes the counts and drops them on export, so it is one
  flag away from the same thing.
- This scanner separates **reading from finding** in the document itself, and refuses to say
  `complete` without a control that licenses the stronger claim. Reading is self-measurable;
  finding is not.
- **sntrup761**, the default hybrid in OpenSSH from 9.0 to 9.9 — OpenSSH 10 defaults to
  `mlkem768x25519-sha256` — has no rule in CryptoScan; this tool reports 145 lines of it in the
  OpenSSH tree.
- **Private keys are recognised by content**, not by file name: the 45 key files CBOMkit-theia
  found in OpenSSH and this tool did not are read from 0.9.0, and a PEM header with the body
  elided — documentation — is not one.
- An excluded cipher (`!MD5`) is counted as a *use* by CryptoScan; here it is an exclusion.
- On certbot, this scanner finds algorithms in 26 files against hyperion's 7, and hyperion's
  one extra finding is wrong (`RSA-96` where certbot defaults to 2048).

## Measured on a corpus this project did not write

The nearest tool of the same kind is **QuantaKrypto's `qscan`** — lexical like this one by its
own changelog, and the only other tool in this class that publishes a detection figure. In
September 2026 both were run against **Cryben** (Näther & Hirsch, arXiv 2608.04857): an
independent corpus with its own reference CBOM and its own scorer, written by neither of us.
The scripts and the raw output are reproducible; the method matters more than the number.

| | qscan 0.12.0 | this tool 0.8.1 | this tool 0.11.0 |
|---|---|---|---|
| Cryben, in the scope this tool declares | 30/37 | 22/37 | **36/37** |
| qscan's own corpus, qscan's own metric | 0.847 | 0.511 | **0.909** |
| the same, no wildcard credit for either tool | 0.790 | — | **0.818** (see below) |
| qscan's corpus without its structural labels | 0.802 | 0.714 | **0.944** |
| Cryben, full 197 findings, precision | **0.93** | — | 0.667 |
| Cryben, full 197 findings, F1 | 0.34 | — | **0.346** |
| a negative corpus, 200 files with no such cryptography | — | — | **200 clean** |
| Vault, wall clock | 7.9 s | 173 s | 219 s |

⚠️ **Every figure in that table was measured on 0.11.0 and has not been re-measured since.**
0.12.0 changes what counts as a use: an external retest found that a denial word anywhere on a
line -- including inside a comment, including the word `weak` in a variable name -- turned a real
key into a ban and dropped it from the inventory. Fixing that necessarily moves both recall and
precision, in directions this table cannot state until the corpora are run again. The numbers
below are the previous release's, labelled as such rather than quietly carried forward.

**Three denominators appear in that table and they are not the same question.** 37 is the number
of Cryben cases inside this tool's declared scope; 176 is the label count in qscan's recall corpus;
197 is Cryben's full finding set. A recall figure over one of them cannot be read against an F1 over
another, and earlier versions of this section invited exactly that. Each row belongs to one task and
one denominator; none of them combine.

**`200 clean` is not a precision figure.** Its denominator is negative files, not emitted findings.
It says the scanner stayed silent on 200 files that contain nothing; it says nothing about how many
of the findings it *does* emit are right. Precision is the row two lines above it, and it is the row
this tool loses.

**The independent control is not published.** The Cryben corpus, its scorer and the raw runs behind
`36/37`, `0.667` and `0.346` are not in this repository. Until they are, those three are this
author's claims rather than something a reader can check, and an external comparison said so in
those words. Publishing the artefacts is the repair; restating the numbers is not.

Four things those numbers do not mean, said here rather than left to be assumed:

- **Cryben is 37 cases in this tool's scope.** A figure from 37 cases has a wide interval. It is
  a floor worth publishing, not a precision claim.
- **The scorer is theirs, and it credits a finding that names nothing.** qscan's metric matches
  per file, not per line, and 10 of its hits name no algorithm at all. A tool that reports
  "something cryptographic is here" scores the same on those as one that says which family it is,
  so detection and family classification have to be published apart. They are not, here, yet.
  An earlier version of this section claimed the figure was unchanged
  with that credit withdrawn. It was wrong: the switch that withdrew it dropped only one bucket,
  while elliptic-curve findings kept the credit unconditionally. Withdrawn properly, **and applied
  to both tools**, the numbers are **0.818 for this tool and 0.790 for qscan**. The conclusion
  survived the correction; the sentence did not.
- **A per-scan control is still not held.** `claims.control.held` stays `false` in your scan
  unless you run one, and it should: a figure measured here says nothing about your repository.
- **Recall is not the axis this tool is weakest on — precision is.** On Cryben's full 197
  findings, scored by its authors' own tool, this scanner's precision is 0.667 against qscan's
  0.93. It was 0.542 one release ago. Reaching a rival's recall while reporting more that the
  reference does not is not the same as being the better inventory, and it would be dishonest to
  publish the first number without the second.

**Three levels of evidence, because a quoted line of code is not always safe to send.**
`--level full` carries the line itself. `--level masked` keeps its shape with everything but the
algorithm name starred out — `*** = rsa.********_*******_***(***_****=****)` — so a reader sees a
call rather than a string without seeing the contents. `--level trimmed` carries no line at all.
The file and the line number stay in all three.

The masking rule is inverted from the obvious one. A rival tool masks by position, keeping the
first characters and starring the rest, which keeps whatever the line happens to begin with — a
token, a key, a password. Here only the characters that spell the algorithm survive; every other
letter and digit becomes a star, and punctuation stays because the shape of a call is not a secret.
An independent analysis of this scanner found a synthetic token sitting on the same line as a
finding, which is what prompted the level.

**From 0.16.0 the tools mask by default.** The level existed on `qrp-mcp scan --out` -- the path
that writes a file for you to read before you send it -- and nowhere else. The `scan_repo` and
`export_cbom` tools returned every matched line as written, and those are the path that runs on
every agent call and hands its result to a model. `export_cbom` says in its own description that
it is for "when the result has to leave the machine", and it carried each line verbatim into
`evidence.occurrences`. The control had been built for the path we thought left the machine
rather than the one that leaves on every call. Both tools now take the same `level` and default
to `masked`; `level="full"` returns the lines. Reading is unchanged -- masking decides how a
finding is quoted, never whether it is found, and no detection figure in this file moves because
of it.

`qscan` is faster: 7.9 s against 219 s on Vault, a factor of **27.7**, and a factor of
**10.6** on the median of five warm runs over a smaller corpus in an independent comparison.
Measured here after 0.13.0: **26.1 s for 823 files of certbot, 31.7 ms per file**, of which the
bulk is 47 algorithm patterns run over every line -- about 4.5 million pattern searches on that
tree. A prefilter would cut it and would also change what is detected, so it is a task of its own
rather than a line in this one.
The figure was written here as "about 24" and was arithmetic nobody had done: 219 / 7.9 is 27.7. It is not deeper: it is lexical, by its own changelog,
as this section already says. Measured per language on its own corpus it leads in none by more
than three labels and trails this tool by five in Go; its real edge is in TLS, SSH and dependency
lines rather than in any language. This tool reads more kinds of file, says what it did not read,
and does not invent a family for an asset that names none.

## The corpus that measures the other direction

A corpus of labelled findings can only ever say what a tool misses. It says nothing about the
twenty lines in the same file that are not cryptography. So this release is measured against one
written for the opposite question:

- **200 files with no quantum-vulnerable cryptography at all** — ordinary code in fifteen
  languages, configuration, CI, infrastructure, manifests, lockfiles, data and documentation.
  Any finding on one of them is a false positive.
- **100 near misses** — cryptography named, banned, discussed, tested against or imitated, but
  not used: an `SSLProtocol` line removing SSLv3, a policy listing forbidden algorithms, a lint
  rule quoting the pattern it forbids, a test asserting an algorithm is rejected, a docstring
  explaining why RSA was dropped, base64 that is a JWT payload rather than a key.

Every file was written and labelled **before** the scanner was run over it, and the corpus was
written by someone who had not read the scanner's rules. A corpus assembled by looking at what a
tool reported measures the tool against itself, which is the circularity this document criticises
elsewhere.

⚠️ **Outdated:** the result below was measured on 0.11.0 (September 2026) and not re-measured
with the method of *How it is measured*; the negative corpus there replaces it once its results
are filled in.

**Result: 200 of the 200 negative files are clean** — no finding of any kind. On the 100 near
misses, this release reports 83 findings the labels say should not read as a use, down from 136.
What remains is one shape: a file whose whole purpose is to forbid. A lint rule quoting
`hashlib.md5(...)` as the thing it bans is, line by line, indistinguishable from code calling it;
telling them apart needs file-level context this release does not attempt.

The corpus is a floor, not a measurement. It was written by the same hands that wrote the tool,
so a construct nobody here thought of is in neither. Its honest use is as a difference between
two releases.

## What is still missing here

Stated rather than hidden, and each of these is a known gap rather than a suspicion:

- **A finding carries a kind, not a confidence level.** Since 0.11.0 every finding says whether
  it is a call, an import, a comment, a declaration, a reference or a ban, and 0.12.0 decides that
  by the position of the match rather than by the line it sits on. What is still missing is a
  graded confidence. Two contexts that were read as code and are not -- a Python docstring, and a
  string constant holding a PEM header -- were reported by an independent comparison and are fixed
  in 0.13.0, with the controls that keep the fix narrow: a key pasted into a triple-quoted value is
  still key material, and a cipher suite named in a string is still configuration.
- **SSH and TLS assets are read at 8/14 and 7/11** on qscan's corpus; X448 at 4/8.
- **Speed.** Reading key material by content costs about 26% over 0.8.1 on a large tree.
- **A symlink is never read.** Where a tree reaches content only through a link whose target
  sits in a directory this tool excludes, that content is not scanned. It is named as a link
  rather than silently skipped, but it is not read.
- **Not built from the 7 Oct 2026 research, and why.** A CDK listener with no `sslPolicy`
  (the result depends on a `cdk.json` feature flag and on CDK inferring the protocol); CloudFront,
  API Gateway, Transfer Family and OpenSearch policies; open62541's
  `UA_ServerConfig_setDefaultWithSecurityPolicies(` (whether the SHA-1 pair is in depends on a build
  flag); Cisco's `authentication … mldsa-sig` (seen only in a vendor blog); PAN-OS and Windows IKE
  fragmentation (no element or key found in a primary source); Junos curly-brace `fragmentation {
  disable; }` (only the `set` form is read); Bouncy Castle's `cert.plants` classes (known from
  search snippets only); `.sage` files, where much CSIDH and SQIsign prototyping lives. Cisco
  running-configs saved as `.txt` or without an extension are not read.
- **A size is not checked against the interface it has to fit.** A finding names the algorithm
  — ML-KEM-768, whose ciphertext is 1,088 bytes (FIPS 203), or an ML-DSA signature (FIPS 204) —
  not whether that fits the link it is configured for: an EAP identity, a single IKE message, a
  DNSSEC answer over UDP. For most interfaces the ceiling is not in the file, and none is claimed.
  Two cases are read: IKE fragmentation (above), where the configuration says whether a large
  message is split, and, from 0.32.0, DNS, where it is in the file — BIND's `max-udp-size` and
  `edns-udp-size`, 1232 bytes when absent (BIND 9 ARM). Even there the size is reported beside the
  algorithm, not compared with the signed answer: how large an answer gets depends on the zone,
  and the effective size on the path can be lower than the configured one.
- **What a TLS library defaults to is not stated** (from 0.33.0 the absence is): an HAProxy
  listener without `ssl-min-ver` or a cipher list says the defaults apply, not which. nginx's
  `proxy_ssl_verify` is off by default and only an explicit `off` is reported. Which TLS library
  an image carries is known for one image (`nginx:1.24.0`); a `Dockerfile`'s `FROM` line is not
  read as a pin (the file itself is read from 0.35.0), so it is not joined to anything.
- **Symmetric cryptography, hashes for integrity, KDFs and random number generation are out of
  scope by design.** This tool reports what a cryptographically relevant quantum computer would
  break. On Cryben's full 197 findings — most of which are AES, SHA-256 and KDF — it scores 0.13,
  and that is the scope working, not failing.

## What an outside review found

0.9.0 was reviewed by someone who did not write it, from the published ZIP, and reported nine
defects. All nine reproduced here before anything was changed, and all nine are fixed in 0.10.0.
Two of them were about the claims this tool makes for itself, which is the worst place to be wrong:

- **A symlink carried the scan outside the directory it was given.** A link inside the tree
  pointing at a file beside it was read, and reported under the link's name. This tool is pointed
  at code its user did not write, and the excerpt travels into an agent's context and into any
  exported CBOM, so that was the declared boundary failing. Links are no longer followed. Each is
  named in `symlinks_not_followed`, with a relative path when the target is inside the root and
  the words "outside the scanned directory" otherwise -- printing an outside path would leak what
  reading it did. A linked directory sets `accounts_for_every_file` to false.
  On certbot, which uses 48 of them, coverage falls from 68.9% to 65.8%: the links are now counted
  as present and not read. No algorithm is lost, because each target is still read at its own path.
- **`compare_coverage` keyed on a commit, and a commit is not what was read.** A dirty emitter
  still compared; an unverified corpus compared because `None` read as False; two different
  subdirectories of one commit compared at 100% and 0% coverage; a git-ignored file that the scan
  reads changed the corpus while both pins stayed clean. Comparability now keys on
  `corpus.content_digest` -- a hash over the files read and the text read from them, the files
  skipped with their sizes, and every entry not read with its reason. The git pin stays as
  provenance a reader can follow; it no longer carries the conclusion. `dirty` is three answers,
  and `None` means nobody checked.

The rest: a malformed coverage block returned an exception instead of `unestablished`; certificate
evidence came off a set, so its order moved between interpreters; `--out ~/file` passed its check
and failed its write; and three tests read the tool's own git pins from the environment, so they
passed from a clone and **failed from the published tarball** -- which anyone who downloaded 0.9.0
and ran its tests saw, and we had not, because we always ran in the checkout. Extracting the
release and running its tests in a fresh environment is now part of shipping one.

## Why deterministic

There is no LLM inside this tool. The same input always produces the same output, and every
finding points at a file and a line you can open yourself.

That is the point of handing it to an agent: **the agent brings the language, the tool brings
the truth.** An agent guessing about your signing code is worse than nothing; an agent reading
a deterministic inventory can actually reason about it.

## What it is not

It reads source, configuration, CI pipelines, infrastructure-as-code, Kubernetes manifests,
build files, certificates and key inventories. It does not read documentation, binaries or
images.

Every file under the path is accounted for in one of four ways: **scanned**, **unreadable**,
**skipped because the tool does not claim that type** — counted by extension, so
the coverage figure has a base, and from 0.27.3 named one by one in the coverage block (`not_examined` → `paths`) —
or **a link not followed**, named in `symlinks_not_followed`. `files_scanned + unreadable_files +
files_skipped_by_type` plus the linked files always equals `files_present`; until 0.34.0 this
sentence said three ways and left the links out. A directory the scan cannot enter or list is named in
`unreadable_directories`; its files cannot be counted, so the scan then says it cannot account
for every file instead of claiming it read them all. A scan that read seven files out of nine is a different report
from one that read seven out of four hundred, and only one of them is worth trusting.

A **free inventory tool**, not a readiness assessment. It deliberately does not do:

- risk scoring or prioritisation,
- migration planning — a `replacement` names what a finding becomes, not when or in what order,
- network or host scanning, or reading a system certificate store,
- tracking change over time — `prove_closure` compares two scans you give it; nothing keeps a history.

Those live in the [Quantum Readiness Platform](https://quantumreadiness.eu), the product this
tool is extracted from. Nothing here is crippled to push you there — what it does, it does
completely.

It also does not tell you that you are about to be hacked. It tells you what you are using.

## License

Apache-2.0.
