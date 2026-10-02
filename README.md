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
| `scan_repo(path)` | Scans a directory's source, CI/CD configs and infrastructure-as-code; returns findings, a summary, and the coverage block below |
| `export_cbom(path)` | The same reading as a CycloneDX 1.6 CBOM, with the coverage block inside it |
| `compare_coverage(a, b)` | Whether two scans produced numbers that can be compared at all |
| `prove_closure(before, after)` | Which findings a change actually closed, from two saved scans of one tree — only if the two runs can be compared for it |
| `list_algorithms()` | The algorithm families the server recognises and how each is classified |

## What it looks at

**Chain and wallet code** — `secp256k1`, `ecrecover`, ethers, web3, bitcoinjs, `ECPair`,
`btcec`, tweetnacl, `@solana/web3.js`, `solana_program`, `bls12-381`, blst, `@chainsafe/bls`,
BIP340/Taproot Schnorr. Solidity (`.sol`), Rust (`.rs`), Move and Cairo are scanned alongside
Python, Go, Java, JS/TS, Ruby, PHP, C/C++/C# — headers included — PowerShell, Perl and shell.

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
`GenerateKey(..., 1024)`) travels with the family, so a weak RSA key is reported as weak rather
than as one more RSA. `algorithm_key_sizes` holds the **smallest** size seen per family — the
figure that answers *is anything weak here* — and `algorithm_key_sizes_observed` holds **every**
size seen, which is a different question and became the operational one when RSA-896 was factored
on a data-centre fleet: *where is RSA-1024 still in use?*

From 0.17.0 the size reaches the CBOM component. Where one size was observed it is stated as
`cryptoProperties.algorithmProperties.parameterSetIdentifier` — the field whose own example in the
schema is a key length. Where several were, that field is **left out** and all of them are named
in `qrp:observedKeySizes` instead: choosing one would put a number in the document that looks
measured and is not, and a reader could not tell the difference.

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
SQIsign, UOV — are recognised as candidates, and CROSS as dropped from that process.

Each carries the mathematical family it rests on (structured or unstructured lattice,
code-based, hash-based, isogeny-based, multivariate, symmetric-based) and where it stands:
standardised, selected, candidate, withdrawn, eliminated or broken. SIKE is reported as broken
and HAWK as withdrawn rather than counted as quantum-resistant — "post-quantum" is a category,
not an assessment.

**Certificates and keys** — `.pem`, `.der`, `.crt`, `.cer`, `.cert`, `.csr`, `.key`, `.pub`,
`.p12`, `.pfx`. Algorithms are resolved from the object identifiers inside the DER and from
PEM labels and OpenSSH key types, and private key material is reported separately. This does
not parse X.509: it matches the object identifiers already in the classifier against the bytes.
A file that is not a certificate but contains an identifier's bytes **is** reported, and the
finding says so — "observed in the file; the file was not decoded as a certificate". An earlier
version of this paragraph promised that a malformed certificate yields nothing; an independent
analysis put a valid RSA identifier into arbitrary bytes and got a finding, which is what the
code measures. For a certificate register — issuer, validity, the device — this tool is the wrong
instrument and says so: that data comes from a structural parser or an external inventory.

**Configuration** — `nginx.conf`, `sshd_config`, `openssl.cnf`, `swanctl.conf`, `.ini`,
`.toml`, `.properties`, `.hcl`, `.json`, and any YAML that is not a manifest. This is where a TLS or SSH hybrid
group is chosen: `X25519MLKEM768` and `mlkem768x25519-sha256` are almost never strings in code.
IKE proposal syntax is read here too — `ecp384` is NIST P-384, `modp2048` is group 14.

**Quantum-resistant mechanisms, not only algorithms** — RFC 8784 mixes a postquantum preshared
key into IKEv2 key derivation, so a tunnel resists a quantum adversary with no post-quantum
algorithm present. A scanner matching algorithm names cannot see that by construction, and
would report a protected deployment as `classical_only`. PPK is matched by the directives that
switch it on and classified as `quantum_resistant_mechanism` — deliberately not `pqc_ready`,
because a preshared key is not ML-KEM. Whether it holds depends on the entropy of the key and
on out-of-band distribution, neither of which is visible in a file, and the finding says so.

**CI/CD pipelines** — signing commands such as `gpg --sign`, `cosign sign`, `signtool`,
`jarsigner`, `codesign`.

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
  identify what did the reading. Where the tool runs from an installed wheel there is no commit,
  and the field says which absence rather than going quiet.
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
figure lifted out of a document without them is the failure the block exists to prevent:

```
This scan read 822 of 1250 files (65.76%); the remaining 428 (3 of 24, by extension —
files with no extension, .rst and .txt — being 68.93% of them) are listed with a reason each.
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

Output is deterministic where it matters. The serial number is derived from the target, the two
pins and a digest of what was found, so the same code over the same corpus that finds the same
things gets the same serial, and a different result gets a different one. The timestamp and the
coverage window record when the run happened, so those fields differ between runs.

## What kind of place a finding sits in

Two things about a match are not the match itself, and both now travel with it — in the
scan result and in the exported CBOM.

**Evidence kind.** `scan_repo` grades every match: `call`, `declaration`, `import`,
`reference`, `ban`, `comment`. Comment evidence is kept out of the inventory, and the
reason is measured — the nearest rival strips comments before matching and scored 0.542
precision on an independent corpus against this scanner's 0.93. The exported document
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

`basis` is `configured_group` for a setting that chooses key-exchange groups and
`configured_protocol` for a pinned version. `null` when the tree configures no TLS; SSH
configuration is not counted here. On certbot: 23 places (22 protocol pins, 1 group
setting); on OpenSSH: none. It stays out of the CBOM, like `files_read`.

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
   as fixed.

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

Transition dates come from NIST IR 8547, which is still an **initial public draft** (12 Nov
2024): quantum-vulnerable signatures and key establishment deprecated after 2030 at 112-bit
strength, disallowed after 2035. Hybrids are named as NIST names them — accommodated, and
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

## Measured against the other scanners

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

Every file under the path is accounted for in one of three ways: **scanned**, **unreadable**,
or **skipped because the tool does not claim that type** — the last counted by extension, so
the coverage figure has a base, and from 0.27.3 named one by one in the coverage block (`not_examined` → `paths`). `files_scanned + unreadable_files + files_skipped_by_type`
always equals `files_present`. A directory the scan cannot enter or list is named in
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
