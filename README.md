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

## Tools

| Tool | What it does |
| --- | --- |
| `scan_repo(path)` | Scans a directory's source, CI/CD configs and infrastructure-as-code; returns findings, a summary, and the coverage block below |
| `export_cbom(path)` | The same reading as a CycloneDX 1.6 CBOM, with the coverage block inside it |
| `compare_coverage(a, b)` | Whether two scans produced numbers that can be compared at all |
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
(`hashes.MD5()`, `hashlib.new('md5')`, `MD5Init`, `<sha1.h>`, Go `sha1.Sum`).

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
  instances is reported at zero rather than omitted.

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

`export_cbom` produces a CycloneDX 1.6 document, validated against the published schema. Three
things travel in it that a component list alone cannot say:

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
the coverage figure has a base. `files_scanned + unreadable_files + files_skipped_by_type`
always equals `files_present`. A directory the scan cannot enter or list is named in
`unreadable_directories`; its files cannot be counted, so the scan then says it cannot account
for every file instead of claiming it read them all. A scan that read seven files out of nine is a different report
from one that read seven out of four hundred, and only one of them is worth trusting.

A **free inventory tool**, not a readiness assessment. It deliberately does not do:

- risk scoring or prioritisation,
- migration planning,
- network or host scanning, or reading a system certificate store,
- tracking change over time.

Those live in the [Quantum Readiness Platform](https://quantumreadiness.eu), the product this
tool is extracted from. Nothing here is crippled to push you there — what it does, it does
completely.

It also does not tell you that you are about to be hacked. It tells you what you are using.

## License

Apache-2.0.
