# qrp-mcp

<!-- mcp-name: eu.quantumreadiness/qrp-mcp -->

**Every signature in your wallet, contract and validator rests on elliptic-curve cryptography.
A large quantum computer breaks it. This tells your AI agent exactly where yours is.**

An MCP server that scans a local directory for cryptography that Shor's algorithm defeats —
secp256k1, Ed25519, BLS, Schnorr, RSA — plus weak primitives and CI signing commands, and
classifies each one: broken by a quantum computer, post-quantum, or neither.

**Everything runs on your machine.** No network calls, no account, no API key, nothing
uploaded. A tool that reads your keys' surroundings has no business phoning home, so this one
makes zero outbound connections — enforced by a test, not promised in a paragraph.

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
before it goes anywhere. Nothing is sent. `--level trimmed` removes the quoted lines of
code but keeps each file and line number. The SHA-256 of the written bytes is printed,
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
SHA-1, RC4 and DES/3DES.

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
not parse X.509: it keeps only the identifiers already in the classifier, so a malformed
certificate yields nothing rather than nonsense.

**Configuration** — `nginx.conf`, `sshd_config`, `openssl.cnf`, `swanctl.conf`, `.ini`,
`.toml`, `.properties`, and any YAML that is not a manifest. This is where a TLS or SSH hybrid
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

- `compositions.aggregate` — `complete` only where every file present was examined, `incomplete`
  otherwise, and `unknown` where the tool cannot account for its own reading.
- `properties` — the whole coverage block. It travels there because the root object is
  `additionalProperties: false` and the format has no field for it; the awkwardness is the point
  rather than something to hide.
- `evidence.occurrences` — file, line and matched text for every asset.

Output is deterministic: the timestamp comes from the scan window and the serial number from the
target and the two pins, so the same code over the same corpus produces the same document and
different code does not.

## Why deterministic

There is no LLM inside this tool. The same input always produces the same output, and every
finding points at a file and a line you can open yourself.

That is the point of handing it to an agent: **the agent brings the language, the tool brings
the truth.** An agent guessing about your signing code is worse than nothing; an agent reading
a deterministic inventory can actually reason about it.

## What it is not

It reads source, configuration, CI pipelines, infrastructure-as-code and Kubernetes
manifests. It does not read documentation, binaries or images.

Every file under the path is accounted for in one of three ways: **scanned**, **unreadable**,
or **skipped because the tool does not claim that type** — the last counted by extension, so
the coverage figure has a base. `files_scanned + unreadable_files + files_skipped_by_type`
always equals `files_present`. A scan that read seven files out of nine is a different report
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
