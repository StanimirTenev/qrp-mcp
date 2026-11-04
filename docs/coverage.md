# What the coverage block says

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

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

## Read in part (from 0.42.0)

- `coverage.scope.read_in_part` — the files that were opened but read only in part or gave
  nothing the scan could decode: a device configuration whose grammar is not parsed, a
  certificate or key block that did not parse. Each is named in `examined_partly` with its line
  and reason.
- `coverage.scope.read_in_full_pct` — the share of the files present that were read and are not
  among those. `coverage_pct` is unchanged beside it: the share of the files present that were
  opened, which is what `--min-coverage` measures.
- `examined_partly.items[]` with the reason `grammar_not_parsed` (FortiOS, Cisco IOS, Junos) carry
  `read` and `not_read`: which settings of that grammar the scan reads, and what it does not
  parse, such as which proposal a tunnel uses.
- The verdict names both: "This scan opened every one of the N files it was given; K of them
  were read only in part or gave nothing it could decode, each named with a reason". The CBOM
  (in the flattened coverage block) and SARIF carry `read_in_part` and `read_in_full_pct`.
