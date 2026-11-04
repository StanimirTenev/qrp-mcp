# How it is measured

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

Every figure on this page carries the version and the date it was measured on. The recall and precision figures are from 0.11.0 and have not been re-measured since: they are kept here as history, not cited as current. The coverage figures of this release are in the README.

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
  an image carries is known for one image (`nginx:1.24.0`); a `Dockerfile`'s `FROM` line is read
  as a pin from 0.40.0, but it mounts nothing, so it is not joined to any configuration.
- **Build switches and default orders** (from 0.39.0 the one verified case is read). Only
  OpenSSH's `WITH_XMSS` is judged as a switch that leaves an algorithm out of a default build;
  other `#ifdef`, CMake or meson options are not. A default key-exchange order written in code
  (OpenSSH's `myproposal.h`) is code, not configuration, and is not read as an order; for TLS,
  whether the server's or the client's group order decides is not read.
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
