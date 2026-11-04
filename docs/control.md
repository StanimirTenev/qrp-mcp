# The self-seeded control

`qrp-mcp control PATH --seed N [--out FILE]` copies the tree to a temporary directory, plants
known lines into the copy, scans the copy with the same instrument and scores every planted
line. The tree itself is not written to, and the copy is removed afterwards. The MCP tool
`run_self_seeded_control` does the same and returns the same document. `qrp-mcp scan PATH
--control-seed N` (and `qrp-mcp cbom`) runs it beside the scan and carries the block as
`coverage.claims.self_seeded_control`.

## What the figure is

**Robustness on known patterns**: what this version of the instrument does on the planted
styles and decoy classes, in this tree's languages and files. It answers one question a reader
of a scan has: on which ways of writing cryptography may this scanner's silence be relied on in
this tree, and which must be read by hand.

What it does not say: what the tree contains, how much of the tree's own cryptography was
found, or how many of the tree's own findings are right. The denominator is what was planted.
The styles and decoys are the harness's own, so a scanner tuned on them would score better
without being better on anything nobody planted. From 0.43.0 on, five decoy classes are ones
the rules were corrected against (ZA-OPRAVYANE rows 420-424), so their figures are no longer
independent of the rules; the first figures, before those corrections, are in the CHANGELOG
entry for 0.43.0.

## Why it never becomes `claims.control`

`claims.control.held` is defined as a corpus with independently established contents
(`coverage.CONTROL_ABSENT["none_held"]`), and it is the one thing that lets the CBOM say
`compositions[].aggregate = "complete"`. A control the instrument's author plants is not
independent, whatever its scope. So the block sits beside `claims.control` under its own key,
`claims.control.held` stays `false`, and nothing in the block is read by the aggregate.
`tests/test_self_seeded_control.py` pins both.

## What is planted

Per language present (Python, Ruby, Rust, PHP, TypeScript, Java, Go), each style and each
decoy class for RSA, ECDSA and Ed25519, into existing files of that language at a blank-line
anchor chosen with the seed; plus new files for the configuration styles, the UTF-16 style and
the two file decoys.

| uses (styles) | decoys (classes) |
|---|---|
| `direct_call` | `disabled_flag` (`RSA_ENABLED = false`) |
| `indirect_name` (alias import, constant on the line above) | `deny_list` (`DISALLOWED = {"RSA", "DSA"}`) |
| `string_built` (`"R" + "SA"`, `getattr`, `const_get`, `format!`) | `log_string` (`log.info("rotating RSA key")`) |
| `split_lines` (the family on one line, the size on another) | `variable_name` (`ecdsa_fallback_count = 0`) |
| `live_string` (a shell script in a string literal) | `comment` |
| `cert_manager_yaml` (`privateKey.algorithm`) | `kid_label` (a JWKS EC key whose `kid` says rsa4096) |
| `terraform_tls_key` (`tls_private_key.algorithm`) | `switched_off_setting` (sshd_config lists beginning with `-`) |
| `java_properties` (`jwt.algorithm=RS256`) | |
| `utf16_nobom` (a direct call in UTF-16LE without a BOM) | |

The templates come from library documentation, not from this scanner's rule tables; the
directories the scan leaves out (`.git`, `node_modules`, `vendor`, ...) are neither copied nor
planted into. The owner's `.qrp.toml` is not applied to the copy: the control measures the
instrument, not the configuration.

**Scoring.** Every evidence row with a path and a line counts. A planted use is `found` (a row
on a use line, the family matching, not a comment or a ban; a generic `EC` row counts for
ECDSA), `read_as_not_a_use` (the family, as a comment or a ban), `wrong_family`,
`declared_not_read` (the file is listed as not read), or `silent`. A planted non-use is
`reported_as_use`, `named_not_used` (a comment or ban row, which is right), or `silent`.

## The block: `claims.self_seeded_control`

The shape is published for other tools to read. Keys are added, never renamed or removed.

| key | type | meaning |
|---|---|---|
| `ran` | bool | `false` in every scan that did not run it; then only `name`, `feeds` and `how` are present |
| `name` | string | always `"robustness on known patterns"` |
| `licenses` | string | what the figure may be quoted as, and what not |
| `feeds` | string | says that `claims.control.held` and `compositions[].aggregate` do not read it |
| `how` | string | only when `ran` is false: the commands that run it |
| `instrument` | object | `tool`, `version`, `revision` of the code that scanned the planted copy |
| `seed` | int | the seed |
| `harness_version` | string | bumped when a template, decoy or scoring rule changes |
| `harness_sha256` | string | SHA-256 over the templates, decoys and family equivalences |
| `plan_sha256` | string | SHA-256 over every planted item (id, kind, style, family, language, path, lines, text); the same seed on the same tree gives the same value |
| `tree` | object | `git_head`: the commit of the tree given, or `null` |
| `languages` | list | the languages planted into, in a fixed order |
| `families` | list | `["RSA", "ECDSA", "Ed25519"]` |
| `planted_uses` | int | = `found + silent + read_as_not_a_use + wrong_family + declared_not_read` |
| `found`, `silent`, `read_as_not_a_use`, `wrong_family`, `declared_not_read` | int | planted uses by outcome |
| `planted_non_uses` | int | = `reported_as_use + named_not_used + silent_on_decoys` |
| `reported_as_use`, `named_not_used`, `silent_on_decoys` | int | planted non-uses by outcome |
| `by_confidence` | object | `high`, `medium`, `low` -> `[found on uses, reported as use on non-uses]`, by the highest confidence on the planted line |
| `by_style` | object | style -> `{planted, found, silent, read_as_not_a_use, wrong_family, declared_not_read}` |
| `by_decoy_class` | object | class -> `{planted, reported_as_use, named_not_used, silent}` |
| `styles`, `decoy_classes` | list | the names, in planting order |
| `key_size_on_another_line` | object | `{planted, read}`: split calls whose size sits on its own line |
| `indirect_name_line` | object | `{planted, found}`: the family found on the alias or constant line itself |
| `sentence` | string | the sentence a report carries with the figure |

The `control` command's document is `{"self_seeded_control": <block>, "items": [...]}`; each
item has `id`, `kind` (`positive` or `decoy`), `style`, `family`, `lang`, `path`, `line`,
`lines`, `outcome`, and where there is one, `confidence`, `evidence_kind` and `reason`.

## The sentence

Built from the block alone, for example (pyjwt at `16231ab`, seed 1, 0.42.0's rules):

> A control planted into a copy of this tree -- 27 cryptographic uses in 9 styles and 18 lines
> that name an algorithm without using it -- was scanned with this instrument (qrp-mcp 0.42.0),
> seed 1. It found 24 of the 27 uses (silent on 3: 2 string_built, 1 indirect_name), and
> reported 5 of the 18 non-uses as uses (3 variable_name, 2 switched_off_setting). This says
> what the instrument does on those styles. It does not say what this tree contains, how much
> of it was found, or that the inventory lists everything, and it is for this version only.

## Limits

- Lexical: the planted blocks are plausible, not compiled. A tool that needs to build the code
  would need compilable plants.
- One shape of removal list (sshd `-`); OpenSSL `!` strings and `java.security` disabled lists
  are not planted.
- More seeds move the blocks, not the templates; the scanner reads lines, so a second seed
  gives the same counts. More templates would add information; more seeds add little.
