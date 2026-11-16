# Sample CBOM from qrp-mcp 0.47.0

`h5bp-server-configs-nginx.cbom.json` is a CycloneDX 1.6 CBOM that qrp-mcp 0.47.0 wrote for a small public
repository. It is meant as an import test for a CBOM reader.

- **Repository:** https://github.com/h5bp/server-configs-nginx (H5BP's nginx configuration)
- **Commit:** `d2f2c3e2fac76f429adb738894499b8fb756d2f3` (20 June 2026)
- **Licence of the repository:** MIT (`LICENSE.txt`, "Copyright (c) H5BP")
- **Command** (qrp-mcp 0.47.0 from PyPI, through `uvx qrp-mcp==0.47.0`):

  ```
  qrp-mcp cbom server-configs-nginx --out h5bp-server-configs-nginx.cbom.json
  ```

  This uses the default `--level masked`: the quoted lines are starred except for the algorithm
  names. Files and line numbers are kept.
- **sha256 of the file:** `2b252185671d4c0f3c1684cab8b6142db911b344a43b736027c79a5ccc644a28`
- **Validated** against the CycloneDX 1.6 JSON schema with zero errors. Two copies were used:
  `bom-1.6.schema.json` from the specification's `master` branch (the copy the qrp-mcp tests
  vendor) and the one from the `1.6` branch. Every `bom-ref` that the document points to resolves
  to a component in it.

## What the TLS component carries now

The repository pins TLS versions in `h5bp/tls/policy_balanced.conf` and
`h5bp/tls/policy_strict.conf` and sets groups with `ssl_ecdh_curve`. Each pinned version is a
`protocol` component. Its key exchange can be read from the standard fields alone, with no
`qrp:` properties:

| component | file | `protocolProperties.cryptoRefArray` |
|---|---|---|
| TLSv1.2 | policy_balanced.conf | X25519, prime256v1, secp521r1, secp384r1 (each a `key-agree` algorithm component) |
| TLSv1.2 | policy_strict.conf | X25519 |
| TLSv1.3 | policy_strict.conf | X25519 |

The link is by file. It records what the file configures, not what a connection negotiates;
`qrp:linked_by` says this.

`protocolProperties.cipherSuites` is not present in this sample. The repository's `ssl_ciphers`
lines are `EECDH+CHACHA20:EECDH+AES`, which are OpenSSL selectors and name no single suite. qrp-mcp
does not expand selectors into suites. Where a file names suites (for example
`ECDHE-RSA-AES128-GCM-SHA256` or `TLS_AES_256_GCM_SHA384`), each one is written by its IANA name,
and its `algorithms` field points at the components for the families it names.

A post-quantum hybrid group such as `X25519MLKEM768` is written the same way. It appears in
`cryptoRefArray` as `hybrid:x25519mlkem768`, and that component's `dependencies` point at its
ML-KEM and X25519 halves. This repository does not configure one.

`compositions[0].aggregate` is `incomplete` because some files present were not read. The list of
those files is in the `qrp:coverage:*` properties.

## Rerunning it yourself

Clone the repository at the commit above and run the command with 0.47.0. Your file should be the
same bytes as this one (sha256 above): the CBOM records the scanned folder by its own name,
`server-configs-nginx`, not by its absolute path, and `qrp:coverage:corpus:target_basis` says so.
This was checked by generating it in two different folders on one machine; both gave the sha256
above. The findings alone can also be compared through `qrp:findings_fingerprint:sha256`, which is
`efaeeeec2048349ac52feb9de26d7c2fbf8d5e4b820856d1737a1821a71bf91a` for this commit, the same as
with 0.46.0.

## What changed from the 0.46.0 sample

The same 13 components, with the same `bom-ref`s and the same TLS links. New: `qrp:tls_listeners`
(each `listen ... ssl` with its port, and where its groups and certificates are set or that they
are not set in that file), `qrp:operation` on the EC components (here `not read`: the
repository configures groups, it does not call key-agreement code), and the excluded-directory
rule as one property per name. `qrp:coverage:corpus:target` is the folder name.
