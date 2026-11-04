# What a TLS line does not establish

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

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
not read; from 0.35.0 it is, and `x25519` in it is found as X25519; from 0.40.0 its `curves`
line is a group setting and `protocols tls1.2 tls1.3` names the versions, both a TLS place) are
not, tested on 22 Oct 2026.

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

From 0.40.0 (row 99) the summary tells the two apart as well: a classical group or SSH key
exchange offered alone on a line that also offers a hybrid stays a classical finding and carries
`fallback_beside_hybrid` (its places), listed in `summary.by_role.key_establishment.
fallback_beside_hybrid` and as `qrp:fallback_beside_hybrid` on its CBOM component. A pure hybrid
has neither. The classical half inside the hybrid's own name is counted as
before.

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
