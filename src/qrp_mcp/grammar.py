"""Device configurations whose grammar this tool does not parse (rows 229 and 333).

A FortiOS backup, a Cisco IOS running configuration and a Junos configuration carry a
tunnel's key exchange and authentication in sections and values: group numbers, defaults the
backup leaves out, which proposal a tunnel uses. The scan reads them by the words they name.
That is a partial reading, and the file is named in `examined_partly` with it rather than
passing as read.

Recognised by form, each from the vendor's own documentation:
- FortiOS: the backup's first header line starts `#config-version=`
  (https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-backup-FortiGate-configurations-using-Kiwi/ta-p/198720).
- Cisco IOS: the global configuration commands `crypto ikev2 ...`, `crypto isakmp ...`,
  `crypto ipsec ...`, `crypto map ...` at the start of a line
  (https://www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ike2vpn/configuration/15-2mt/sec-cfg-ikev2-flex.html).
- Junos: the `[edit security ike]` / `[edit security ipsec]` hierarchy, as `set security
  ike|ipsec ...` lines or as `security {` with `ike {` / `ipsec {` inside
  (https://juniper.net/documentation/en_US/junos12.2/topics/reference/configuration-statement/proposal-edit-security-ike.html).

WireGuard is not here: its grammar is small and is read whole elsewhere.
"""

from __future__ import annotations

import re

REASON = "grammar_not_parsed"  # its meaning is in certificates.UNPARSED_REASONS

# What of each grammar is read, and what is not (row 229/333 re-checked after rows 225-228,
# 334). Each "read" names a rule in ike.py, switches.py or fortios.py.
READ_IN_PART = {
    "FortiOS configuration": (
        "the words it names; `set dhgrp` and `set addke1`-`addke7` group numbers; "
        "`strong-crypto`, `ssl-static-key-ciphers` and the TLS version settings; the "
        "firmware defaults of `ssl-static-key-ciphers`, SSL VPN `ssl-min-proto-ver`/"
        "`ssl-max-proto-ver` and phase1 `dhgrp` where a section leaves them out",
        "which proposal or phase1 a tunnel uses; every other default the backup leaves out "
        "(listed as not evaluated); the sections as a whole"),
    "Cisco IOS configuration": (
        "the words it names; `group` numbers in a `crypto ikev2 proposal`; "
        "`authentication remote|local rsa-sig` in a `crypto ikev2 profile`",
        "`crypto isakmp policy` groups (IKEv1); which proposal, profile or crypto map a "
        "tunnel uses; defaults the configuration leaves out"),
    "Junos configuration": (
        "the words it names; `dh-group groupN` and PFS `keys groupN`; "
        "`authentication-method` signatures",
        "which proposal or policy a gateway uses; defaults the configuration leaves out"),
}

_CISCO = re.compile(r"crypto (?:ikev2|isakmp|ipsec|map) \S")
_JUNOS_SET = re.compile(r"set security (?:ike|ipsec) \S")
_JUNOS_BLOCK = re.compile(r"\s+(?:ike|ipsec) \{\s*$")


def device_grammar(lines: list[str]) -> tuple[int, str] | None:
    """(line, label) of the form that names the file a device configuration, or None."""
    if lines and lines[0].startswith("#config-version="):
        return 1, "FortiOS configuration"
    in_security = False
    for number, line in enumerate(lines, 1):
        if _CISCO.match(line):
            return number, "Cisco IOS configuration"
        if _JUNOS_SET.match(line):
            return number, "Junos configuration"
        if line.rstrip() == "security {":
            in_security = True
        elif in_security and _JUNOS_BLOCK.match(line):
            return number, "Junos configuration"
    return None
