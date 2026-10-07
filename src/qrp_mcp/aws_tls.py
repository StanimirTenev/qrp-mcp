"""AWS load-balancer TLS policies: what a policy name configures, and what an absent one does.

Until this release `ssl_policy = "ELBSecurityPolicy-2016-08"` gave no finding, and a
listener with no `ssl_policy` gave none either (Vladimir Mikhalev, 7 Oct 2026). Both
mean the same thing: AWS, describe-ssl-policies for ALB and NLB, read 7 Oct 2026 --
"Other methods (for example, the AWS CLI, AWS CloudFormation, and the AWS CDK) - The
default security policy is ELBSecurityPolicy-2016-08." Terraform sends nothing when the
attribute is absent (`if v, ok := d.GetOk("ssl_policy"); ok`), so the API default
applies there too. The console default is different
(ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09), which is the whole of the original post.

"Application Load Balancers do not support custom security policies", so the name fixes
the configuration and the table below is complete for the names on the two pages.
Derived mechanically from the "Protocols by policy" and "Ciphers by policy" tables:

* every policy offers classical (EC)DHE key exchange -- the PQ ones "support both
  classical and post-quantum ML-KEM key exchange" -- so every one names ECDH. The
  classical curves themselves are not listed on either page;
* a `PQ` policy adds SecP256r1MLKEM768, SecP384r1MLKEM1024 and X25519MLKEM768;
* RSA key transport is a TLS 1.2 suite without an ECDHE prefix (AES128-GCM-SHA256 ...);
* the certificate, not the policy, decides RSA or ECDSA signatures, so neither is named.
"""

from __future__ import annotations

import json
import re
from typing import Any

_V = {"3": "TLSv1.3", "2": "TLSv1.2", "1": "TLSv1.1", "0": "TLSv1.0"}

# name -> (protocol versions, post-quantum hybrid offered, RSA key transport offered)
_TABLE = """
TLS13-1-3-2021-06 3 - -
TLS13-1-3-PQ-2025-09 3 pq -
TLS13-1-2-2021-06 32 - -
TLS13-1-2-PQ-2025-09 32 pq -
TLS13-1-2-Res-2021-06 32 - -
TLS13-1-2-Res-PQ-2025-09 32 pq -
TLS13-1-2-Ext2-2021-06 32 - rsa
TLS13-1-2-Ext2-PQ-2025-09 32 pq rsa
TLS13-1-2-Ext1-2021-06 32 - rsa
TLS13-1-2-Ext1-PQ-2025-09 32 pq rsa
TLS13-1-1-2021-06 321 - rsa
TLS13-1-0-2021-06 3210 - rsa
TLS13-1-0-PQ-2025-09 3210 pq rsa
TLS-1-2-Ext-2018-06 2 - rsa
TLS-1-2-2017-01 2 - rsa
TLS-1-1-2017-01 21 - rsa
2016-08 210 - rsa
TLS13-1-3-FIPS-2023-04 3 - -
TLS13-1-3-FIPS-PQ-2025-09 3 pq -
TLS13-1-2-FIPS-2023-04 32 - -
TLS13-1-2-FIPS-PQ-2025-09 32 pq -
TLS13-1-2-Res-FIPS-2023-04 32 - -
TLS13-1-2-Res-FIPS-PQ-2025-09 32 pq -
TLS13-1-2-Ext2-FIPS-2023-04 32 - rsa
TLS13-1-2-Ext2-FIPS-PQ-2025-09 32 pq rsa
TLS13-1-2-Ext1-FIPS-2023-04 32 - rsa
TLS13-1-2-Ext1-FIPS-PQ-2025-09 32 pq rsa
TLS13-1-2-Ext0-FIPS-2023-04 32 - -
TLS13-1-2-Ext0-FIPS-PQ-2025-09 32 pq -
TLS13-1-1-FIPS-2023-04 321 - rsa
TLS13-1-0-FIPS-2023-04 3210 - rsa
TLS13-1-0-FIPS-PQ-2025-09 3210 pq rsa
TLS13-1-3-RFC9151-FIPS-2023-07 3 - -
TLS13-1-2-RFC9151-FIPS-2023-07 32 - -
TLS13-1-2-Ext0-RFC9151-FIPS-2023-07 32 - rsa
TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07 32 - -
TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07 32 - -
TLS13-1-2-RFC9151-INTEROP3-FIPS-2023-07 32 - -
TLS13-1-2-RFC9151-INTEROP4-FIPS-2023-07 32 - rsa
FS-1-2-Res-2020-10 2 - -
FS-1-2-Res-2019-08 2 - -
FS-1-2-2019-08 2 - -
FS-1-1-2019-08 21 - -
FS-2018-06 210 - -
2015-05 210 - rsa
"""
# 2015-05 is on the NLB page only; its protocols and ciphers equal 2016-08's.
POLICIES: dict[str, tuple[tuple[str, ...], bool, bool]] = {
    f"ELBSecurityPolicy-{name}": (tuple(_V[d] for d in versions), pq == "pq", rsa == "rsa")
    for name, versions, pq, rsa in (row.split() for row in _TABLE.strip().splitlines())
}

DEFAULT_POLICY = "ELBSecurityPolicy-2016-08"
DEFAULT_APPLIED = "default applied because ssl_policy is absent"

# CDK `elbv2.SslPolicy` members (aws-cdk-lib, enums.ts, main, 7 Oct 2026). `LEGACY` is
# left out: ELBSecurityPolicy-TLS-1-0-2015-04 is on neither AWS page, and its contents
# are known only from a CDK comment.
CDK_ENUM = {
    "RECOMMENDED_TLS": "TLS13-1-2-2021-06", "TLS13_12_PQ": "TLS13-1-2-PQ-2025-09",
    "RECOMMENDED": "2016-08", "TLS13_RES": "TLS13-1-2-Res-2021-06",
    "TLS13_EXT1": "TLS13-1-2-Ext1-2021-06", "TLS13_EXT2": "TLS13-1-2-Ext2-2021-06",
    "TLS13_10": "TLS13-1-0-2021-06", "TLS13_11": "TLS13-1-1-2021-06",
    "TLS13_13": "TLS13-1-3-2021-06", "TLS13_13_PQ": "TLS13-1-3-PQ-2025-09",
    "TLS13_12_RES_PQ": "TLS13-1-2-Res-PQ-2025-09", "TLS13_12_EXT1_PQ": "TLS13-1-2-Ext1-PQ-2025-09",
    "TLS13_12_EXT2_PQ": "TLS13-1-2-Ext2-PQ-2025-09", "TLS13_10_PQ": "TLS13-1-0-PQ-2025-09",
    "FIPS_TLS13_13": "TLS13-1-3-FIPS-2023-04", "FIPS_TLS13_12_RES": "TLS13-1-2-Res-FIPS-2023-04",
    "FIPS_TLS13_12": "TLS13-1-2-FIPS-2023-04", "FIPS_TLS13_12_EXT0": "TLS13-1-2-Ext0-FIPS-2023-04",
    "FIPS_TLS13_12_EXT1": "TLS13-1-2-Ext1-FIPS-2023-04",
    "FIPS_TLS13_12_EXT2": "TLS13-1-2-Ext2-FIPS-2023-04",
    "FIPS_TLS13_11": "TLS13-1-1-FIPS-2023-04", "FIPS_TLS13_10": "TLS13-1-0-FIPS-2023-04",
    "FIPS_TLS13_13_PQ": "TLS13-1-3-FIPS-PQ-2025-09", "FIPS_TLS13_12_PQ": "TLS13-1-2-FIPS-PQ-2025-09",
    "FIPS_TLS13_12_RES_PQ": "TLS13-1-2-Res-FIPS-PQ-2025-09",
    "FIPS_TLS13_12_EXT0_PQ": "TLS13-1-2-Ext0-FIPS-PQ-2025-09",
    "FIPS_TLS13_12_EXT1_PQ": "TLS13-1-2-Ext1-FIPS-PQ-2025-09",
    "FIPS_TLS13_12_EXT2_PQ": "TLS13-1-2-Ext2-FIPS-PQ-2025-09",
    "FIPS_TLS13_10_PQ": "TLS13-1-0-FIPS-PQ-2025-09",
    "FORWARD_SECRECY_TLS12_RES_GCM": "FS-1-2-Res-2020-10",
    "FORWARD_SECRECY_TLS12_RES": "FS-1-2-Res-2019-08", "FORWARD_SECRECY_TLS12": "FS-1-2-2019-08",
    "FORWARD_SECRECY_TLS11": "FS-1-1-2019-08", "FORWARD_SECRECY": "FS-2018-06",
    "TLS12": "TLS-1-2-2017-01", "TLS12_EXT": "TLS-1-2-Ext-2018-06", "TLS11": "TLS-1-1-2017-01",
}

# A name only where it is one of the table's: an unknown name claims nothing.
_LITERAL = re.compile(r"(?<![A-Za-z0-9-])(ELBSecurityPolicy-[A-Za-z0-9-]+?)(?![A-Za-z0-9-])")
_CDK = re.compile(r"\bSslPolicy\.([A-Z0-9_]+)\b")


def scan(line: str) -> list[tuple[str, int]]:
    """(policy, position) for each known policy this line names, literally or by CDK enum."""
    out: list[tuple[str, int]] = []
    if "ELBSecurityPolicy-" in line:
        out += [(m.group(1), m.start(1)) for m in _LITERAL.finditer(line)
                if m.group(1) in POLICIES]
    if "SslPolicy." in line:
        out += [(f"ELBSecurityPolicy-{CDK_ENUM[m.group(1)]}", m.start(1))
                for m in _CDK.finditer(line) if m.group(1) in CDK_ENUM]
    return out


def families(policy: str) -> list[str]:
    _versions, pq, rsa = POLICIES[policy]
    return ["ECDH"] + (["ML-KEM"] if pq else []) + (["RSA"] if rsa else [])


def describe(policy: str, default: bool = False) -> str:
    versions, pq, rsa = POLICIES[policy]
    parts = [", ".join(versions),
             "hybrid ML-KEM groups beside classical (EC)DHE" if pq
             else "classical (EC)DHE only, no post-quantum group"]
    if rsa:
        parts.append("RSA key-transport suites")
    said = f"AWS ELB TLS policy {policy}: " + "; ".join(parts) + "."
    if default:
        said += (f" Not written in the file: {DEFAULT_APPLIED} (AWS: the default for the "
                 f"CLI, CloudFormation, the CDK and the API; Terraform sends none). The "
                 f"console default differs.")
    return said


def asset(policy: str, default: bool = False) -> dict[str, Any]:
    """The policy as a configured-protocol asset: what it allows, in its own words."""
    versions, pq, _rsa = POLICIES[policy]
    item: dict[str, Any] = {
        "protocol": "tls",
        "version": None,
        "policy": policy,
        "allows_versions": list(versions),
        "post_quantum": pq,
        "deprecated": any(v in ("TLSv1.0", "TLSv1.1") for v in versions),
        "basis": "provider_default" if default else "configured_protocol",
        "description": describe(policy, default),
    }
    if default:
        item["default_applied"] = DEFAULT_APPLIED
    return item


# --- a listener with no policy ----------------------------------------------------------
#
# Block-level, never line-level: `redirect { protocol = "HTTPS" }` inside an HTTP
# listener's default_action is the commonest Terraform pattern there is, and a flat
# search reads it as an HTTPS listener. Only a top-level `protocol` and `ssl_policy` count.

_TF_LISTENER = re.compile(r'^\s*resource\s+"aws_(?:lb|alb)_listener"\s+"[^"]*"\s*\{')
_TF_PROTOCOL = re.compile(r'^\s*protocol\s*=\s*"(HTTPS|TLS)"', re.IGNORECASE)
_TF_POLICY = re.compile(r"^\s*ssl_policy\s*=")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_CFN_TYPE = re.compile(r"""^(\s*)Type:\s*["']?AWS::ElasticLoadBalancingV2::Listener["']?\s*$""")


def _terraform(lines: list[str]) -> list[int]:
    found: list[int] = []
    i = 0
    while i < len(lines):
        if not _TF_LISTENER.match(lines[i]):
            i += 1
            continue
        start, depth, https, policy = i, 0, False, False
        while i < len(lines):
            code = _STRING.sub('""', lines[i]).split("#", 1)[0].split("//", 1)[0]
            if depth == 1:
                https = https or bool(_TF_PROTOCOL.match(lines[i]))
                policy = policy or bool(_TF_POLICY.match(lines[i]))
            depth += code.count("{") - code.count("}")
            i += 1
            if depth <= 0:
                break
        if https and not policy:
            found.append(start + 1)
    return found


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _cfn_yaml(lines: list[str]) -> list[int]:
    found: list[int] = []
    for t, line in enumerate(lines):
        match = _CFN_TYPE.match(line)
        if not match:
            continue
        type_indent = len(match.group(1))
        # The logical ID: the nearest line above that is less indented.
        head = next((j for j in range(t - 1, -1, -1)
                     if lines[j].strip() and _indent(lines[j]) < type_indent), None)
        if head is None:
            continue
        block: list[str] = []
        for following in lines[head + 1:]:
            if following.strip() and _indent(following) <= _indent(lines[head]):
                break
            block.append(following)
        props = next((k for k, text in enumerate(block)
                      if text.strip() == "Properties:" and _indent(text) == type_indent), None)
        if props is None:
            continue
        children = [text for text in block[props + 1:] if text.strip()]
        child_indent = _indent(children[0]) if children else 0
        direct = []
        for text in children:
            if _indent(text) <= type_indent:
                break
            if _indent(text) == child_indent:
                direct.append(text.strip())
        https = any(re.match(r"""Protocol:\s*["']?(HTTPS|TLS)["']?\s*$""", d) for d in direct)
        if https and not any(d.startswith("SslPolicy:") for d in direct):
            found.append(head + 1)
    return found


def _cfn_json(lines: list[str]) -> list[int]:
    try:
        doc = json.loads("\n".join(lines))
    except (ValueError, TypeError):
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return []
    found: list[int] = []
    for name, resource in resources.items():
        if not (isinstance(resource, dict)
                and resource.get("Type") == "AWS::ElasticLoadBalancingV2::Listener"):
            continue
        props = resource.get("Properties")
        if not isinstance(props, dict) or "SslPolicy" in props:
            continue
        if props.get("Protocol") in ("HTTPS", "TLS"):
            key = re.compile(r'"' + re.escape(name) + r'"\s*:')
            found.append(next((n for n, text in enumerate(lines, 1) if key.search(text)), 1))
    return found


def listeners_without_policy(suffix: str, lines: list[str]) -> list[int]:
    """Lines of HTTPS/TLS listener resources that set no policy. Terraform and
    CloudFormation; the CDK is not read this way (see the README)."""
    if suffix in (".tf",):
        return _terraform(lines)
    if suffix in (".yaml", ".yml"):
        return _cfn_yaml(lines)
    if suffix == ".json":
        return _cfn_json(lines)
    return []
