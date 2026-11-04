"""IBM MQ channels without TLS (ZA-OPRAVYANE row 202, remainder).

IBM MQ 9.4, "Configuring TLS channels with MQSC"
(https://www.ibm.com/docs/SSFKSJ_9.4.0/secure/tlschannels.html): "To alter an IBM MQ channel
to disable TLS, set SSLCIPH to a blank value. For example: ALTER CHANNEL('MQ.TEST')
CHLTYPE(SDR) SSLCIPH(' ')". So `SSLCIPH(' ')` (or `SSLCIPH('')`) on a DEFINE or ALTER CHANNEL
is a channel without TLS. A DEFINE CHANNEL that names no SSLCIPH takes the attribute from the
object it is modelled on (the SYSTEM.DEF channel of its type, or LIKE), which this file does not
show: it is said as such, not as a fact about the wire. The channel type is reported as written;
the rule was checked against IBM's SDR example, not separately for every type.

MQSC continues a command on the next line with a trailing `+` or `-`; those are joined first.
"""

from __future__ import annotations

import re
from typing import Any

_CHANNEL = re.compile(r"^\s*(DEFINE|ALTER|DEF)\s+(?:CHANNEL|CHL)\s*\(\s*'?([^')]*)'?\s*\)", re.I)
_TYPE = re.compile(r"\bCHLTYPE\s*\(\s*(\w+)\s*\)", re.I)
_SSLCIPH = re.compile(r"\bSSLCIPH\s*\(\s*('?)([^')]*)\1\s*\)", re.I)
_LIKE = re.compile(r"\bLIKE\s*\(", re.I)


def _commands(lines: list[str]):
    command, start = "", 0
    for number, line in enumerate(lines, 1):
        text = line.rstrip()
        if not command:
            start = number
            if text.lstrip().startswith("*"):
                continue
        if text.endswith(("+", "-")):
            command += text[:-1] + " "
            continue
        yield start, command + text
        command = ""
    if command:
        yield start, command


def scan(lines: list[str]) -> list[dict[str, Any]]:
    """A TLS place for each MQSC channel with a blank SSLCIPH, or none on its DEFINE."""
    out: list[dict[str, Any]] = []
    for number, command in _commands(lines):
        channel = _CHANNEL.match(command)
        if not channel:
            continue
        verb, name = channel.group(1).upper(), channel.group(2)
        kind = _TYPE.search(command)
        kind = kind.group(1).upper() if kind else "type not stated"
        cipher = _SSLCIPH.search(command)
        if cipher and not cipher.group(2).strip():
            said = (f"IBM MQ channel {name} ({kind}) has a blank SSLCIPH: no TLS. IBM: \"To "
                    f"alter an IBM MQ channel to disable TLS, set SSLCIPH to a blank value.\"")
            setting, flags = "SSLCIPH(' ')", {"tls_disabled": True}
        elif cipher is None and verb.startswith("DEF"):
            model = "the object named by LIKE" if _LIKE.search(command) else f"SYSTEM.DEF.{kind}"
            said = (f"IBM MQ channel {name} ({kind}) is defined without SSLCIPH: it takes the "
                    f"attribute from {model}, which this file does not show. A blank SSLCIPH "
                    f"is a channel without TLS; whether this one has TLS is not established.")
            setting, flags = "no SSLCIPH", {"tls_not_established": True}
        else:
            continue
        out.append({"line": number, "excerpt": command.strip()[:200], "protocol": "tls",
                    "version": None, "basis": "configured_switch", "setting": setting,
                    "channel": name, "channel_type": kind, "deprecated": False,
                    "description": said, **flags})
    return out
