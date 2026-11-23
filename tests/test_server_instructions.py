"""The server tells a model when to reach for it (ZA-OPRAVYANE row 543).

`instructions` travels in the initialize result, before any tool is listed. It is
the one sentence a client can put in front of the model, so it carries the words
people ask with: quantum-vulnerable cryptography, RSA/ECDSA/DH, cryptographic
inventory, CBOM.
"""

from __future__ import annotations

import asyncio

from mcp import Client

from qrp_mcp.server import mcp


def _initialize_instructions() -> str | None:
    async def run() -> str | None:
        # "legacy" forces the initialize handshake rather than server/discover.
        async with Client(mcp._build(), mode="legacy") as client:
            return client.instructions

    return asyncio.run(run())


def test_initialize_result_carries_instructions():
    text = _initialize_instructions()
    assert text, "the initialize result carries no instructions"
    lowered = text.lower()
    for words in ("quantum-vulnerable", "rsa", "ecdsa", "dh",
                  "cryptographic inventory", "cbom"):
        assert words in lowered, f"instructions do not say {words!r}"
