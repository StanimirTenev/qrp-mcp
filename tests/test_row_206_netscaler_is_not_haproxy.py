"""ZA-OPRAVYANE row 206 (LinkedIn, 04.11.2026; fixture from the room's probe `ig-ns`, whose
NetScaler syntax was written from memory and is not checked against the vendor's manual).

Every `bind ssl profile ...` line of a NetScaler-style `ns.conf` read as "TLS is terminated
here (HAProxy `bind ... ssl`)", five times, the back-end profile included. HAProxy's `bind`
takes an address first; `bind ssl ...` is not an HAProxy listener, and is no longer read as
one. The algorithms on those lines are still found; reading ns.conf itself (front end and back
end, its curve names) is not attempted."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "row-206" / "ns.conf"


def test_bind_ssl_profile_is_not_an_haproxy_listener(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURE, tmp_path / "ns.conf")
    result = scan_directory(tmp_path)
    listeners = [p for p in result["evidence"]["protocols"]
                 if p.get("listener") == "HAProxy bind"]
    assert listeners == []
    families = {f["algorithm_family"] for f in result["findings"]}
    assert {"ML-KEM", "X25519", "ECDH", "RSA"} <= families


def test_haproxy_bind_still_is(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "haproxy.cfg").write_text(
        "frontend fe\n    bind :443 ssl crt /etc/haproxy/site.pem\n")
    listeners = [p for p in scan_directory(tmp_path)["evidence"]["protocols"]
                 if p.get("listener") == "HAProxy bind"]
    assert [p["line"] for p in listeners] == [2]
