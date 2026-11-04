"""IBM MQ channels without TLS (ZA-OPRAVYANE row 202, remainder; fixture
linkedin-postove/2026-11-04/qrp-stai/proba/sb-swift/mq). IBM MQ 9.4, "Configuring TLS channels
with MQSC", https://www.ibm.com/docs/SSFKSJ_9.4.0/secure/tlschannels.html: "To alter an IBM MQ
channel to disable TLS, set SSLCIPH to a blank value. For example: ALTER CHANNEL('MQ.TEST')
CHLTYPE(SDR) SSLCIPH(' ')".
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

CHANNELS = """* channels of the SWIFT gateway
DEFINE CHANNEL('SAA.TO.CORE') CHLTYPE(SDR) TRPTYPE(TCP) SSLCIPH('TLS_RSA_WITH_AES_256_CBC_SHA256') REPLACE
DEFINE CHANNEL('MW.SVRCONN') CHLTYPE(SVRCONN) TRPTYPE(TCP) SSLCIPH(' ') REPLACE
ALTER CHANNEL('MQ.TEST') CHLTYPE(SDR) SSLCIPH('')
DEFINE CHANNEL('TO.BRANCH') CHLTYPE(CLUSSDR) +
       CONNAME('branch(1414)') REPLACE
* SSLCIPH(' ') in a comment configures nothing
"""


def test_blank_and_missing_sslciph(tmp_path):
    (tmp_path / "channels.mqsc").write_text(CHANNELS)
    result = scan_directory(tmp_path)
    rows = [(p["line"], p["channel"], p["channel_type"], p["setting"])
            for p in result["evidence"]["protocols"] if p.get("channel")]
    assert rows == [(3, "MW.SVRCONN", "SVRCONN", "SSLCIPH(' ')"),
                    (4, "MQ.TEST", "SDR", "SSLCIPH(' ')"),
                    (5, "TO.BRANCH", "CLUSSDR", "no SSLCIPH")]
    flags = {p["channel"]: (p.get("tls_disabled"), p.get("tls_not_established"))
             for p in result["evidence"]["protocols"] if p.get("channel")}
    assert flags["MW.SVRCONN"] == (True, None) and flags["TO.BRANCH"] == (None, True)
    names = {c["name"] for c in build(result)["components"]}
    assert "IBM MQ channel MW.SVRCONN (SSLCIPH(' '))" in names
