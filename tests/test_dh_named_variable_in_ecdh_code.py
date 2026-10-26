"""A `dh_` variable in ECDH code is not finite-field DH (scoreboard judge, kragg-3/05, 26.10.2026).

OpenSSH kexecdh.c names the peer's EC point `dh_pub`: `EC_POINT *dh_pub`,
`sshbuf_get_ec(buf, dh_pub, group)`, `ECDH_compute_key(kbuf, klen, dh_pub, key, NULL)`. The
identifier pass read DH from `dh_pub` on 7 lines, all of them ECDH. A DH carried by an
identifier on a line that also names the elliptic-curve side (EC_POINT, ECDH_*, `_ec`, X25519)
is the generic "Diffie-Hellman" of ECDH and is dropped. Real DH stays: OpenSSH dh.c, kexdh.c
and kexgexs.c's `DH_GRP_MIN` name no curve on the line.
"""

from qrp_mcp.scan import scan_directory

ECDH_C = """#include <openssl/ecdh.h>

int
kex_ecdh_dec_key_group(EC_KEY *key, const EC_GROUP *group, struct sshbuf *buf)
{
	EC_POINT *dh_pub = NULL;
	if ((dh_pub = EC_POINT_new(group)) == NULL)
		return -1;
	if (sshbuf_get_ec(buf, dh_pub, group) != 0)
		return -1;
	if (sshkey_ec_validate_public(group, dh_pub) != 0)
		return -1;
	if (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (int)klen)
		return -1;
	EC_POINT_clear_free(dh_pub);
	return 0;
}
"""

FFDH_C = """#include <openssl/dh.h>

int
kexgex_server(struct ssh *ssh, u_int min, u_int max)
{
	DH *dh;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	dh_pub = dh_pub_from(dh);
	return kex_dh_keypair(ssh->kex);
}
"""


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["evidence"]["source_code"]


def test_dh_named_ec_point_is_not_dh(tmp_path):
    rows = _rows(tmp_path, "kexecdh.c", ECDH_C)
    dh = [(e["line"], e["excerpt"]) for e in rows if e["algorithm"] == "DH"]
    assert dh == [], dh
    families = {e["algorithm"] for e in rows}
    assert {"EC", "ECDH"} <= families, families


def test_finite_field_dh_identifiers_stay(tmp_path):
    rows = _rows(tmp_path, "kexgexs.c", FFDH_C)
    dh_lines = {e["line"] for e in rows if e["algorithm"] == "DH"}
    assert {7, 8, 9, 10} <= dh_lines, dh_lines
