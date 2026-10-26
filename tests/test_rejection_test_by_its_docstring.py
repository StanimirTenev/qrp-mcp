"""A test whose docstring says the thing is removed or disabled tests that it is refused
(rel3-rules review of rel3e, 26.10.2026). Mbed TLS's tests/scripts/test_config_checks.py sets
`#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED` to check that the build rejects an option that was
removed; 10 of rel3e's 30 sampled added rows sat in that file and were judged FALSE. They had
been `comment` only because a value's closing triple quote flipped the docstring state; with
that fixed (rel3e) they read as RSA and MD5 use.

The test's name, the configuration it feeds and the error it expects are about a refusal, as a
`pytest.raises` block is (row 91); and the message a test expects is text, as a prose string is.
"""

from pathlib import Path

from qrp_mcp import detectors as d

REMOVED = '''class T:
    def test_define_KEY_EXCHANGE_RSA_ENABLED(self) -> None:
        """Error when setting a removed option."""
        self.bad_case('#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED',
                      error='MBEDTLS_KEY_EXCHANGE_RSA_ENABLED was removed')

    def test_exempt_define_KEY_EXCHANGE_RSA_ENABLED(self) -> None:
        """Bypassed error when setting a removed option."""
        self.good_case(None,
                       '#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED',
                       extra_options=['-DMBEDTLS_CONFIG_CHECK_BYPASS'])

    def test_define_MD5_C_added(self) -> None:
        """Error when setting an internal option that was disabled."""
        self.bad_case('#undef MBEDTLS_MD5_C',
                      '#define MBEDTLS_MD5_C',
                      error=r'MBEDTLS_MD5_C is an internal macro')

    def test_no_ecdsa(self) -> None:
        """An error expected from the check based on the configuration."""
        self.bad_case('#undef PSA_WANT_ALG_ECDSA',
                      error='MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED')

    def test_rsa_sign(self) -> None:
        """RSA signatures verify."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
'''


def _rows(text, name="tests/scripts/test_config_checks.py"):
    lines = text.split("\n")
    return d.scan_source_file(Path(name), name, lines)


def _used(rows):
    return {(r["line"], r["algorithm"]) for r in rows if r["evidence_kind"] not in ("comment", "ban")}


def test_a_test_of_a_removed_or_disabled_option_is_a_rejection_test():
    used = _used(_rows(REMOVED))
    assert not {u for u in used if u[0] <= 17}, sorted(used)


def test_the_error_a_test_expects_is_text():
    used = _used(_rows(REMOVED))
    assert (22, "ECDSA") not in used and (22, "ECDH") not in used, sorted(used)


def test_a_test_that_is_not_about_a_refusal_still_uses():
    used = _used(_rows(REMOVED))
    assert (26, "RSA") in used
    # And the rule follows the docstring, not the name of the file.
    assert (26, "RSA") in _used(_rows(REMOVED, "lib/checks.py"))


def test_a_function_that_is_not_a_test_keeps_its_calls():
    text = ('def load(path):\n    """Load a key; DSA keys are rejected."""\n'
            '    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    assert (3, "RSA") in _used(_rows(text, "lib/keys.py"))


def test_the_gate_and_the_full_read_agree():
    lines = REMOVED.split("\n")
    name = "tests/scripts/test_config_checks.py"
    hot = d.hot_lines(lines, ".py")
    assert (d.scan_source_file(Path(name), name, lines, hot=None)
            == d.scan_source_file(Path(name), name, lines, hot=hot))
