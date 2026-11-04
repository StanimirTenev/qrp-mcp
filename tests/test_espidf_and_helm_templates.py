"""ESP-IDF sdkconfig files, EC J-PAKE, and Helm template partials (ZA-OPRAVYANE rows 304, 309;
fixtures L1/f02-espidf, L1/f14-helm-tpl).

* ESP-IDF build system, https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/build-system.html:
  "create a file `sdkconfig.defaults` in the project directory"; "If and only if an
  `sdkconfig.defaults` file exists ... `sdkconfig.defaults.TARGET_NAME`". All were type not
  claimed (91 files in one real tree).
* EC J-PAKE: RFC 8236, https://www.rfc-editor.org/rfc/rfc8236 -- "This document specifies a
  Password-Authenticated Key Exchange by Juggling (J-PAKE) protocol"; "The J-PAKE protocol
  works basically the same in the elliptic curve (EC) setting". ESP-IDF Kconfig reference,
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html:
  CONFIG_MBEDTLS_ECJPAKE_C "Elliptic curve J-PAKE"; CONFIG_MBEDTLS_KEY_EXCHANGE_ECJPAKE "Enable
  to support ciphersuites with prefix TLS-ECJPAKE-WITH-".
* Helm, https://helm.sh/docs/chart_template_guide/named_templates/: `_helpers.tpl` is "the
  default location for template partials".

Not done here (A's rows): a `=n` value is not yet told from `=y`.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name", ["sdkconfig", "sdkconfig.defaults", "sdkconfig.defaults.esp32s3",
                                  "sdkconfig.ci"])
def test_sdkconfig_files_are_read(tmp_path, name):
    (tmp_path / name).write_text("CONFIG_MBEDTLS_KEY_EXCHANGE_ECJPAKE=y\nCONFIG_MBEDTLS_ECJPAKE_C=y\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    rows = [(f["line"], f["algorithm"]) for f in result["evidence"]["source_code"]
            if "J-PAKE" in f["description"]]
    assert rows == [(1, "EC"), (2, "EC")]


def test_ecjpake_in_c(tmp_path):
    (tmp_path / "thread.c").write_text(
        "int f(mbedtls_ecjpake_context *ctx) {\n"
        "    return mbedtls_ecjpake_setup(ctx, MBEDTLS_ECJPAKE_CLIENT, MBEDTLS_MD_SHA256,\n"
        "                                 MBEDTLS_ECP_DP_SECP256R1, pskc, len);\n}\n")
    result = scan_directory(tmp_path)
    assert {f["line"] for f in result["evidence"]["source_code"] if "J-PAKE" in f["description"]} == {1, 2}


def test_jpake_word_alone_is_not_ec(tmp_path):
    # Finite-field J-PAKE exists too; only the EC spellings are EC.
    (tmp_path / "a.c").write_text("int jpake_round(void);\n")
    result = scan_directory(tmp_path)
    assert result["evidence"]["source_code"] == []


@pytest.mark.parametrize("name", ["templates/_helpers.tpl", "templates/nginx.gotmpl"])
def test_helm_template_partials_are_read(tmp_path, name):
    (tmp_path / "templates").mkdir()
    (tmp_path / name).write_text('{{- define "app.nginxTls" -}}\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n'
                                 "ssl_ecdh_curve prime256v1;\n{{- end -}}\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0", "TLSv1.1"]
