"""Rows 302, 364, 365, 366 (04.11.2026): a switch or command that turns an algorithm OFF.

Each was reported as a use, and 302 raised readiness: a build script writing
`USE_ML_KEM_768=false` into Libreswan's make configuration gave `hybrid_partial`. A ban is
named and is never a use (evidence_kind `ban`, confidence low).

- 302: Libreswan `mk/config.mk`: "USE_ML_KEM_768 ?= true", "When USE_<package>=true,
  -DUSE_<package> is added to CFLAGS"
  (https://github.com/libreswan/libreswan/blob/main/mk/config.mk). `=false` builds without.
- 364: SCHANNEL `Enabled`=0 under `Ciphers\\RC4 128/128` disables RC4: Microsoft Security
  Advisory 2868725 (https://support.microsoft.com/en-us/kb/2868725), KB 245030
  (https://support.microsoft.com/kb/245030); for protocols, "change the DWORD registry value of
  Enabled to 0" (https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings).
- 365: "The Disable-TlsCipherSuite cmdlet disables a cipher suite"
  (https://learn.microsoft.com/en-us/powershell/module/tls/disable-tlsciphersuite).
- 366: Disable-TlsEccCurve -Name: "Specifies the name of the ECC curve to disable"
  (https://learn.microsoft.com/en-us/powershell/module/tls/disable-tlsecccurve)."""

from __future__ import annotations


def _kinds(result, family):
    return {(e["path"], e["line"], e["evidence_kind"]) for e in result["evidence"]["source_code"]
            if e["algorithm"] == family}


def test_echoed_switch_off_does_not_raise_readiness(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "build.sh").write_text(
        '#!/bin/sh\necho "USE_ML_KEM_768=false" >> Makefile.inc.local\n'
        "echo USE_ML_KEM_1024=false >> Makefile.inc.local\n"
        'echo "USE_ML_KEM_512=true" >> Makefile.inc.local\n'
        "openssl genrsa -out k.pem 2048\n")
    result = scan_directory(tmp_path)
    kinds = _kinds(result, "ML-KEM")
    assert ("build.sh", 2, "ban") in kinds and ("build.sh", 3, "ban") in kinds
    assert all(k != "ban" for p, n, k in kinds if n == 4)


def test_echoed_switch_off_alone_is_not_hybrid(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "build.sh").write_text(
        '#!/bin/sh\necho "USE_ML_KEM_768=false" >> Makefile.inc.local\n'
        "openssl genrsa -out k.pem 2048\n")
    assert scan_directory(tmp_path)["summary"]["pqc_readiness"] == "classical_only"


def test_schannel_key_set_to_disabled_is_a_ban(tmp_path):
    from qrp_mcp.scan import scan_directory
    key = "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
    (tmp_path / "off.ini").write_text(
        f"{key}\\Ciphers\\RC4 128/128]\n\"Enabled\"=dword:00000000\n\n"
        f"{key}\\KeyExchangeAlgorithms\\Diffie-Hellman]\n\"Enabled\"=dword:00000000\n")
    (tmp_path / "on.ini").write_text(
        f"{key}\\Ciphers\\RC4 128/128]\n\"Enabled\"=dword:ffffffff\n")
    result = scan_directory(tmp_path)
    assert _kinds(result, "RC4") == {("off.ini", 1, "ban"), ("on.ini", 1, "reference")}
    assert {k for _, _, k in _kinds(result, "DH")} == {"ban"}


def test_disable_tls_cmdlets_are_bans(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "tls.ps1").write_text(
        'Disable-TlsCipherSuite -Name "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"\n'
        'Disable-TlsEccCurve -Name "NistP384"\n'
        'Enable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA" -Position 0\n')
    result = scan_directory(tmp_path)
    assert {k for _, _, k in _kinds(result, "ECDSA")} == {"ban"}
    assert {k for _, _, k in _kinds(result, "ECDH")} == {"ban"}
    assert {k for _, n, k in _kinds(result, "EC") if n == 2} == {"ban"}
    assert {k for _, _, k in _kinds(result, "3DES")} != {"ban"}
