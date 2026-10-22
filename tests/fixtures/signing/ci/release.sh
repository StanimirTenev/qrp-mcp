#!/bin/sh
openssl dgst -sha256 -sign keys/fw_signing.pem -out fw.sig build/fw.bin
cosign sign --key cosign.key ghcr.io/example/agent:1.4
sbsign --key keys/db.key --cert keys/db.crt --output grubx64.efi.signed grubx64.efi
