resource "vault_pki_secret_backend_root_cert" "root" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = "Bank Internal Root CA"
  key_type    = "rsa"
  key_bits    = 4096
}

resource "vault_pki_secret_backend_role" "services" {
  backend   = vault_mount.pki_int.path
  name      = "services"
  key_type  = "ec"
  key_bits  = 256
  max_ttl   = "720h"
}

resource "vault_transit_secret_backend_key" "payments" {
  backend = vault_mount.transit.path
  name    = "payments-signing"
  type    = "rsa-2048"
}

resource "vault_transit_secret_backend_key" "pii" {
  backend = vault_mount.transit.path
  name    = "pii"
  type    = "aes256-gcm96"
}
