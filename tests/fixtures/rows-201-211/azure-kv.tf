resource "azurerm_key_vault_key" "signing" {
  name         = "doc-signing"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["sign", "verify"]
}

resource "azurerm_key_vault_key" "exchange" {
  name         = "partner-exchange"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]
}
