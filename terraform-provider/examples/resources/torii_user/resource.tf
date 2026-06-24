resource "torii_user" "alice" {
  username   = "alice"
  email      = "alice@example.com"
  first_name = "Alice"
  last_name  = "Anderson"
  # Write-only: the API never returns the password, so changing it here is the
  # only way to rotate it. username/email/first_name/last_name force replacement.
  password = var.alice_password
}

variable "alice_password" {
  type      = string
  sensitive = true
}
