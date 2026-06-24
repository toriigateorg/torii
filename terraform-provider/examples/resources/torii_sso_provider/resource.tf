resource "torii_sso_provider" "google" {
  slug          = "google"
  name          = "Google"
  issuer_url    = "https://accounts.google.com"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret # write-only; never returned by the API
  scopes        = "openid email profile"
  enabled       = true
  allow_signup  = false
  link_by_email = true
}

variable "google_client_id" {
  type = string
}

variable "google_client_secret" {
  type      = string
  sensitive = true
}
