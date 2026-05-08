resource "torii_role" "viewer" {
  name        = "viewer"
  description = "Read-only access to a curated set of services."

  permissions = [
    "services.read",
  ]
}
