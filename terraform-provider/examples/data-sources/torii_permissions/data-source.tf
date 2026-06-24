# The catalog of permission strings torii recognizes.
data "torii_permissions" "all" {}

output "torii_permissions" {
  value = data.torii_permissions.all.permissions
}
