# Assigns a role to a user. The built-in "all" role is auto-assigned by torii
# and must not be managed here.
resource "torii_user_role" "alice_viewer" {
  user_id = torii_user.alice.id
  role_id = torii_role.viewer.id
}
