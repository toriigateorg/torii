# Look up an existing user by username (or set id instead).
data "torii_user" "alice" {
  username = "alice"
}
