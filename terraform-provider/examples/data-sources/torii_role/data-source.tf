# Look up an existing role by name (or set id instead).
data "torii_role" "admin" {
  name = "admin"
}
