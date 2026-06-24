# Look up an existing service by domain (or set id instead).
data "torii_service" "grafana" {
  domain = "grafana.example.com"
}
