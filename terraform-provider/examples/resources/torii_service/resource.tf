resource "torii_service" "grafana" {
  title       = "Grafana"
  description = "Internal metrics dashboard"
  service_url = "http://grafana.internal:3000"
  domain      = "grafana.example.com"

  headers = {
    "X-Forwarded-User" = "torii"
  }
}
