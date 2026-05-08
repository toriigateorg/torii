resource "torii_role_service" "viewer_grafana" {
  role_id    = torii_role.viewer.id
  service_id = torii_service.grafana.id
}
