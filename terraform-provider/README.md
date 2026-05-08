# terraform-provider-torii

Manage [torii](../web) services and RBAC roles via Terraform.

> **Status:** v0, in-tree, not yet published to the Terraform Registry.
> Use via local `dev_overrides`.

## Resources

| Resource              | Wraps                                      |
| --------------------- | ------------------------------------------ |
| `torii_service`       | `/api/v1/admin/services`                   |
| `torii_role`          | `/api/v1/admin/roles` (+ permissions PUT)  |
| `torii_role_service`  | `/api/v1/admin/roles/:id/services`         |

User management, SSO providers, settings, and audit logs are not yet exposed.

## Bootstrap

The provider authenticates to torii with a long-lived API token
(`Authorization: Bearer torii_pat_...`). To mint one:

1. Sign in to the torii UI as an admin.
2. From a logged-in browser, copy a fresh access token, then:

   ```
   curl -X POST https://torii.example.com/api/v1/admin/api_tokens \
     -H "Authorization: Bearer <admin_jwt>" \
     -H "Content-Type: application/json" \
     -d '{"user_id":"<admin_user_uuid>","name":"terraform"}'
   ```

3. Save the returned `token` field — it is shown once.
4. Export it for the provider:

   ```
   export TORII_ENDPOINT=https://torii.example.com
   export TORII_API_TOKEN=torii_pat_...
   ```

The token inherits the owning user's permissions. Give the token's user the
`services.*`, `roles.*`, `role_services.*`, and `permissions.read`
permissions.

## Local development

```
cd terraform-provider
go mod tidy
make install   # installs into ~/.terraform.d/plugins/...
```

Then in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "torii/torii" = "/path/to/torii/terraform-provider"
  }
  direct {}
}
```

## Example

```hcl
terraform {
  required_providers {
    torii = { source = "torii/torii" }
  }
}

provider "torii" {}

resource "torii_service" "grafana" {
  title       = "Grafana"
  service_url = "http://grafana.internal:3000"
  domain      = "grafana.example.com"
}

resource "torii_role" "viewer" {
  name        = "viewer"
  permissions = ["services.read"]
}

resource "torii_role_service" "viewer_grafana" {
  role_id    = torii_role.viewer.id
  service_id = torii_service.grafana.id
}
```
