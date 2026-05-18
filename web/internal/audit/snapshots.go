package audit

import (
	"encoding/json"

	"torii/internal/db"
)

const Redacted = "[redacted]"

func SnapshotUser(u db.User) map[string]any {
	return map[string]any{
		"id":            u.ID.String(),
		"username":      u.Username,
		"email":         u.Email,
		"first_name":    u.FirstName,
		"last_name":     u.LastName,
		"password_hash": Redacted,
		"created_at":    TimestamptzToString(u.CreatedAt),
		"updated_at":    TimestamptzToString(u.UpdatedAt),
	}
}

func SnapshotRole(r db.Role) map[string]any {
	return map[string]any{
		"id":          r.ID.String(),
		"name":        r.Name,
		"description": r.Description,
		"is_system":   r.IsSystem,
		"created_at":  TimestamptzToString(r.CreatedAt),
		"updated_at":  TimestamptzToString(r.UpdatedAt),
	}
}

func SnapshotService(s db.Service) map[string]any {
	var headers any = nil
	if len(s.Headers) > 0 {
		var parsed any
		if err := json.Unmarshal(s.Headers, &parsed); err == nil {
			headers = parsed
		} else {
			headers = string(s.Headers)
		}
	}
	return map[string]any{
		"id":                 s.ID.String(),
		"title":              s.Title,
		"description":        s.Description,
		"service_url":        s.ServiceUrl,
		"domain":             s.Domain,
		"headers":            headers,
		"preserve_host":      s.PreserveHost,
		"passthrough_errors": s.PassthroughErrors,
		"created_at":         TimestamptzToString(s.CreatedAt),
		"updated_at":         TimestamptzToString(s.UpdatedAt),
	}
}

func SnapshotSSOProvider(p db.SsoProvider) map[string]any {
	return map[string]any{
		"id":            p.ID.String(),
		"slug":          p.Slug,
		"name":          p.Name,
		"issuer_url":    p.IssuerUrl,
		"client_id":     p.ClientID,
		"client_secret": Redacted,
		"scopes":        p.Scopes,
		"enabled":       p.Enabled,
		"allow_signup":  p.AllowSignup,
		"link_by_email": p.LinkByEmail,
		"created_at":    TimestamptzToString(p.CreatedAt),
		"updated_at":    TimestamptzToString(p.UpdatedAt),
	}
}
