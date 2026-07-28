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

// redactedHeaders keeps the names from a services.headers overlay and replaces
// every value with Redacted, so a header diff stays readable without carrying
// the credential. The overlay is documented as the place to put a service
// account bearer for upstreams running their own auth, and audit rows are served
// to anyone holding audit.read — a permission an auditor gets without
// services.read. Values must not land in audit_logs.metadata or audit.jsonl:
// `before` snapshots would keep them recoverable after rotation, and the JSONL
// file is not touched by `torii audit prune`.
func redactedHeaders(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Redacted
	}
	return redactValues(parsed)
}

func redactValues(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k := range m {
		out[k] = Redacted
	}
	return out
}

// RedactHeadersIn walks decoded audit metadata and redacts the values of any
// "headers" map in it. Belt-and-braces for rows written before SnapshotService
// redacted them: they stay on disk, but stop being served. Mutates in place.
func RedactHeadersIn(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k != "headers" {
				RedactHeadersIn(val)
				continue
			}
			switch h := val.(type) {
			case nil:
			case map[string]any:
				t[k] = redactValues(h)
			default:
				t[k] = Redacted
			}
		}
	case []any:
		for _, item := range t {
			RedactHeadersIn(item)
		}
	}
}

func SnapshotService(s db.Service) map[string]any {
	return map[string]any{
		"id":                 s.ID.String(),
		"title":              s.Title,
		"description":        s.Description,
		"service_url":        s.ServiceUrl,
		"domain":             s.Domain,
		"headers":            redactedHeaders(s.Headers),
		"preserve_host":      s.PreserveHost,
		"passthrough_errors": s.PassthroughErrors,
		"max_body_size":      s.MaxBodySize,
		"read_timeout_secs":  s.ReadTimeoutSecs,
		"write_timeout_secs": s.WriteTimeoutSecs,
		"dial_timeout_secs":  s.DialTimeoutSecs,
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
