package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// upstreamErrorPage mirrors the look of client/app/error.vue (console-card,
// mono labels, light/dark via prefers-color-scheme). We render it standalone
// because this page is served on the upstream service's domain, where the
// torii SPA / Tailwind runtime is not available.
const upstreamErrorPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%[1]d &middot; %[2]s</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f7f7f8;
    --fg: #0a0a0a;
    --muted: #6b7280;
    --card: #ffffff;
    --border: rgba(0,0,0,.08);
    --soft: rgba(0,0,0,.04);
    --accent: #f59e0b;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0a0a0b;
      --fg: #ededed;
      --muted: #9ca3af;
      --card: #111113;
      --border: rgba(255,255,255,.08);
      --soft: rgba(255,255,255,.04);
    }
  }
  * { box-sizing: border-box; }
  html, body { height: 100%%; }
  body {
    margin: 0;
    font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--fg);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .wrap { width: 100%%; max-width: 720px; }
  .card {
    border: 1px solid var(--border);
    background: color-mix(in oklab, var(--card) 92%%, transparent);
    backdrop-filter: blur(6px);
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 20px 60px -20px rgba(0,0,0,.35);
  }
  .strip {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--soft);
  }
  .dots { display: flex; gap: 6px; align-items: center; }
  .dot { width: 8px; height: 8px; border-radius: 999px; background: color-mix(in oklab, var(--fg) 18%%, transparent); }
  .ping { width: 6px; height: 6px; border-radius: 999px; background: var(--accent); margin-left: 6px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10px; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); }
  .body { padding: 40px 44px; }
  .label { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); margin: 0 0 12px; }
  h1 { font-size: 28px; line-height: 1.15; font-weight: 600; letter-spacing: -.01em; margin: 0 0 14px; }
  p { color: var(--muted); margin: 0; max-width: 56ch; }
  .foot {
    border-top: 1px solid var(--border);
    background: color-mix(in oklab, var(--soft) 50%%, transparent);
    padding: 12px 18px;
    display: flex; align-items: center; justify-content: space-between;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10px; letter-spacing: .18em; text-transform: uppercase; color: var(--muted);
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="strip">
        <div class="dots">
          <span class="dot"></span><span class="dot"></span><span class="dot"></span>
          <span class="ping"></span>
          <span class="mono" style="margin-left:8px">edge &middot; response</span>
        </div>
        <span class="mono">status %[1]d</span>
      </div>
      <div class="body">
        <p class="label">// %[3]s</p>
        <h1>%[4]s</h1>
        <p>%[5]s</p>
      </div>
      <div class="foot">
        <span>fig.err &middot; %[1]d</span>
        <span>torii edge</span>
      </div>
    </div>
  </div>
</body>
</html>
`

func wantsJSON(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if accept == "" {
		return false
	}
	if strings.Contains(accept, "text/html") {
		return false
	}
	return strings.Contains(accept, "application/json")
}

func errorCopy(status int) (label, title, blurb string) {
	switch status {
	case http.StatusBadGateway:
		return "upstream unreachable", "This service isn't responding",
			"torii couldn't reach the service behind this domain. It may be offline, restarting, or temporarily misconfigured. Try again in a moment, or contact your administrator if it keeps happening."
	case http.StatusGatewayTimeout:
		return "upstream timeout", "The service took too long to respond",
			"torii reached the service, but it didn't reply in time. Try again in a moment, or contact your administrator if it keeps happening."
	case http.StatusServiceUnavailable:
		return "service unavailable", "The service is temporarily unavailable",
			"The service behind this domain reported that it's temporarily unavailable. Try again in a moment, or contact your administrator if it keeps happening."
	case http.StatusInternalServerError:
		return "upstream error", "Something went wrong on the service side",
			"The service behind this domain returned an internal error. Contact your administrator if this keeps happening."
	case http.StatusRequestEntityTooLarge:
		return "request too large", "Your upload exceeds the size limit",
			"The request body is larger than the maximum size allowed for this service. Contact your administrator if you need the limit raised."
	default:
		return "upstream error", "Something went wrong",
			"The service behind this domain returned an error. Contact your administrator if this keeps happening."
	}
}

func renderUpstreamError(w http.ResponseWriter, r *http.Request, status int) {
	label, title, blurb := errorCopy(status)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   http.StatusText(status),
			"status":  status,
			"message": blurb,
		})
		return
	}

	body := fmt.Sprintf(upstreamErrorPage,
		status,
		html.EscapeString(http.StatusText(status)),
		html.EscapeString(label),
		html.EscapeString(title),
		html.EscapeString(blurb),
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// replaceWithUpstreamError swaps a 5xx response body for the torii error page.
// The original status code is preserved so callers still see the upstream's
// signal. No upstream details are leaked into the rendered body.
func replaceWithUpstreamError(resp *http.Response) error {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	label, title, blurb := errorCopy(resp.StatusCode)
	if wantsJSON(resp.Request) {
		payload, _ := json.Marshal(map[string]any{
			"error":   http.StatusText(resp.StatusCode),
			"status":  resp.StatusCode,
			"message": blurb,
		})
		resp.Body = io.NopCloser(bytes.NewReader(payload))
		resp.ContentLength = int64(len(payload))
		resp.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
		resp.Header.Del("Content-Encoding")
		return nil
	}

	body := fmt.Sprintf(upstreamErrorPage,
		resp.StatusCode,
		html.EscapeString(http.StatusText(resp.StatusCode)),
		html.EscapeString(label),
		html.EscapeString(title),
		html.EscapeString(blurb),
	)
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
	return nil
}
