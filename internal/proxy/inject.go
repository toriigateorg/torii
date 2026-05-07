package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// sanmonOverlay is a self-contained HTML snippet injected before </body> on
// every proxied HTML response. It renders a floating sign-out pill in a
// shadow root so the upstream's stylesheet can never bleed in.
const sanmonOverlay = `<div id="__sanmon_overlay" data-sanmon></div>
<script>(function(){
  if (window.__sanmonOverlayMounted) return;
  window.__sanmonOverlayMounted = true;
  var host = document.getElementById('__sanmon_overlay');
  if (!host || !host.attachShadow) return;
  var root = host.attachShadow({mode:'closed'});
  root.innerHTML = [
    '<style>',
    ':host{all:initial;}',
    '.wrap{position:fixed;right:16px;bottom:16px;z-index:2147483647;font:500 12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color-scheme:light dark;}',
    '.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 13px 9px 11px;border-radius:9999px;border:1px solid rgba(120,120,140,.35);background:rgba(20,20,24,.78);color:#f5f5f7;cursor:pointer;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);box-shadow:0 6px 24px -6px rgba(0,0,0,.45),0 2px 6px -1px rgba(0,0,0,.25);transition:transform .15s ease,background .15s ease,border-color .15s ease;}',
    '.btn:hover{background:rgba(28,28,32,.92);border-color:rgba(160,160,180,.55);transform:translateY(-1px);}',
    '.btn:focus-visible{outline:2px solid #7aa2ff;outline-offset:2px;}',
    '.btn:active{transform:translateY(0);}',
    '.btn[disabled]{opacity:.6;cursor:wait;}',
    '.dot{width:6px;height:6px;border-radius:9999px;background:#34d399;box-shadow:0 0 6px rgba(52,211,153,.7);}',
    '.lbl{letter-spacing:.08em;text-transform:uppercase;font-size:10.5px;}',
    '.sep{width:1px;height:12px;background:rgba(255,255,255,.18);}',
    '.icon{width:13px;height:13px;}',
    '@media (prefers-color-scheme: light){.btn{background:rgba(255,255,255,.85);color:#111;border-color:rgba(0,0,0,.12);box-shadow:0 6px 24px -6px rgba(0,0,0,.18),0 2px 6px -1px rgba(0,0,0,.08);} .btn:hover{background:rgba(255,255,255,.95);border-color:rgba(0,0,0,.2);} .sep{background:rgba(0,0,0,.12);}}',
    '</style>',
    '<div class="wrap" role="region" aria-label="sanmon session">',
      '<button class="btn" type="button" aria-label="Sign out of sanmon">',
        '<span class="dot" aria-hidden="true"></span>',
        '<span class="lbl">sanmon</span>',
        '<span class="sep" aria-hidden="true"></span>',
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>',
        '<span>Sign out</span>',
      '</button>',
    '</div>'
  ].join('');
  var btn = root.querySelector('button');
  btn.addEventListener('click', function(){
    btn.disabled = true;
    fetch('/api/v1/logout', { method:'POST', credentials:'include', cache:'no-store' })
      .catch(function(){})
      .finally(function(){
        // Replace + cache-buster so the browser cannot serve the upstream's
        // cached HTML for "/" — we want the proxy dispatch to re-evaluate
        // with the now-cleared cookies and bounce us into the sanmon SPA.
        window.location.replace('/?sanmon_logout=' + Date.now());
      });
  });
})();</script>`

var sanmonOverlayBytes = []byte(sanmonOverlay)
var bodyCloseTag = []byte("</body>")

// injectOverlay rewrites an HTML response to splice the sanmon overlay in
// just before </body>. No-op for non-HTML, encoded, or partial responses.
func injectOverlay(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil
	}
	// Skip pre-compressed payloads — we'd have to decode them to inject.
	// Director strips Accept-Encoding to make this rare.
	if resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	idx := bytes.LastIndex(body, bodyCloseTag)
	var out []byte
	if idx >= 0 {
		out = make([]byte, 0, len(body)+len(sanmonOverlayBytes))
		out = append(out, body[:idx]...)
		out = append(out, sanmonOverlayBytes...)
		out = append(out, body[idx:]...)
	} else {
		// Probably an HTML fragment / XHR partial — leave it alone.
		out = body
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}
