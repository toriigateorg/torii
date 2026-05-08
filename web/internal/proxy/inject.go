package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// toriiOverlay is a self-contained HTML snippet injected before </body> on
// every proxied HTML response. It mounts a draggable circular button in a
// closed shadow root that opens a small dropdown with a sign-out action.
const toriiOverlay = `<div id="__torii_overlay" data-torii></div>
<script>(function(){
  if (window.__toriiOverlayMounted) return;
  window.__toriiOverlayMounted = true;
  var mount = document.getElementById('__torii_overlay');
  if (!mount || !mount.attachShadow) return;
  var root = mount.attachShadow({mode:'closed'});
  root.innerHTML = [
    '<style>',
    ':host{all:initial;}',
    '*{box-sizing:border-box;font:500 12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color-scheme:light dark;}',
    '.btn{position:fixed;width:40px;height:40px;border-radius:9999px;border:0;padding:0;background:transparent;display:inline-flex;align-items:center;justify-content:center;cursor:grab;touch-action:none;user-select:none;-webkit-user-select:none;filter:drop-shadow(0 6px 16px rgba(0,0,0,.45)) drop-shadow(0 2px 4px rgba(0,0,0,.25));transition:transform .15s ease,filter .15s ease;z-index:2147483647;}',
    '.btn:hover{transform:scale(1.06);filter:drop-shadow(0 8px 22px rgba(0,0,0,.55)) drop-shadow(0 2px 4px rgba(0,0,0,.3));}',
    '.btn:focus-visible{outline:2px solid #7aa2ff;outline-offset:3px;border-radius:9999px;}',
    '.btn.dragging{cursor:grabbing;transform:scale(1.06);transition:none;}',
    '.btn .logo{width:40px;height:40px;display:block;border-radius:9999px;}',
    '.btn .ind{position:absolute;top:1px;right:1px;width:8px;height:8px;border-radius:9999px;background:#34d399;box-shadow:0 0 6px rgba(52,211,153,.7),0 0 0 2px rgba(20,20,24,.92);}',
    '.menu{position:fixed;min-width:208px;border-radius:10px;border:1px solid rgba(120,120,140,.35);background:rgba(20,20,24,.94);color:#f5f5f7;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);padding:6px;box-shadow:0 12px 40px -8px rgba(0,0,0,.55),0 4px 12px -2px rgba(0,0,0,.3);z-index:2147483647;display:none;animation:fade .12s ease-out;}',
    '.menu .label{padding:8px 10px 4px;letter-spacing:.18em;text-transform:uppercase;font-size:9.5px;color:rgba(245,245,247,.5);}',
    '.menu .item{display:flex;align-items:center;gap:10px;width:100%;padding:9px 10px;border:0;background:transparent;color:inherit;border-radius:6px;cursor:pointer;font:500 12.5px/1 ui-monospace,SFMono-Regular,Menlo,monospace;text-align:left;transition:background .12s ease;}',
    '.menu .item:hover,.menu .item:focus-visible{background:rgba(255,255,255,.08);outline:none;}',
    '.menu .item[disabled]{opacity:.6;cursor:wait;}',
    '.menu .item .icon{width:14px;height:14px;flex:none;}',
    '.menu .sep{height:1px;background:rgba(255,255,255,.08);margin:4px 2px;}',
    '@keyframes fade{from{opacity:0;transform:translateY(2px);}to{opacity:1;transform:translateY(0);}}',
    '@media (prefers-color-scheme: light){.btn{background:rgba(255,255,255,.88);color:#111;border-color:rgba(0,0,0,.12);box-shadow:0 6px 24px -6px rgba(0,0,0,.18),0 2px 6px -1px rgba(0,0,0,.08);} .btn:hover{background:rgba(255,255,255,.96);border-color:rgba(0,0,0,.22);} .menu{background:rgba(255,255,255,.96);color:#111;border-color:rgba(0,0,0,.12);box-shadow:0 12px 40px -8px rgba(0,0,0,.18),0 4px 12px -2px rgba(0,0,0,.08);} .menu .label{color:rgba(0,0,0,.5);} .menu .item:hover,.menu .item:focus-visible{background:rgba(0,0,0,.06);} .menu .sep{background:rgba(0,0,0,.08);}}',
    '</style>',
    '<button class="btn" type="button" aria-label="Open torii menu" aria-haspopup="menu" aria-expanded="false">',
      '<svg class="logo" viewBox="0 0 680 680" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">',
        '<defs><clipPath id="sm_clip"><circle cx="340" cy="340" r="300"/></clipPath></defs>',
        '<circle cx="340" cy="340" r="300" fill="#f5e9d3"/>',
        '<g clip-path="url(#sm_clip)" fill="#1a1a1a">',
          '<circle cx="340" cy="320" r="90" fill="#c8392c"/>',
          '<rect x="40" y="560" width="600" height="6"/>',
          '<rect x="180" y="340" width="38" height="220"/>',
          '<rect x="462" y="340" width="38" height="220"/>',
          '<rect x="168" y="554" width="62" height="14"/>',
          '<rect x="450" y="554" width="62" height="14"/>',
          '<rect x="150" y="430" width="380" height="16"/>',
          '<rect x="130" y="335" width="420" height="22"/>',
          '<rect x="160" y="318" width="20" height="20"/>',
          '<rect x="220" y="318" width="20" height="20"/>',
          '<rect x="280" y="318" width="20" height="20"/>',
          '<rect x="340" y="318" width="20" height="20"/>',
          '<rect x="400" y="318" width="20" height="20"/>',
          '<rect x="460" y="318" width="20" height="20"/>',
          '<rect x="500" y="318" width="20" height="20"/>',
          '<path d="M 90 318 Q 90 290 130 285 L 550 285 Q 590 290 590 318 Q 540 305 340 305 Q 140 305 90 318 Z"/>',
          '<rect x="240" y="240" width="18" height="18"/>',
          '<rect x="290" y="240" width="18" height="18"/>',
          '<rect x="340" y="240" width="18" height="18"/>',
          '<rect x="390" y="240" width="18" height="18"/>',
          '<rect x="422" y="240" width="18" height="18"/>',
          '<rect x="220" y="258" width="240" height="14"/>',
          '<path d="M 180 240 Q 180 215 220 210 L 460 210 Q 500 215 500 240 Q 460 228 340 228 Q 220 228 180 240 Z"/>',
          '<rect x="320" y="180" width="40" height="32"/>',
          '<rect x="328" y="160" width="24" height="22"/>',
          '<circle cx="340" cy="155" r="8"/>',
        '</g>',
        '<circle cx="340" cy="340" r="300" fill="none" stroke="#1a1a1a" stroke-width="6"/>',
      '</svg>',
      '<span class="ind" aria-hidden="true"></span>',
    '</button>',
    '<div class="menu" role="menu" aria-label="torii">',
      '<div class="label">// torii</div>',
      '<button class="item" type="button" role="menuitem" data-action="signout">',
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>',
        '<span>Sign out</span>',
      '</button>',
    '</div>'
  ].join('');

  var btn = root.querySelector('.btn');
  var menu = root.querySelector('.menu');
  var signoutItem = root.querySelector('[data-action="signout"]');

  var STORAGE_KEY = 'torii:overlay:pos';
  var DRAG_THRESHOLD = 16; // squared px (4px movement)
  var pos = loadPos();
  applyPos();

  var drag = null;
  btn.addEventListener('pointerdown', function(e){
    if (e.button !== undefined && e.button !== 0) return;
    e.preventDefault();
    btn.setPointerCapture(e.pointerId);
    drag = { id:e.pointerId, sx:e.clientX, sy:e.clientY, ox:pos.left, oy:pos.top, moved:false };
  });
  btn.addEventListener('pointermove', function(e){
    if (!drag || e.pointerId !== drag.id) return;
    var dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (!drag.moved && (dx*dx + dy*dy) > DRAG_THRESHOLD) {
      drag.moved = true;
      btn.classList.add('dragging');
      hideMenu();
    }
    if (drag.moved) {
      pos.left = clamp(drag.ox + dx, 4, window.innerWidth - btn.offsetWidth - 4);
      pos.top = clamp(drag.oy + dy, 4, window.innerHeight - btn.offsetHeight - 4);
      applyPos();
    }
  });
  function endDrag(e){
    if (!drag || (e && e.pointerId !== drag.id)) return;
    var moved = drag.moved;
    try { btn.releasePointerCapture(drag.id); } catch (_) {}
    btn.classList.remove('dragging');
    drag = null;
    if (moved) savePos(); else toggleMenu();
  }
  btn.addEventListener('pointerup', endDrag);
  btn.addEventListener('pointercancel', endDrag);

  function showMenu(){
    menu.style.display = 'block';
    btn.setAttribute('aria-expanded','true');
    positionMenu();
    document.addEventListener('pointerdown', onOutside, true);
    window.addEventListener('keydown', onKey);
  }
  function hideMenu(){
    if (menu.style.display !== 'block') return;
    menu.style.display = 'none';
    btn.setAttribute('aria-expanded','false');
    document.removeEventListener('pointerdown', onOutside, true);
    window.removeEventListener('keydown', onKey);
  }
  function toggleMenu(){ if (menu.style.display === 'block') hideMenu(); else showMenu(); }
  function onOutside(e){
    var path = e.composedPath ? e.composedPath() : [];
    if (path.indexOf(mount) === -1) hideMenu();
  }
  function onKey(e){ if (e.key === 'Escape') { hideMenu(); btn.focus(); } }

  function positionMenu(){
    var bw = btn.offsetWidth, bh = btn.offsetHeight;
    var mw = menu.offsetWidth, mh = menu.offsetHeight;
    var openUp = pos.top + bh + 8 + mh > window.innerHeight - 4;
    var alignRight = pos.left + mw > window.innerWidth - 4;
    var left = alignRight ? pos.left + bw - mw : pos.left;
    var top = openUp ? pos.top - mh - 8 : pos.top + bh + 8;
    menu.style.left = clamp(left, 4, window.innerWidth - mw - 4) + 'px';
    menu.style.top  = clamp(top, 4, window.innerHeight - mh - 4) + 'px';
  }

  signoutItem.addEventListener('click', function(){
    signoutItem.disabled = true;
    hideMenu();
    fetch('/api/v1/logout', { method:'POST', credentials:'include', cache:'no-store' })
      .catch(function(){})
      .finally(function(){
        window.location.replace('/?torii_logout=' + Date.now());
      });
  });

  window.addEventListener('resize', function(){
    pos.left = clamp(pos.left, 4, window.innerWidth - btn.offsetWidth - 4);
    pos.top = clamp(pos.top, 4, window.innerHeight - btn.offsetHeight - 4);
    applyPos();
    if (menu.style.display === 'block') positionMenu();
  });

  function clamp(v, lo, hi){ return Math.max(lo, Math.min(hi, v)); }
  function applyPos(){
    btn.style.left = pos.left + 'px';
    btn.style.top  = pos.top + 'px';
  }
  function defaultPos(){
    return { left: Math.max(4, window.innerWidth - 56), top: Math.max(4, window.innerHeight - 56) };
  }
  function loadPos(){
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        var p = JSON.parse(raw);
        if (p && typeof p.left === 'number' && typeof p.top === 'number') {
          return { left: clamp(p.left, 4, window.innerWidth - 44), top: clamp(p.top, 4, window.innerHeight - 44) };
        }
      }
    } catch (_) {}
    return defaultPos();
  }
  function savePos(){
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(pos)); } catch (_) {}
  }
})();</script>`

var toriiOverlayBytes = []byte(toriiOverlay)
var bodyCloseTag = []byte("</body>")

// injectOverlay rewrites an HTML response to splice the torii overlay in
// just before </body>. No-op for non-HTML, encoded, or partial responses.
func injectOverlay(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil
	}
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
		out = make([]byte, 0, len(body)+len(toriiOverlayBytes))
		out = append(out, body[:idx]...)
		out = append(out, toriiOverlayBytes...)
		out = append(out, body[idx:]...)
	} else {
		out = body
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}
