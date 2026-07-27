// Client-side mirror of safeRelativeRedirect in internal/api/auth.go.
//
// ?to= is attacker-controlled: it reaches the SPA from any link, and on a
// service host the signin flow hard-navigates to it. A bare startsWith("/")
// check is not enough — "//evil.com" is protocol-relative, and browsers
// normalize the backslash in "/\evil.com" to a second slash — so both leave
// the origin while looking relative. Keep this in step with the Go version.
export function safeRelativePath(raw: unknown, fallback = "/"): string {
  if (typeof raw !== "string" || raw === "") return fallback
  // Backslashes and control characters (CR/LF included) are rejected outright
  // rather than stripped: any appearance of them here is not a real path.
  if (raw.includes("\\") || /[\x00-\x1f\x7f]/.test(raw)) return fallback
  if (!raw.startsWith("/") || raw.startsWith("//")) return fallback
  // A relative URL parsed against an opaque base keeps that base's origin;
  // anything carrying its own scheme or host does not.
  try {
    const u = new URL(raw, "http://invalid.invalid")
    if (u.host !== "invalid.invalid") return fallback
    return u.pathname + u.search + u.hash
  } catch {
    return fallback
  }
}
