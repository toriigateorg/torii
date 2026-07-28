// Runs on every client-side navigation. When the SPA is loaded on a host
// that isn't TORII_URL (i.e. some service domain or an unknown one), users
// must not be able to browse arbitrary torii pages — they should only see
// the cross-host auth pages. Once authenticated on this host we know the
// dispatch already decided no service is bound here, so anything other than
// those pages becomes a 404.

// Pages the Go dispatch and the SSO callback legitimately land on when the
// SPA is running on a service domain. /handoff is where the post-SSO redirect
// arrives (unauthenticated — the token it carries is what mints the session),
// and /forbidden is where dispatch sends an authenticated user whose roles
// don't grant the service.
const crossHostPages = new Set(["/signin", "/signup", "/handoff", "/forbidden"])

export default defineNuxtRouteMiddleware((to) => {
  if (import.meta.server) return

  const expected = useToriiUrl()
  const here = window.location.host
  if (!expected || here === expected) return

  // Vue Router strips app.baseURL from to.path, so the comparison is against
  // the unprefixed route names even though the browser URL is /_torii/signin.
  // Normalize: strip baseURL if present (defensive against early-hydration
  // edge cases), drop trailing slashes, then match.
  const stripped = to.path.replace(/^\/_torii/, "") || "/"
  const normalized = stripped.replace(/\/+$/, "") || "/"
  if (crossHostPages.has(normalized)) return

  const { isAuthed } = useAuth()

  if (isAuthed.value) {
    throw createError({
      statusCode: 404,
      statusMessage: "No service configured for this domain",
      fatal: true,
    })
  }

  return navigateTo("/signin", { replace: true })
})
