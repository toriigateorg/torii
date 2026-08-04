// Runs on every client-side navigation. When the SPA is loaded on a host
// that isn't TORII_URL (i.e. some service domain or an unknown one), users
// must not be able to browse arbitrary torii pages — they should only see
// the cross-host auth pages. Once authenticated on this host we know the
// dispatch already decided no service is bound here, so anything other than
// those pages becomes a 404.

// Pages the Go dispatch and the cross-host return leg legitimately land on when
// the SPA is running on a service domain. /handoff is where that leg arrives
// (unauthenticated — the token it carries is what mints the session), and
// /forbidden is where dispatch sends an authenticated user whose roles don't
// grant the service.
//
// /signin and /signup are deliberately absent, and must stay absent. Rendering
// them here put torii's password form on the upstream application's origin,
// same-origin with whatever script that upstream runs — and a captured password
// has no host binding, so it replays on the control plane and on every other
// service. Credential collection belongs to TORII_URL; dispatch redirects there
// and the session comes back through /handoff. The server enforces this too (see
// cmd/serve.go toriiPathAllowedOffHost); this is the client half.
const crossHostPages = new Set(["/handoff", "/forbidden"])

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

  // Leave this origin entirely. navigateTo("/signin") would render the sign-in
  // form right here, which is the thing this gate exists to prevent.
  const scheme = window.location.protocol === "https:" ? "https" : "http"
  window.location.replace(`${scheme}://${expected}/_torii/signin`)

  // location.replace only schedules the navigation; without aborting, the router
  // completes this one first and paints the denied page — torii's genuine
  // sign-in form, rendered on the upstream's origin — for however long the real
  // navigation takes.
  return abortNavigation()
})
