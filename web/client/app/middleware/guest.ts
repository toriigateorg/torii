export default defineNuxtRouteMiddleware((to) => {
  const { isAuthed } = useAuth()
  if (!isAuthed.value) return

  // On a service domain the SPA only ever serves /signin and /signup (see
  // domain-gate.global). Bouncing an already-authed visitor to /dashboard
  // would trip that gate; hard-load the ?to= target (or "/") so the Go
  // dispatch re-evaluates and proxies the user through to the upstream.
  if (import.meta.client) {
    const expected = useToriiUrl()
    if (expected && window.location.host !== expected) {
      const raw = to.query.to
      const target = typeof raw === "string" && raw.startsWith("/") ? raw : "/"
      window.location.assign(target)
      return abortNavigation()
    }
  }

  return navigateTo("/dashboard")
})
