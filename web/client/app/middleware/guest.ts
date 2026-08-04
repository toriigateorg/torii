export default defineNuxtRouteMiddleware((to) => {
  const { isAuthed } = useAuth()
  if (!isAuthed.value) return

  // On a service domain the SPA only ever serves /handoff and /forbidden (see
  // domain-gate.global). Bouncing an already-authed visitor to /dashboard
  // would trip that gate; hard-load the ?to= target (or "/") so the Go
  // dispatch re-evaluates and proxies the user through to the upstream.
  if (import.meta.client) {
    const expected = useToriiUrl()
    if (expected && window.location.host !== expected) {
      window.location.assign(safeRelativePath(to.query.to))
      return abortNavigation()
    }
  }

  return navigateTo("/dashboard")
})
