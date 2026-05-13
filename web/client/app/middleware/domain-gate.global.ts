// Runs on every client-side navigation. When the SPA is loaded on a host
// that isn't TORII_URL (i.e. some service domain or an unknown one), users
// must not be able to browse arbitrary torii pages — they should only see
// /signin or /signup. Once authenticated on this host we know the dispatch
// already decided no service is bound here, so anything other than the auth
// pages becomes a 404.
export default defineNuxtRouteMiddleware((to) => {
  if (import.meta.server) return

  const expected = useToriiUrl()
  const here = window.location.host
  if (!expected || here === expected) return

  const { isAuthed } = useAuth()

  if (isAuthed.value) {
    throw createError({
      statusCode: 404,
      statusMessage: "No service configured for this domain",
      fatal: true,
    })
  }

  // Vue Router strips app.baseURL from to.path, so the comparison is against
  // the unprefixed route names even though the browser URL is /_torii/signin.
  if (to.path !== "/signin" && to.path !== "/signup") {
    return navigateTo("/signin", { replace: true })
  }
})
