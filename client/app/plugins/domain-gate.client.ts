// Runs after auth.client.ts (alphabetical order). Decides what the SPA should
// do when it's loaded on a host that isn't SANMON_URL: either prompt signin
// (so the user gets a sanmon cookie scoped to this host, after which Go will
// reverse-proxy on the next request) or render a 4xx because no service is
// configured for this domain.
export default defineNuxtPlugin(() => {
  const cfg = useRuntimeConfig()
  const expected = cfg.public.sanmonUrl
  const here = window.location.host
  if (!expected || here === expected) return

  const { isAuthed } = useAuth()
  const router = useRouter()

  function applyGate() {
    if (isAuthed.value) {
      throw createError({
        statusCode: 404,
        statusMessage: "No service configured for this domain",
        fatal: true,
      })
    }
    const path = router.currentRoute.value.fullPath
    if (path !== "/signin" && path !== "/signup") {
      void navigateTo("/signin", { replace: true })
    }
  }

  applyGate()
})
