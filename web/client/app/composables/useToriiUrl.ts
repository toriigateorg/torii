// Resolve the operator-configured TORII_URL at runtime.
//
// In prod the Go server injects `window.__TORII_URL__` into every served
// HTML document (see internal/web/web.go) so the value can change per deploy
// without rebuilding the SPA. In dev the Nuxt dev server reads it from
// nuxt.config.ts > runtimeConfig.public.toriiUrl, which is sourced from the
// TORII_URL env var at boot. Always prefer the runtime injection when present.
declare global {
  interface Window {
    __TORII_URL__?: string
  }
}

// Snapshotted at module evaluation, before any application code — and therefore
// before any injected upstream script — has run. window.__TORII_URL__ is a plain
// writable global, so reading it lazily let same-origin script on a proxied host
// rewrite it to that host's own name and make the domain gate conclude it was
// already on the control plane. The snapshot is not a real defence against
// same-origin script (nothing in the page is), but it removes the trivial
// one-line bypass of a control that exists precisely to keep torii's credential
// form off an upstream's origin.
const injected = import.meta.client ? window.__TORII_URL__ : undefined

export function useToriiUrl(): string {
  if (injected) {
    return injected
  }
  return useRuntimeConfig().public.toriiUrl as string
}
