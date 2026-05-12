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

export function useToriiUrl(): string {
  if (import.meta.client && window.__TORII_URL__) {
    return window.__TORII_URL__
  }
  return useRuntimeConfig().public.toriiUrl as string
}
