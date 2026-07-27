// Resolve a file from client/public/ to a URL the Go dispatch will actually
// serve. The SPA lives under app.baseURL (/_torii/) and dispatch routes only
// /_torii/* to it: a root-absolute "/torii-logo.svg" redirects to the SPA shell
// on the torii host, and proxies to the upstream on a service host. Nuxt
// rewrites build assets with baseURL but leaves hand-written paths alone.
export function publicAsset(path: string): string {
  const base = useRuntimeConfig().app.baseURL || "/"
  return base.replace(/\/$/, "") + "/" + path.replace(/^\//, "")
}
