// Resolve the build-time torii version. Baked into the SPA at `bun run
// generate` time via process.env.TORII_VERSION (see nuxt.config.ts and the
// client stage of web/Dockerfile). Falls back to "dev" for local dev builds.
export function useToriiVersion(): string {
  return useRuntimeConfig().public.toriiVersion as string
}
