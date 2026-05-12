// The Go server injects `window.__TORII_URL__` into the served index.html so
// the operator-configured TORII_URL is available at runtime instead of being
// baked in at `nuxt generate` time. We hoist that into runtimeConfig.public so
// every existing call site (middleware, signin, error.vue) reads the right
// value without conditional logic.
//
// Numeric prefix (`0.`) ensures this plugin sorts before others — middleware
// and other plugins (auth bootstrap) need the resolved value.
declare global {
  interface Window {
    __TORII_URL__?: string
  }
}

export default defineNuxtPlugin(() => {
  const injected = window.__TORII_URL__
  if (!injected) return
  const config = useRuntimeConfig()
  config.public.toriiUrl = injected
})
