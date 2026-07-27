// https://nuxt.com/docs/api/configuration/nuxt-config
//
import tailwindcss from "@tailwindcss/vite";

// The Go dispatch only routes /_torii/* to the SPA, so every URL the app emits
// has to carry the prefix. Nuxt applies baseURL to build assets but not to
// hand-written public-asset paths, hence the explicit joins below.
const baseURL = "/_torii/";

export default defineNuxtConfig({
  compatibilityDate: "2025-07-15",
  devtools: { enabled: true },
  css: ["~/assets/css/tailwind.css"],
  ssr: false,

  runtimeConfig: {
    public: {
      toriiUrl: process.env.TORII_URL ?? "",
      toriiVersion: process.env.TORII_VERSION ?? "dev",
      siteUrl: process.env.SITE_URL ?? "https://toriigate.org",
    },
  },

  site: {
    url: process.env.SITE_URL ?? "https://toriigate.org",
    name: "torii",
    description: "Identity-aware reverse proxy with built-in auth and RBAC. Open-source zero trust gateway you self-host as a single Go binary.",
    defaultLocale: "en",
    indexable: true,
  },

  app: {
    baseURL,
    head: {
      htmlAttrs: { lang: "en" },
      meta: [
        { name: "viewport", content: "width=device-width, initial-scale=1, viewport-fit=cover" },
        { name: "theme-color", content: "#c8392c" },
        { name: "format-detection", content: "telephone=no" },
        // Defaults; per-page useSeoMeta() can override.
        { property: "og:image", content: `${(process.env.SITE_URL ?? "https://toriigate.org").replace(/\/$/, "")}/og-image.png` },
        { property: "og:image:width", content: "1200" },
        { property: "og:image:height", content: "630" },
        { property: "og:image:type", content: "image/png" },
        { property: "og:image:alt", content: "torii — identity-aware reverse proxy" },
        { name: "twitter:card", content: "summary_large_image" },
        { name: "twitter:image", content: `${(process.env.SITE_URL ?? "https://toriigate.org").replace(/\/$/, "")}/og-image.png` },
        { name: "twitter:image:alt", content: "torii — identity-aware reverse proxy" },
      ],
      link: [
        { rel: "icon", type: "image/svg+xml", href: `${baseURL}torii-logo.svg` },
        { rel: "alternate icon", type: "image/x-icon", href: `${baseURL}favicon.ico` },
        { rel: "apple-touch-icon", href: `${baseURL}torii-logo.svg` },
      ],
    },
  },

  vite: {
    plugins: [tailwindcss()],
  },

  experimental: {
    viteEnvironmentApi: true,
  },

  modules: ["shadcn-nuxt", "@nuxtjs/color-mode", "@nuxtjs/seo"],

  sitemap: {
    exclude: ["/_torii/dashboard", "/_torii/admin/**", "/_torii/health"],
  },

  robots: {
    disallow: ["/_torii/dashboard", "/_torii/admin/", "/_torii/api/v1/"],
  },

  ogImage: {
    enabled: false,
  },

  schemaOrg: {
    enabled: false,
  },

  linkChecker: {
    enabled: false,
  },

  colorMode: {
    preference: "system",
    fallback: "light",
    classSuffix: "",
    storageKey: "torii-theme",
  },

  shadcn: {
    /**
     * Prefix for all the imported component.
     * @default "Ui"
     */
    prefix: "",
    /**
     * Directory that the component lives in.
     * Will respect the Nuxt aliases.
     * @link https://nuxt.com/docs/api/nuxt-config#alias
     * @default "@/components/ui"
     */
    componentDir: "@/components/ui",
  },
});
