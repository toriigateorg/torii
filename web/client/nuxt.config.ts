// https://nuxt.com/docs/api/configuration/nuxt-config
//
import tailwindcss from "@tailwindcss/vite";

export default defineNuxtConfig({
  compatibilityDate: "2025-07-15",
  devtools: { enabled: true },
  css: ["~/assets/css/tailwind.css"],
  ssr: false,

  runtimeConfig: {
    public: {
      toriiUrl: process.env.TORII_URL ?? "",
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
    head: {
      htmlAttrs: { lang: "en" },
      meta: [
        { name: "viewport", content: "width=device-width, initial-scale=1, viewport-fit=cover" },
        { name: "theme-color", content: "#c8392c" },
        { name: "format-detection", content: "telephone=no" },
      ],
      link: [
        { rel: "icon", type: "image/svg+xml", href: "/torii-logo.svg" },
        { rel: "alternate icon", type: "image/x-icon", href: "/favicon.ico" },
        { rel: "apple-touch-icon", href: "/torii-logo.svg" },
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
    exclude: ["/dashboard", "/admin/**", "/health"],
  },

  robots: {
    disallow: ["/dashboard", "/admin/", "/api/"],
  },

  schemaOrg: {
    identity: "Organization",
  },

  ogImage: {
    defaults: {
      width: 1200,
      height: 630,
    },
  },

  nitro: {
    prerender: {
      crawlLinks: false,
      routes: ["/", "/signin", "/signup", "/sitemap.xml", "/robots.txt"],
    },
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
