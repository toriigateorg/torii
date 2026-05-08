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
      sanmonUrl: process.env.SANMON_URL ?? "",
    },
  },

  app: {
    head: {
      htmlAttrs: { lang: "en" },
      meta: [
        { name: "viewport", content: "width=device-width, initial-scale=1, viewport-fit=cover" },
      ],
      link: [
        { rel: "icon", type: "image/svg+xml", href: "/sanmon-logo.svg" },
        { rel: "alternate icon", type: "image/x-icon", href: "/favicon.ico" },
        { rel: "apple-touch-icon", href: "/sanmon-logo.svg" },
      ],
    },
  },

  vite: {
    plugins: [tailwindcss()],
  },

  experimental: {
    viteEnvironmentApi: true,
  },

  modules: ["shadcn-nuxt", "@nuxtjs/color-mode"],

  colorMode: {
    preference: "system",
    fallback: "light",
    classSuffix: "",
    storageKey: "sanmon-theme",
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
