<script setup lang="ts">
const site = useSiteConfig()

useSeoMeta({
  titleTemplate: "%s",
  ogSiteName: "torii",
  ogType: "website",
  ogLocale: "en_US",
  twitterCard: "summary_large_image",
  themeColor: "#c8392c",
})

useSchemaOrg([
  defineOrganization({
    name: "torii",
    url: site.url,
    logo: `${site.url}/torii-logo.svg`,
    description: "Open-source identity-aware reverse proxy with built-in auth and RBAC.",
    sameAs: ["https://github.com/ameyashenoy/torii"],
  }),
  defineWebSite({
    name: "torii",
    description: site.description,
  }),
])

defineOgImageComponent("ToriiOg")
</script>

<template>
  <NuxtLayout>
    <NuxtRouteAnnouncer />
    <NuxtPage />
  </NuxtLayout>
</template>
