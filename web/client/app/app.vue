<script setup lang="ts">
useSeoMeta({
  titleTemplate: "%s",
  ogSiteName: "torii",
  ogType: "website",
  ogLocale: "en_US",
  twitterCard: "summary_large_image",
})
</script>

<template>
  <NuxtLayout>
    <NuxtRouteAnnouncer />
    <NuxtPage />
  </NuxtLayout>
</template>
