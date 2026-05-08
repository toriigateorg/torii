<script setup lang="ts">
withDefaults(defineProps<{
  title?: string
  description?: string
}>(), {
  title: "torii — identity-aware reverse proxy",
  description: "Auth, RBAC, and routing in one open-source Go binary.",
})
</script>

<template>
  <div
    class="w-full h-full flex flex-col justify-between p-20"
    style="background: #0b0b0d; color: #f5f5f4; font-family: 'Inter', sans-serif;"
  >
    <div class="flex items-center gap-5">
      <svg width="56" height="56" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" fill="#c8392c">
        <path d="M2 8 C14 8, 22 16, 32 16 C42 16, 50 8, 62 8 L62 12 C50 12, 42 20, 32 20 C22 20, 14 12, 2 12 Z" />
        <rect x="10" y="22" width="44" height="2" />
        <rect x="30" y="22" width="4" height="8" />
        <rect x="12" y="30" width="40" height="4" />
        <path d="M14 58 L21 58 L20 24 L15 24 Z" />
        <path d="M43 58 L50 58 L49 24 L44 24 Z" />
      </svg>
      <span style="font-size: 32px; font-weight: 600; letter-spacing: -0.02em;">torii</span>
    </div>

    <div class="flex flex-col gap-6">
      <div
        style="font-family: 'JetBrains Mono', monospace; font-size: 18px; color: #c8392c; letter-spacing: 0.1em; text-transform: uppercase;"
      >
        // identity-aware reverse proxy
      </div>
      <h1
        style="font-size: 76px; font-weight: 600; line-height: 1.05; letter-spacing: -0.03em; margin: 0; max-width: 1000px;"
      >
        {{ title }}
      </h1>
      <p
        style="font-size: 28px; line-height: 1.4; color: #a1a1aa; margin: 0; max-width: 900px;"
      >
        {{ description }}
      </p>
    </div>

    <div class="flex items-center justify-between" style="font-size: 20px; color: #71717a;">
      <span>Open-source zero trust gateway</span>
      <span style="font-family: 'JetBrains Mono', monospace;">toriigate.org</span>
    </div>
  </div>
</template>
