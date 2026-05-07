<script setup lang="ts">
import { ShieldOff } from "lucide-vue-next"
import type { NuxtError } from "#app"

const props = defineProps<{ error: NuxtError }>()

const title = computed(() => {
  if (props.error.statusCode === 401) return "Unauthorized"
  if (props.error.statusCode === 403) return "Forbidden"
  if (props.error.statusCode === 404) return "Not found"
  return "Something went wrong"
})

const detail = computed(() => {
  if (props.error.statusCode === 401) {
    return "You don't have access to this page. Sign in with an admin account, or head back home."
  }
  return props.error.statusMessage || "An unexpected error occurred."
})

function goHome() {
  clearError({ redirect: "/" })
}
</script>

<template>
  <main id="main-content" tabindex="-1" class="min-h-screen bg-background text-foreground flex items-center justify-center px-4 focus:outline-none">
    <div class="max-w-md text-center">
      <div aria-hidden="true" class="inline-flex items-center justify-center size-14 rounded-2xl hairline bg-card mb-6">
        <ShieldOff class="size-6 text-primary" />
      </div>
      <p class="font-mono text-[11px] tracking-[0.2em] uppercase text-muted-foreground mb-3">
        error / {{ error.statusCode }}
      </p>
      <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight mb-4">
        {{ title }}
      </h1>
      <p class="text-muted-foreground leading-relaxed mb-8">
        {{ detail }}
      </p>
      <Button class="h-10 px-5" @click="goHome">Go home</Button>
    </div>
  </main>
</template>
