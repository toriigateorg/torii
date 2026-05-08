<script setup lang="ts">
import { ArrowUpRight, Globe, Inbox } from "lucide-vue-next"

definePageMeta({ middleware: "auth" })
useHead({ title: "Dashboard — sanmon" })

type Service = {
  id: string
  title: string
  description: string
  domain: string
  service_url: string
}

const { authHeaders } = useAuth()
const services = ref<Service[]>([])
const loading = ref(true)
const errorMsg = ref<string | null>(null)

async function loadServices() {
  loading.value = true
  errorMsg.value = null
  try {
    const res = await $fetch<{ items: Service[] }>("/api/v1/me/services", {
      credentials: "include",
      headers: authHeaders(),
    })
    services.value = res.items ?? []
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    errorMsg.value = e?.data?.error ?? e?.message ?? "Failed to load services"
  } finally {
    loading.value = false
  }
}

onMounted(loadServices)

function urlForDomain(domain: string): string {
  return `${window.location.protocol}//${domain}/`
}
</script>

<template>
  <div class="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-16 sm:py-24">
    <div class="mb-10">
      <p class="text-mono-label mb-3">// dashboard</p>
      <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight">Your services</h1>
      <p class="mt-3 text-muted-foreground max-w-xl leading-relaxed">
        Everything you have access to, in one place.
      </p>
    </div>

    <div v-if="loading" class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <div v-for="i in 3" :key="i" class="hairline rounded-lg p-5 bg-card animate-pulse h-36" />
    </div>

    <div
      v-else-if="errorMsg"
      class="hairline rounded-lg p-5 bg-card text-sm text-destructive"
      role="alert"
    >
      {{ errorMsg }}
    </div>

    <div
      v-else-if="services.length === 0"
      class="hairline rounded-xl p-10 sm:p-14 bg-card/40 text-center"
    >
      <div
        aria-hidden="true"
        class="inline-flex items-center justify-center size-12 hairline rounded-lg bg-background mb-5"
      >
        <Inbox class="size-5 text-muted-foreground" />
      </div>
      <p class="text-mono-label mb-3">// nothing here yet</p>
      <h2 class="text-xl font-semibold tracking-tight mb-2">No services available</h2>
      <p class="text-sm text-muted-foreground max-w-md mx-auto leading-relaxed">
        You don't have access to any services. Ask an administrator to grant your role access.
      </p>
    </div>

    <ul v-else class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <li v-for="s in services" :key="s.id">
        <a
          :href="urlForDomain(s.domain)"
          class="group block hairline rounded-lg p-5 bg-card hover:bg-accent/40 transition-colors h-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div class="flex items-start justify-between mb-4">
            <div
              aria-hidden="true"
              class="inline-flex items-center justify-center size-9 hairline rounded-md bg-background"
            >
              <Globe class="size-4 text-primary" />
            </div>
            <ArrowUpRight
              class="size-4 text-muted-foreground group-hover:text-primary group-hover:-translate-y-0.5 group-hover:translate-x-0.5 transition-all"
              aria-hidden="true"
            />
          </div>
          <h2 class="text-base font-semibold tracking-tight mb-1.5 line-clamp-1">
            {{ s.title }}
          </h2>
          <p
            v-if="s.description"
            class="text-sm text-muted-foreground leading-relaxed line-clamp-2 mb-4"
          >
            {{ s.description }}
          </p>
          <p class="font-mono text-[11px] text-muted-foreground/80 truncate">{{ s.domain }}</p>
        </a>
      </li>
    </ul>
  </div>
</template>
