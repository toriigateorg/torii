<script setup lang="ts">
import { RefreshCw, CheckCircle2, XCircle, AlertTriangle } from "lucide-vue-next"

useSeoMeta({ title: "torii — health", robots: "noindex, nofollow" })

type HealthResponse = { all: boolean; db: boolean; api: boolean }

const data = ref<HealthResponse | null>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const lastChecked = ref<Date | null>(null)

async function check() {
  loading.value = true
  error.value = null
  try {
    data.value = await $fetch<HealthResponse>("/_torii/api/v1/ht/")
    lastChecked.value = new Date()
  } catch (e: any) {
    error.value = e?.message ?? "request failed"
    data.value = null
  } finally {
    loading.value = false
  }
}

onMounted(check)

const overall = computed(() => {
  if (loading.value && !data.value) return { tone: "muted", label: "checking" }
  if (error.value) return { tone: "destructive", label: "unreachable" }
  if (!data.value) return { tone: "muted", label: "unknown" }
  return data.value.all
    ? { tone: "ok", label: "all systems operational" }
    : { tone: "warn", label: "degraded" }
})

const checks = computed(() => {
  if (!data.value) return []
  return [
    { key: "api", label: "API", desc: "echo http server", value: data.value.api },
    { key: "db", label: "Database", desc: "postgres ping", value: data.value.db },
    { key: "all", label: "Overall", desc: "aggregate state", value: data.value.all },
  ]
})

function timeAgo(d: Date | null) {
  if (!d) return "—"
  return d.toLocaleTimeString()
}
</script>

<template>
  <div class="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8 py-16 sm:py-24">
    <p class="text-mono-label mb-4">// /_torii/api/v1/ht/</p>
    <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight">System health</h1>
    <p class="mt-3 text-muted-foreground">
      Live state of the torii control plane and its dependencies.
    </p>

    <!-- Overall status -->
    <section
      class="mt-10 hairline rounded-xl p-6 sm:p-7 bg-card relative overflow-hidden"
      aria-labelledby="overall-status-label"
      :aria-busy="loading"
    >
      <h2 id="overall-status-label" class="sr-only">Overall status</h2>
      <div
        aria-hidden="true"
        class="absolute -top-16 -right-16 size-48 rounded-full blur-3xl pointer-events-none"
        :class="{
          'bg-emerald-500/20': overall.tone === 'ok',
          'bg-amber-500/20': overall.tone === 'warn',
          'bg-destructive/20': overall.tone === 'destructive',
          'bg-muted/40': overall.tone === 'muted',
        }"
      />
      <div class="relative flex items-start sm:items-center justify-between flex-col sm:flex-row gap-4">
        <div class="flex items-center gap-4">
          <div
            aria-hidden="true"
            class="size-11 rounded-full flex items-center justify-center hairline"
            :class="{
              'bg-emerald-500/10 text-emerald-500': overall.tone === 'ok',
              'bg-amber-500/10 text-amber-500': overall.tone === 'warn',
              'bg-destructive/10 text-destructive': overall.tone === 'destructive',
              'bg-muted text-muted-foreground': overall.tone === 'muted',
            }"
          >
            <CheckCircle2 v-if="overall.tone === 'ok'" class="size-5" />
            <AlertTriangle v-else-if="overall.tone === 'warn'" class="size-5" />
            <XCircle v-else-if="overall.tone === 'destructive'" class="size-5" />
            <RefreshCw v-else class="size-5 animate-spin" />
          </div>
          <div>
            <div
              class="text-lg font-semibold tracking-tight capitalize"
              role="status"
              aria-live="polite"
              aria-atomic="true"
            >{{ overall.label }}</div>
            <div class="text-mono-label mt-1">last check &middot; {{ timeAgo(lastChecked) }}</div>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          class="hairline gap-2"
          :disabled="loading"
          :aria-busy="loading"
          @click="check"
        >
          <RefreshCw class="size-3.5" aria-hidden="true" :class="{ 'animate-spin': loading }" />
          Re-check
        </Button>
      </div>
    </section>

    <!-- Checks -->
    <div class="mt-6 hairline rounded-xl bg-card overflow-hidden">
      <div class="px-5 py-3 border-b border-border/60 bg-muted/30 flex items-center justify-between">
        <span class="text-mono-label">component</span>
        <span class="text-mono-label">status</span>
      </div>

      <template v-if="loading && !data">
        <div v-for="i in 3" :key="i" class="px-5 py-4 border-b border-border/60 last:border-b-0">
          <Skeleton class="h-5 w-full" />
        </div>
      </template>

      <template v-else-if="error">
        <div class="px-5 py-8 text-center" role="alert">
          <XCircle class="size-6 text-destructive mx-auto mb-3" aria-hidden="true" />
          <p class="font-mono text-sm">request failed</p>
          <p class="text-xs text-muted-foreground mt-1">{{ error }}</p>
        </div>
      </template>

      <template v-else>
        <div
          v-for="row in checks"
          :key="row.key"
          class="px-5 py-4 border-b border-border/60 last:border-b-0 flex items-center justify-between gap-4"
        >
          <div class="flex items-center gap-3 min-w-0">
            <span
              aria-hidden="true"
              class="size-2 rounded-full shrink-0"
              :class="row.value ? 'bg-emerald-500' : 'bg-destructive'"
            />
            <div class="min-w-0">
              <div class="font-medium text-sm">{{ row.label }}</div>
              <div class="text-mono-label">{{ row.desc }}</div>
            </div>
          </div>
          <span
            class="font-mono text-xs px-2.5 py-1 rounded-md hairline"
            :class="row.value
              ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/5'
              : 'text-destructive bg-destructive/5'"
            :aria-label="`${row.label}: ${row.value ? 'operational' : 'down'}`"
          >
            <span aria-hidden="true">{{ row.value ? 'true' : 'false' }}</span>
          </span>
        </div>
      </template>
    </div>

    <!-- Raw response -->
    <div v-if="data" class="mt-6 hairline rounded-xl bg-card overflow-hidden">
      <div class="px-5 py-2.5 border-b border-border/60 bg-muted/30 flex items-center justify-between">
        <span class="text-mono-label">raw response</span>
        <span class="text-mono-label">json</span>
      </div>
      <pre class="font-mono text-xs leading-relaxed p-5 overflow-x-auto">{{ JSON.stringify(data, null, 2) }}</pre>
    </div>
  </div>
</template>
