<script setup lang="ts">
import { Users, Shield, Server, ShieldCheck, LogIn, KeyRound, Inbox, Globe } from "lucide-vue-next"
import type { StatsResponse, StatsWindow } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useHead({ title: "Admin · Stats — sanmon" })

const api = useAdminApi()

const window = ref<StatsWindow>("7d")
const data = ref<StatsResponse | null>(null)
const loading = ref(false)
const errorMsg = ref<string | null>(null)

async function load() {
  loading.value = true
  errorMsg.value = null
  try {
    data.value = await api.stats(window.value)
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    errorMsg.value = e?.data?.error ?? e?.message ?? "Failed to load stats"
  } finally {
    loading.value = false
  }
}

onMounted(load)
watch(window, load)

const counters = computed(() => {
  const c = data.value?.counters
  return [
    { label: "Users", value: c?.users ?? 0, icon: Users },
    { label: "Admins", value: c?.admins ?? 0, icon: ShieldCheck },
    { label: "Services", value: c?.services ?? 0, icon: Server },
    { label: "Roles", value: c?.roles ?? 0, icon: Shield },
    { label: "SSO providers", value: c?.sso_providers ?? 0, icon: LogIn },
    { label: "Active sessions", value: c?.active_sessions ?? 0, icon: KeyRound },
  ]
})

const maxBucket = computed(() => {
  const a = data.value?.activity ?? []
  return a.reduce((m, b) => (b.count > m ? b.count : m), 0)
})

const totalEvents = computed(() => {
  const a = data.value?.activity ?? []
  return a.reduce((s, b) => s + b.count, 0)
})

function barHeight(count: number): string {
  if (maxBucket.value === 0) return "2px"
  const pct = Math.max(2, Math.round((count / maxBucket.value) * 100))
  return `${pct}%`
}

const axisLabels = computed(() => {
  const a = data.value?.activity ?? []
  if (a.length === 0) return [] as string[]
  if (a.length === 1) return [a[0]!.day]
  const mid = Math.floor((a.length - 1) / 2)
  return [a[0]!.day, a[mid]!.day, a[a.length - 1]!.day]
})

const topMax = computed(() => {
  const t = data.value?.top_services ?? []
  return t.reduce((m, s) => (s.access_count > m ? s.access_count : m), 0)
})
</script>

<template>
  <AdminShell>
    <div class="flex items-start justify-between flex-wrap gap-3 mb-6">
      <div>
        <h2 class="text-xl font-semibold tracking-tight">Stats</h2>
        <p class="text-sm text-muted-foreground mt-1">
          A health check at a glance.
        </p>
      </div>
      <div class="inline-flex hairline rounded-md p-1 bg-card/40 gap-1" role="group" aria-label="Time window">
        <Button
          v-for="w in (['7d','30d','90d'] as StatsWindow[])"
          :key="w"
          :variant="window === w ? 'default' : 'ghost'"
          size="sm"
          class="font-mono text-xs h-7 px-3"
          @click="window = w"
        >{{ w }}</Button>
      </div>
    </div>

    <div v-if="errorMsg" class="hairline rounded-md p-4 bg-destructive/10 text-sm text-destructive mb-6" role="alert">
      {{ errorMsg }}
    </div>

    <!-- Counters -->
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
      <div
        v-for="c in counters"
        :key="c.label"
        class="hairline rounded-lg p-4 bg-card/60 flex flex-col gap-3"
      >
        <div class="flex items-center justify-between">
          <span class="text-mono-label">{{ c.label }}</span>
          <component :is="c.icon" class="size-3.5 text-muted-foreground" aria-hidden="true" />
        </div>
        <div class="font-mono text-2xl tabular-nums tracking-tight">
          <span v-if="loading && !data" class="text-muted-foreground">—</span>
          <span v-else>{{ c.value }}</span>
        </div>
      </div>
    </div>

    <!-- Activity chart -->
    <section class="hairline rounded-lg bg-card/60 p-5 sm:p-6 mb-6" aria-labelledby="activity-h">
      <div class="flex items-end justify-between mb-5 gap-3 flex-wrap">
        <div>
          <p class="text-mono-label mb-1">// activity</p>
          <h3 id="activity-h" class="text-base font-semibold tracking-tight">Audit events per day</h3>
        </div>
        <div class="font-mono text-xs text-muted-foreground">
          <span class="text-foreground tabular-nums">{{ totalEvents }}</span> events · {{ window }}
        </div>
      </div>

      <div v-if="loading && !data" class="h-40 flex items-center justify-center text-mono-label">loading…</div>
      <template v-else-if="data && data.activity.length > 0">
        <div class="h-40 flex items-end gap-[2px] sm:gap-1" role="img" :aria-label="`Audit events per day, ${window} window`">
          <div
            v-for="b in data.activity"
            :key="b.day"
            class="flex-1 flex items-end min-w-0"
          >
            <div
              class="w-full rounded-sm bg-primary/70 hover:bg-primary transition-colors"
              :style="{ height: barHeight(b.count) }"
              :title="`${b.day} · ${b.count} event${b.count === 1 ? '' : 's'}`"
            />
          </div>
        </div>
        <div class="mt-3 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          <span v-for="(d, i) in axisLabels" :key="d + i">{{ d }}</span>
        </div>
      </template>
      <div v-else class="h-40 flex items-center justify-center text-mono-label">no events in this window</div>
    </section>

    <!-- Top services -->
    <section class="hairline rounded-lg bg-card/60 p-5 sm:p-6" aria-labelledby="top-h">
      <div class="flex items-end justify-between mb-5 gap-3 flex-wrap">
        <div>
          <p class="text-mono-label mb-1">// top services</p>
          <h3 id="top-h" class="text-base font-semibold tracking-tight">Most-accessed services</h3>
        </div>
        <span class="font-mono text-xs text-muted-foreground">{{ window }}</span>
      </div>

      <div v-if="loading && !data" class="py-8 flex items-center justify-center text-mono-label">loading…</div>
      <ul v-else-if="data && data.top_services.length > 0" class="flex flex-col gap-2">
        <li
          v-for="(s, i) in data.top_services"
          :key="s.id"
          class="relative hairline rounded-md overflow-hidden bg-background"
        >
          <div
            aria-hidden="true"
            class="absolute inset-y-0 left-0 bg-primary/10"
            :style="{ width: topMax === 0 ? '0%' : `${Math.max(2, Math.round((s.access_count / topMax) * 100))}%` }"
          />
          <div class="relative flex items-center justify-between gap-4 px-4 py-3">
            <div class="flex items-center gap-3 min-w-0">
              <span class="font-mono text-[10px] tracking-wider text-muted-foreground w-5 shrink-0">
                {{ String(i + 1).padStart(2, "0") }}
              </span>
              <Globe class="size-3.5 text-muted-foreground shrink-0" aria-hidden="true" />
              <div class="min-w-0">
                <p class="text-sm font-medium truncate">{{ s.title }}</p>
                <p class="font-mono text-[11px] text-muted-foreground truncate">{{ s.domain }}</p>
              </div>
            </div>
            <span class="font-mono text-sm tabular-nums shrink-0">{{ s.access_count }}</span>
          </div>
        </li>
      </ul>
      <div
        v-else
        class="hairline rounded-md p-8 bg-background text-center"
      >
        <Inbox class="size-5 text-muted-foreground inline-block mb-2" aria-hidden="true" />
        <p class="text-sm text-muted-foreground">No proxy access in this window.</p>
      </div>
    </section>
  </AdminShell>
</template>
