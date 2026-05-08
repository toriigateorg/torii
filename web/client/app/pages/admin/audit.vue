<script setup lang="ts">
import { Search, X } from "lucide-vue-next"
import type { AuditLog, AuditLogQuery } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · Audit log — torii", robots: "noindex, nofollow" })

const api = useAdminApi()

const items = ref<AuditLog[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)
const selected = ref<AuditLog | null>(null)

const filters = reactive({
  event_type: "",
  target_type: "",
  actor_user_id: "",
  from: "",
  to: "",
})

const eventTypes = [
  "auth.signup.success",
  "auth.signup.failed",
  "auth.signin.success",
  "auth.signin.failed",
  "auth.signin.sso",
  "auth.logout",
  "auth.token_refresh.failed",
  "authz.denied",
  "rbac.user.created",
  "rbac.user.deleted",
  "rbac.role.created",
  "rbac.role.updated",
  "rbac.role.deleted",
  "rbac.role.permissions_changed",
  "rbac.role.service_assigned",
  "rbac.role.service_revoked",
  "rbac.user_role.assigned",
  "rbac.user_role.revoked",
  "service.created",
  "service.updated",
  "service.deleted",
  "sso.provider.created",
  "sso.provider.updated",
  "sso.provider.deleted",
  "settings.updated",
  "token.revoked_by_admin",
  "token.cleanup",
  "proxy.access",
  "proxy.denied",
]

const targetTypes = ["user", "role", "service", "sso_provider", "setting", "refresh_token"]

function buildQuery(): AuditLogQuery {
  const q: AuditLogQuery = { page: page.value, page_size: pageSize.value }
  if (filters.event_type) q.event_type = filters.event_type
  if (filters.target_type) q.target_type = filters.target_type
  if (filters.actor_user_id.trim()) q.actor_user_id = filters.actor_user_id.trim()
  if (filters.from) q.from = new Date(filters.from).toISOString()
  if (filters.to) q.to = new Date(filters.to).toISOString()
  return q
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listAuditLogs(buildQuery())
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load audit logs"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

function applyFilters() {
  page.value = 1
  load()
}

function clearFilters() {
  filters.event_type = ""
  filters.target_type = ""
  filters.actor_user_id = ""
  filters.from = ""
  filters.to = ""
  page.value = 1
  load()
}

function fmt(ts: string) {
  if (!ts) return "—"
  return new Date(ts).toLocaleString()
}

function shortId(id: string | null): string {
  if (!id) return "—"
  return id.slice(0, 8)
}

function categoryVariant(eventType: string): "default" | "destructive" | "secondary" | "outline" {
  if (eventType.includes("denied") || eventType.endsWith(".failed") || eventType.includes(".deleted")) return "destructive"
  if (eventType.startsWith("auth.signin.success") || eventType.startsWith("auth.signin.sso")) return "default"
  if (eventType.startsWith("rbac.") || eventType.startsWith("service.") || eventType.startsWith("sso.")) return "secondary"
  return "outline"
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

const selectedBefore = computed(() => selected.value?.metadata?.before)
const selectedAfter = computed(() => selected.value?.metadata?.after)
const selectedOtherMeta = computed(() => {
  if (!selected.value) return {}
  const m = { ...(selected.value.metadata ?? {}) } as Record<string, unknown>
  delete m.before
  delete m.after
  return m
})
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// audit</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">Audit log</h2>
        <p class="text-sm text-muted-foreground mt-1">
          Security-relevant events: signins, RBAC changes, proxy access, denials.
        </p>
      </div>
    </div>

    <div class="hairline rounded-lg p-4 bg-card/40 mb-4">
      <div class="grid gap-3 md:grid-cols-3 lg:grid-cols-5">
        <div>
          <Label for="f-event" class="text-xs">Event type</Label>
          <NativeSelect id="f-event" v-model="filters.event_type" class="mt-1">
            <option value="">All</option>
            <option v-for="et in eventTypes" :key="et" :value="et">{{ et }}</option>
          </NativeSelect>
        </div>
        <div>
          <Label for="f-target" class="text-xs">Target type</Label>
          <NativeSelect id="f-target" v-model="filters.target_type" class="mt-1">
            <option value="">All</option>
            <option v-for="tt in targetTypes" :key="tt" :value="tt">{{ tt }}</option>
          </NativeSelect>
        </div>
        <div>
          <Label for="f-actor" class="text-xs">Actor user ID</Label>
          <Input id="f-actor" v-model="filters.actor_user_id" placeholder="UUID" class="mt-1 font-mono text-xs" />
        </div>
        <div>
          <Label for="f-from" class="text-xs">From</Label>
          <Input id="f-from" v-model="filters.from" type="datetime-local" class="mt-1" />
        </div>
        <div>
          <Label for="f-to" class="text-xs">To</Label>
          <Input id="f-to" v-model="filters.to" type="datetime-local" class="mt-1" />
        </div>
      </div>
      <div class="flex items-center gap-2 mt-3">
        <Button size="sm" @click="applyFilters">
          <Search class="size-4 mr-1.5" aria-hidden="true" />
          Apply
        </Button>
        <Button size="sm" variant="ghost" @click="clearFilters">
          <X class="size-4 mr-1.5" aria-hidden="true" />
          Clear
        </Button>
      </div>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">Audit log entries</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Event</TableHead>
            <TableHead>Actor</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Client IP</TableHead>
            <TableHead>User agent</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-if="loading && !items.length">
            <TableCell colspan="6" class="text-center py-12 text-muted-foreground font-mono text-xs">
              <span role="status">loading…</span>
            </TableCell>
          </TableRow>
          <TableRow v-else-if="!items.length">
            <TableCell colspan="6" class="text-center py-12 text-muted-foreground font-mono text-xs">
              no events
            </TableCell>
          </TableRow>
          <TableRow
            v-for="row in items"
            :key="row.id"
            class="cursor-pointer hover:bg-accent/40"
            @click="selected = row"
          >
            <TableCell class="font-mono text-xs whitespace-nowrap">{{ fmt(row.created_at) }}</TableCell>
            <TableCell>
              <Badge :variant="categoryVariant(row.event_type)" class="font-mono text-[10px]">
                {{ row.event_type }}
              </Badge>
            </TableCell>
            <TableCell>
              <div class="flex flex-col">
                <span class="font-mono text-xs">{{ row.actor_username || "—" }}</span>
                <span class="font-mono text-[10px] text-muted-foreground">{{ shortId(row.actor_user_id) }}</span>
              </div>
            </TableCell>
            <TableCell>
              <div v-if="row.target_type" class="flex flex-col">
                <span class="font-mono text-xs">{{ row.target_type }}: {{ row.target_name || shortId(row.target_id) }}</span>
                <span class="font-mono text-[10px] text-muted-foreground">{{ shortId(row.target_id) }}</span>
              </div>
              <span v-else class="text-muted-foreground font-mono text-xs">—</span>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ row.client_ip || "—" }}</TableCell>
            <TableCell class="font-mono text-[10px] text-muted-foreground max-w-[260px] truncate" :title="row.user_agent">
              {{ row.user_agent || "—" }}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <PaginationBar
      :page="page"
      :page-size="pageSize"
      :total="total"
      @update:page="(p) => (page = p)"
    />

    <Sheet :open="!!selected" @update:open="(v) => { if (!v) selected = null }">
      <SheetContent class="sm:max-w-2xl overflow-y-auto">
        <SheetHeader>
          <SheetTitle>Event details</SheetTitle>
          <SheetDescription v-if="selected">
            <span class="font-mono">{{ selected.event_type }}</span>
            ·
            {{ fmt(selected.created_at) }}
          </SheetDescription>
        </SheetHeader>

        <div v-if="selected" class="mt-4 space-y-4 text-sm">
          <div class="grid grid-cols-[120px_1fr] gap-2 hairline rounded-md p-3 bg-card/40">
            <span class="text-muted-foreground">Actor</span>
            <span class="font-mono text-xs">
              {{ selected.actor_username || "—" }}
              <span v-if="selected.actor_user_id" class="text-muted-foreground"> ({{ selected.actor_user_id }})</span>
            </span>
            <span class="text-muted-foreground">Target</span>
            <span class="font-mono text-xs">
              <template v-if="selected.target_type">
                {{ selected.target_type }}: {{ selected.target_name || "—" }}
                <span v-if="selected.target_id" class="text-muted-foreground"> ({{ selected.target_id }})</span>
              </template>
              <template v-else>—</template>
            </span>
            <span class="text-muted-foreground">Client IP</span>
            <span class="font-mono text-xs">{{ selected.client_ip || "—" }}</span>
            <span class="text-muted-foreground">User agent</span>
            <span class="font-mono text-xs break-all">{{ selected.user_agent || "—" }}</span>
          </div>

          <div v-if="selectedBefore || selectedAfter" class="grid gap-3 md:grid-cols-2">
            <div>
              <p class="text-mono-label mb-1">// before</p>
              <pre v-if="selectedBefore" class="hairline rounded-md p-3 bg-card/40 text-[11px] font-mono overflow-auto max-h-72">{{ prettyJson(selectedBefore) }}</pre>
              <p v-else class="text-muted-foreground text-xs">—</p>
            </div>
            <div>
              <p class="text-mono-label mb-1">// after</p>
              <pre v-if="selectedAfter" class="hairline rounded-md p-3 bg-card/40 text-[11px] font-mono overflow-auto max-h-72">{{ prettyJson(selectedAfter) }}</pre>
              <p v-else class="text-muted-foreground text-xs">—</p>
            </div>
          </div>

          <div v-if="Object.keys(selectedOtherMeta).length">
            <p class="text-mono-label mb-1">// metadata</p>
            <pre class="hairline rounded-md p-3 bg-card/40 text-[11px] font-mono overflow-auto max-h-72">{{ prettyJson(selectedOtherMeta) }}</pre>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  </AdminShell>
</template>
