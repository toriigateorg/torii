<script setup lang="ts">
import { Plus, Trash2, Pencil, X, RefreshCw } from "lucide-vue-next"
import type { Service, ServicePayload, ServiceHealth } from "~/composables/useAdminApi"

interface HealthState {
  status: "idle" | "checking" | "done"
  result?: ServiceHealth
}

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · Services — torii", robots: "noindex, nofollow" })

const api = useAdminApi()

const items = ref<Service[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const formOpen = ref(false)
const formMode = ref<"create" | "edit">("create")
const editTargetId = ref<string | null>(null)
const submitting = ref(false)
const formError = ref<string | null>(null)

interface HeaderRow { key: string; value: string }

const form = ref<ServicePayload>({
  title: "",
  description: "",
  service_url: "",
  domain: "",
  headers: {},
  preserve_host: false,
  passthrough_errors: true,
})
const headerRows = ref<HeaderRow[]>([])

const deleteTarget = ref<Service | null>(null)
const deleting = ref(false)

const health = ref<Record<string, HealthState>>({})

async function checkHealth(id: string) {
  health.value = { ...health.value, [id]: { status: "checking" } }
  try {
    const result = await api.checkServiceHealth(id)
    health.value = { ...health.value, [id]: { status: "done", result } }
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    health.value = {
      ...health.value,
      [id]: {
        status: "done",
        result: { ok: false, latency_ms: 0, error: err?.data?.error ?? err?.message ?? "check failed" },
      },
    }
  }
}

function checkAll() {
  for (const s of items.value) void checkHealth(s.id)
}

const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]+)?$/

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listServices(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
    health.value = {}
    checkAll()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load services"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

function resetForm() {
  form.value = { title: "", description: "", service_url: "", domain: "", headers: {}, preserve_host: false, passthrough_errors: true }
  headerRows.value = []
  formError.value = null
  editTargetId.value = null
}

function openCreate() {
  resetForm()
  formMode.value = "create"
  formOpen.value = true
}

function openEdit(svc: Service) {
  formMode.value = "edit"
  editTargetId.value = svc.id
  form.value = {
    title: svc.title,
    description: svc.description,
    service_url: svc.service_url,
    domain: svc.domain,
    headers: { ...svc.headers },
    preserve_host: svc.preserve_host,
    passthrough_errors: svc.passthrough_errors,
  }
  headerRows.value = Object.entries(svc.headers).map(([key, value]) => ({ key, value }))
  formError.value = null
  formOpen.value = true
}

function addHeaderRow() {
  headerRows.value.push({ key: "", value: "" })
}

function removeHeaderRow(i: number) {
  headerRows.value.splice(i, 1)
}

function collectHeaders(): Record<string, string> {
  const out: Record<string, string> = {}
  for (const row of headerRows.value) {
    const k = row.key.trim()
    if (k) out[k] = row.value
  }
  return out
}

function validate(): string | null {
  const title = form.value.title.trim()
  if (title.length < 1 || title.length > 200) return "title must be 1-200 chars"
  if (form.value.description.length > 2000) return "description must be at most 2000 chars"
  const domain = form.value.domain.trim().toLowerCase()
  if (!domainRe.test(domain)) return "domain must be a hostname[:port], no scheme, no path"
  const url = form.value.service_url.trim()
  let parsed: URL
  try { parsed = new URL(url) } catch { return "service_url must be a valid http(s) URL" }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "service_url scheme must be http or https"
  if (!(parsed.pathname === "" || parsed.pathname === "/") || parsed.search || parsed.hash) {
    return "service_url must not contain a path, query, or fragment"
  }
  return null
}

async function submit() {
  const msg = validate()
  if (msg) { formError.value = msg; return }
  submitting.value = true
  formError.value = null
  try {
    const payload: ServicePayload = {
      title: form.value.title.trim(),
      description: form.value.description.trim(),
      service_url: form.value.service_url.trim(),
      domain: form.value.domain.trim().toLowerCase(),
      headers: collectHeaders(),
      preserve_host: form.value.preserve_host,
      passthrough_errors: form.value.passthrough_errors,
    }
    if (formMode.value === "create") {
      await api.createService(payload)
    } else if (editTargetId.value) {
      await api.updateService(editTargetId.value, payload)
    }
    formOpen.value = false
    resetForm()
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    formError.value = err?.data?.error ?? err?.message ?? "Failed to save service"
  } finally {
    submitting.value = false
  }
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await api.deleteService(deleteTarget.value.id)
    deleteTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete service"
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// services</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">All services</h2>
      </div>
      <div class="flex items-center gap-2">
        <Button
          variant="outline"
          class="h-9"
          :disabled="!items.length"
          @click="checkAll"
        >
          <RefreshCw class="size-4 mr-1.5" aria-hidden="true" /> Recheck all
        </Button>
        <Button class="h-9" @click="openCreate">
          <Plus class="size-4 mr-1.5" aria-hidden="true" /> Create service
        </Button>
      </div>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">List of proxied services</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Title</TableHead>
            <TableHead>Domain</TableHead>
            <TableHead>Service URL</TableHead>
            <TableHead>Headers</TableHead>
            <TableHead>Status</TableHead>
            <TableHead class="text-right">Actions</TableHead>
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
              no services
            </TableCell>
          </TableRow>
          <TableRow v-for="s in items" :key="s.id">
            <TableCell>
              <div class="font-medium">{{ s.title }}</div>
              <div v-if="s.description" class="text-xs text-muted-foreground line-clamp-1">{{ s.description }}</div>
            </TableCell>
            <TableCell class="font-mono text-xs break-all">{{ s.domain }}</TableCell>
            <TableCell class="font-mono text-xs break-all">{{ s.service_url }}</TableCell>
            <TableCell>
              <Badge variant="secondary">{{ Object.keys(s.headers).length }}</Badge>
            </TableCell>
            <TableCell>
              <div class="flex items-center gap-2">
                <template v-if="!health[s.id] || health[s.id]?.status === 'checking'">
                  <span
                    class="inline-block size-2 rounded-full bg-muted-foreground/40 animate-pulse"
                    aria-hidden="true"
                  />
                  <span class="text-xs font-mono text-muted-foreground">checking…</span>
                </template>
                <template v-else-if="health[s.id]?.result?.ok">
                  <span class="inline-block size-2 rounded-full bg-emerald-500" aria-hidden="true" />
                  <span class="text-xs font-mono text-muted-foreground">
                    {{ health[s.id]?.result?.status }} · {{ health[s.id]?.result?.latency_ms }}ms
                  </span>
                </template>
                <template v-else>
                  <span class="inline-block size-2 rounded-full bg-destructive" aria-hidden="true" />
                  <span
                    class="text-xs font-mono text-muted-foreground truncate max-w-[16ch]"
                    :title="health[s.id]?.result?.error || `HTTP ${health[s.id]?.result?.status}`"
                  >
                    {{ health[s.id]?.result?.status
                      ? `HTTP ${health[s.id]?.result?.status}`
                      : (health[s.id]?.result?.error || "down") }}
                  </span>
                </template>
                <Button
                  variant="ghost"
                  size="icon"
                  class="size-7 ml-auto"
                  :disabled="health[s.id]?.status === 'checking'"
                  :aria-label="`Recheck ${s.title}`"
                  @click="checkHealth(s.id)"
                >
                  <RefreshCw
                    class="size-3.5"
                    :class="{ 'animate-spin': health[s.id]?.status === 'checking' }"
                    aria-hidden="true"
                  />
                </Button>
              </div>
            </TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :aria-label="`Edit service ${s.title}`"
                @click="openEdit(s)"
              >
                <Pencil class="size-4" aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :aria-label="`Delete service ${s.title}`"
                @click="deleteTarget = s"
              >
                <Trash2 class="size-4" aria-hidden="true" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <AdminPaginationBar
      :page="page"
      :page-size="pageSize"
      :total="total"
      @update:page="(p) => (page = p)"
    />

    <Dialog v-model:open="formOpen">
      <DialogContent class="max-w-xl">
        <DialogHeader>
          <DialogTitle>{{ formMode === "create" ? "Create service" : "Edit service" }}</DialogTitle>
          <DialogDescription>
            Map an incoming domain to an upstream URL. Torii proxies the request once the user is signed in.
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="svc-title">Title</Label>
            <Input id="svc-title" v-model="form.title" placeholder="Glance" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="svc-desc">Description</Label>
            <Input id="svc-desc" v-model="form.description" placeholder="Optional" />
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="svc-domain">Domain</Label>
              <Input id="svc-domain" v-model="form.domain" placeholder="glance.example.com" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="svc-url">Service URL</Label>
              <Input id="svc-url" v-model="form.service_url" placeholder="http://10.0.0.5:8080" />
            </div>
          </div>

          <div class="flex flex-col gap-2">
            <div class="flex items-center justify-between">
              <Label>Headers</Label>
              <Button type="button" variant="ghost" size="sm" class="h-7" @click="addHeaderRow">
                <Plus class="size-3.5 mr-1" aria-hidden="true" /> Add header
              </Button>
            </div>
            <div v-if="!headerRows.length" class="text-xs text-muted-foreground font-mono">
              no headers
            </div>
            <div
              v-for="(row, i) in headerRows"
              :key="i"
              class="flex items-center gap-2"
            >
              <Input v-model="row.key" placeholder="X-Forwarded-User" class="font-mono text-xs" />
              <Input v-model="row.value" placeholder="value" class="font-mono text-xs" />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                class="size-8 shrink-0"
                :aria-label="`Remove header ${row.key || i + 1}`"
                @click="removeHeaderRow(i)"
              >
                <X class="size-4" aria-hidden="true" />
              </Button>
            </div>
          </div>

          <div class="flex items-start gap-3 hairline rounded-md p-3 bg-muted/20">
            <Checkbox
              id="svc-preserve-host"
              :model-value="form.preserve_host"
              @update:model-value="(v) => (form.preserve_host = v === true)"
            />
            <div class="flex flex-col gap-0.5 -mt-0.5">
              <Label for="svc-preserve-host" class="cursor-pointer">Preserve Host header</Label>
              <p class="text-xs text-muted-foreground leading-relaxed">
                Forward the client's original
                <span class="font-mono">Host</span> header to the upstream. Enable for apps like
                Streamlit that build redirects from <span class="font-mono">Host</span>; leave off
                for vhost-based upstreams.
              </p>
            </div>
          </div>

          <div class="flex items-start gap-3 hairline rounded-md p-3 bg-muted/20">
            <Checkbox
              id="svc-passthrough-errors"
              :model-value="form.passthrough_errors"
              @update:model-value="(v) => (form.passthrough_errors = v === true)"
            />
            <div class="flex flex-col gap-0.5 -mt-0.5">
              <Label for="svc-passthrough-errors" class="cursor-pointer">Pass through upstream errors</Label>
              <p class="text-xs text-muted-foreground leading-relaxed">
                When the upstream returns a 5xx, forward its response body as-is. Disable to
                replace upstream 5xx responses with torii's generic error page.
              </p>
            </div>
          </div>

          <p
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ formError || '' }}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" @click="formOpen = false">Cancel</Button>
            <Button type="submit" :disabled="submitting">
              {{ submitting ? "Saving…" : (formMode === "create" ? "Create" : "Save") }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deleteTarget" @update:open="(v) => { if (!v) deleteTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete service?</DialogTitle>
          <DialogDescription>
            This will permanently remove the
            <span class="font-mono">{{ deleteTarget?.domain }}</span>
            mapping. Future requests to that domain will hit the 4xx page until reconfigured.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" @click="deleteTarget = null">Cancel</Button>
          <Button variant="destructive" :disabled="deleting" @click="confirmDelete">
            {{ deleting ? "Deleting…" : "Delete" }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </AdminShell>
</template>
