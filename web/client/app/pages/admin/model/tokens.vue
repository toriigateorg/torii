<script setup lang="ts">
import { Trash2, Eraser } from "lucide-vue-next"
import type { TokenSession } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useHead({ title: "Admin · Tokens — sanmon" })

const api = useAdminApi()

const items = ref<TokenSession[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const cleaning = ref(false)
const revokeTarget = ref<TokenSession | null>(null)
const revoking = ref(false)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listTokens(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load tokens"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

async function cleanup() {
  cleaning.value = true
  try {
    const res = await api.cleanupExpiredTokens()
    error.value = null
    await load()
    return res.deleted
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Cleanup failed"
  } finally {
    cleaning.value = false
  }
}

async function confirmRevoke() {
  if (!revokeTarget.value) return
  revoking.value = true
  try {
    await api.revokeToken(revokeTarget.value.id)
    revokeTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to revoke token"
  } finally {
    revoking.value = false
  }
}

function statusVariant(s: TokenSession["status"]) {
  if (s === "active") return "default"
  if (s === "revoked") return "destructive"
  return "secondary"
}

function fmt(ts: string | null) {
  if (!ts) return "—"
  return new Date(ts).toLocaleString()
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// tokens</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">Outstanding sessions</h2>
        <p class="text-sm text-muted-foreground mt-1">
          Active refresh tokens. Revoke a row to kill that session within ≤ 5 min.
        </p>
      </div>
      <Button variant="outline" class="hairline h-9" :disabled="cleaning" :aria-busy="cleaning" @click="cleanup">
        <Eraser class="size-4 mr-1.5" aria-hidden="true" />
        {{ cleaning ? "Cleaning…" : "Cleanup expired" }}
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">Outstanding refresh-token sessions</caption>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Revoked</TableHead>
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
              no sessions
            </TableCell>
          </TableRow>
          <TableRow v-for="t in items" :key="t.id">
            <TableCell>
              <div class="flex flex-col">
                <span class="font-mono text-xs">{{ t.username }}</span>
                <span class="font-mono text-[10px] text-muted-foreground break-all">{{ t.email }}</span>
              </div>
            </TableCell>
            <TableCell>
              <div class="flex items-center gap-2">
                <Badge :variant="statusVariant(t.status)">
                  <span class="sr-only">Status: </span>{{ t.status }}
                </Badge>
                <Badge v-if="t.is_current" variant="outline" class="font-mono text-[10px]">this session</Badge>
              </div>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.created_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.expires_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.revoked_at) }}</TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :disabled="t.status !== 'active' || t.is_current"
                :title="t.is_current ? 'Use sign out for current session' : t.status !== 'active' ? 'Already revoked or expired' : 'Revoke session'"
                :aria-label="t.is_current ? `Cannot revoke current session for ${t.username}` : t.status !== 'active' ? `Session for ${t.username} already ${t.status}` : `Revoke session for ${t.username}`"
                @click="revokeTarget = t"
              >
                <Trash2 class="size-4" aria-hidden="true" />
              </Button>
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

    <Dialog :open="!!revokeTarget" @update:open="(v) => { if (!v) revokeTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke session?</DialogTitle>
          <DialogDescription>
            This will revoke the refresh token for
            <span class="font-mono">{{ revokeTarget?.username }}</span>.
            They'll be signed out within one access-token lifetime.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" @click="revokeTarget = null">Cancel</Button>
          <Button variant="destructive" :disabled="revoking" @click="confirmRevoke">
            {{ revoking ? "Revoking…" : "Revoke" }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </AdminShell>
</template>
