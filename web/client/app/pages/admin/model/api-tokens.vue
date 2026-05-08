<script setup lang="ts">
import { Plus, Trash2, Copy, Check } from "lucide-vue-next"
import type { APIToken, CreateAPITokenPayload } from "~/composables/useAdminApi"
import type { AuthUser } from "~/composables/useAuth"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · API tokens — torii", robots: "noindex, nofollow" })

const { user: currentUser } = useAuth()
const api = useAdminApi()

const items = ref<APIToken[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const createOpen = ref(false)
const creating = ref(false)
const createError = ref<string | null>(null)
const usersForPicker = ref<AuthUser[]>([])
const newToken = ref<CreateAPITokenPayload>({ user_id: "", name: "", expires_at: "" })

const justCreated = ref<{ token: string; name: string; prefix: string } | null>(null)
const copied = ref(false)

const deleteTarget = ref<APIToken | null>(null)
const deleting = ref(false)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listAPITokens(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load API tokens"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

async function openCreate() {
  createError.value = null
  newToken.value = { user_id: currentUser.value?.id ?? "", name: "", expires_at: "" }
  createOpen.value = true
  try {
    const res = await api.listUsers(1, 100)
    usersForPicker.value = res.items
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    createError.value = err?.data?.error ?? err?.message ?? "Failed to load users"
  }
}

async function submitCreate() {
  creating.value = true
  createError.value = null
  try {
    const payload: CreateAPITokenPayload = {
      user_id: newToken.value.user_id,
      name: newToken.value.name.trim(),
    }
    if (newToken.value.expires_at) {
      payload.expires_at = new Date(newToken.value.expires_at).toISOString()
    }
    const res = await api.createAPIToken(payload)
    createOpen.value = false
    justCreated.value = { token: res.token, name: res.name, prefix: res.prefix }
    copied.value = false
    page.value = 1
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    createError.value = err?.data?.error ?? err?.message ?? "Failed to create token"
  } finally {
    creating.value = false
  }
}

async function copyToken() {
  if (!justCreated.value) return
  try {
    await navigator.clipboard.writeText(justCreated.value.token)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    /* clipboard blocked; user can select+copy manually */
  }
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await api.deleteAPIToken(deleteTarget.value.id)
    deleteTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete token"
  } finally {
    deleting.value = false
  }
}

function fmt(ts: string | null) {
  if (!ts) return "—"
  return new Date(ts).toLocaleString()
}

function isExpired(t: APIToken): boolean {
  if (!t.expires_at) return false
  return new Date(t.expires_at).getTime() < Date.now()
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// api tokens</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">Personal access tokens</h2>
        <p class="text-sm text-muted-foreground mt-1">
          Long-lived <span class="font-mono">torii_pat_…</span> credentials for scripts and the Terraform provider.
          A token inherits its owning user's permissions.
        </p>
      </div>
      <Button class="h-9" @click="openCreate">
        <Plus class="size-4 mr-1.5" aria-hidden="true" /> Create token
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">Active API tokens</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Prefix</TableHead>
            <TableHead>Owner</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Last used</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-if="loading && !items.length">
            <TableCell colspan="7" class="text-center py-12 text-muted-foreground font-mono text-xs">
              <span role="status">loading…</span>
            </TableCell>
          </TableRow>
          <TableRow v-else-if="!items.length">
            <TableCell colspan="7" class="text-center py-12 text-muted-foreground font-mono text-xs">
              no api tokens
            </TableCell>
          </TableRow>
          <TableRow v-for="t in items" :key="t.id">
            <TableCell>
              <div class="flex items-center gap-2">
                <span>{{ t.name }}</span>
                <Badge v-if="isExpired(t)" variant="destructive">expired</Badge>
              </div>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ t.prefix }}…</TableCell>
            <TableCell>
              <div class="flex flex-col">
                <span class="font-mono text-xs">{{ t.username }}</span>
                <span class="font-mono text-[10px] text-muted-foreground break-all">{{ t.email }}</span>
              </div>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.created_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.last_used_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(t.expires_at) }}</TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :title="`Delete token ${t.name}`"
                :aria-label="`Delete API token ${t.name}`"
                @click="deleteTarget = t"
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

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create API token</DialogTitle>
          <DialogDescription>
            The token will be shown <span class="font-semibold">once</span> after creation. Save it somewhere safe.
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submitCreate">
          <div class="flex flex-col gap-1.5">
            <Label for="at-name">Name</Label>
            <Input id="at-name" v-model="newToken.name" placeholder="terraform-prod" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="at-user">Owner</Label>
            <NativeSelect id="at-user" v-model="newToken.user_id">
              <option value="" disabled>Select a user…</option>
              <option v-for="u in usersForPicker" :key="u.id" :value="u.id">
                {{ u.username }} ({{ u.email }})
              </option>
            </NativeSelect>
            <p class="text-xs text-muted-foreground">
              The token inherits this user's permissions at request time.
            </p>
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="at-exp">Expires (optional)</Label>
            <Input id="at-exp" v-model="newToken.expires_at" type="datetime-local" />
            <p class="text-xs text-muted-foreground">Leave blank for no expiry.</p>
          </div>
          <p
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ createError || '' }}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" @click="createOpen = false">Cancel</Button>
            <Button type="submit" :disabled="creating || !newToken.name || !newToken.user_id">
              {{ creating ? "Creating…" : "Create" }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!justCreated" @update:open="(v) => { if (!v) justCreated = null }">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>Save your token now</DialogTitle>
          <DialogDescription>
            This is the only time the full token will be displayed. Copy it and store it somewhere safe.
          </DialogDescription>
        </DialogHeader>
        <div class="flex flex-col gap-3">
          <div class="flex flex-col gap-1">
            <Label class="text-mono-label">// {{ justCreated?.name }}</Label>
            <div class="flex items-stretch gap-2">
              <code
                class="flex-1 hairline rounded-md px-3 py-2 font-mono text-xs break-all bg-card/60 select-all"
              >{{ justCreated?.token }}</code>
              <Button
                type="button"
                variant="outline"
                size="icon"
                class="shrink-0"
                :title="copied ? 'Copied' : 'Copy to clipboard'"
                :aria-label="copied ? 'Copied' : 'Copy token to clipboard'"
                @click="copyToken"
              >
                <Check v-if="copied" class="size-4" aria-hidden="true" />
                <Copy v-else class="size-4" aria-hidden="true" />
              </Button>
            </div>
          </div>
          <Alert variant="destructive">
            <AlertDescription>
              Once you close this dialog the token cannot be retrieved again. If you lose it, delete this row and create a new one.
            </AlertDescription>
          </Alert>
        </div>
        <DialogFooter>
          <Button @click="justCreated = null">I've saved it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deleteTarget" @update:open="(v) => { if (!v) deleteTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete API token?</DialogTitle>
          <DialogDescription>
            Anything using <span class="font-mono">{{ deleteTarget?.name }}</span> will start getting 401s immediately. This cannot be undone.
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
