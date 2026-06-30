<script setup lang="ts">
import { Plus, Trash2, Copy, Check, ShieldCheck, RefreshCw } from "lucide-vue-next"
import type { APIUser, CreateAPIUserPayload, Role } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · Service users — torii", robots: "noindex, nofollow" })

const api = useAdminApi()

const items = ref<APIUser[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const createOpen = ref(false)
const creating = ref(false)
const createError = ref<string | null>(null)
const newUser = ref<CreateAPIUserPayload>({ name: "", description: "", expires_at: "" })

const justCreated = ref<{ token: string; name: string } | null>(null)
const copied = ref(false)

const deleteTarget = ref<APIUser | null>(null)
const deleting = ref(false)

const regenTarget = ref<APIUser | null>(null)
const regenerating = ref(false)

const rolesTarget = ref<APIUser | null>(null)
const allRoles = ref<Role[]>([])
const userRoles = ref<Role[]>([])
const rolesLoading = ref(false)
const rolesError = ref<string | null>(null)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listAPIUsers(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load service users"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

function openCreate() {
  createError.value = null
  newUser.value = { name: "", description: "", expires_at: "" }
  createOpen.value = true
}

async function submitCreate() {
  creating.value = true
  createError.value = null
  try {
    const payload: CreateAPIUserPayload = {
      name: newUser.value.name.trim(),
      description: (newUser.value.description ?? "").trim(),
    }
    if (newUser.value.expires_at) {
      payload.expires_at = new Date(newUser.value.expires_at).toISOString()
    }
    const res = await api.createAPIUser(payload)
    createOpen.value = false
    justCreated.value = { token: res.token, name: res.name }
    copied.value = false
    page.value = 1
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    createError.value = err?.data?.error ?? err?.message ?? "Failed to create service user"
  } finally {
    creating.value = false
  }
}

async function confirmRegenerate() {
  if (!regenTarget.value) return
  regenerating.value = true
  try {
    const res = await api.regenerateAPIUserToken(regenTarget.value.id)
    regenTarget.value = null
    justCreated.value = { token: res.token, name: res.name }
    copied.value = false
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to regenerate token"
  } finally {
    regenerating.value = false
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
    await api.deleteAPIUser(deleteTarget.value.id)
    deleteTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete service user"
  } finally {
    deleting.value = false
  }
}

async function openRoles(u: APIUser) {
  rolesTarget.value = u
  rolesError.value = null
  rolesLoading.value = true
  try {
    const [rolesRes, userRolesRes] = await Promise.all([
      api.listRoles(1, 100),
      api.listAPIUserRoles(u.id),
    ])
    allRoles.value = rolesRes.items
    userRoles.value = userRolesRes.items
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    rolesError.value = err?.data?.error ?? err?.message ?? "Failed to load roles"
  } finally {
    rolesLoading.value = false
  }
}

function isAssigned(roleId: string) {
  return userRoles.value.some((r) => r.id === roleId)
}

async function toggleRole(role: Role) {
  if (!rolesTarget.value) return
  if (role.is_system && role.name === "all") return
  const apiUserId = rolesTarget.value.id
  rolesError.value = null
  try {
    if (isAssigned(role.id)) {
      await api.revokeAPIUserRole(apiUserId, role.id)
    } else {
      await api.assignAPIUserRole(apiUserId, role.id)
    }
    const userRolesRes = await api.listAPIUserRoles(apiUserId)
    userRoles.value = userRolesRes.items
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    rolesError.value = err?.data?.error ?? err?.message ?? "Failed to update role"
  }
}

function fmt(ts: string | null) {
  if (!ts) return "—"
  return new Date(ts).toLocaleString()
}

function isExpired(u: APIUser): boolean {
  if (!u.expires_at) return false
  return new Date(u.expires_at).getTime() < Date.now()
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// service users</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">Service API users</h2>
        <p class="text-sm text-muted-foreground mt-1">
          Passwordless machine identities. A script passes the
          <span class="font-mono">torii_sat_…</span> token in the
          <span class="font-mono">X-Torii-Service-Token</span> header (or
          <span class="font-mono">Authorization: Bearer</span>) to reach a service behind torii without SSO.
          Access is governed by the roles you assign.
        </p>
      </div>
      <Button class="h-9" @click="openCreate">
        <Plus class="size-4 mr-1.5" aria-hidden="true" /> Create service user
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">Service API users</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Prefix</TableHead>
            <TableHead>Description</TableHead>
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
              no service users
            </TableCell>
          </TableRow>
          <TableRow v-for="u in items" :key="u.id">
            <TableCell>
              <div class="flex items-center gap-2">
                <span>{{ u.name }}</span>
                <Badge v-if="u.disabled" variant="outline">disabled</Badge>
                <Badge v-if="isExpired(u)" variant="destructive">expired</Badge>
              </div>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ u.prefix }}…</TableCell>
            <TableCell class="text-sm text-muted-foreground max-w-xs truncate">{{ u.description || "—" }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(u.created_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(u.last_used_at) }}</TableCell>
            <TableCell class="font-mono text-xs">{{ fmt(u.expires_at) }}</TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :title="`Manage roles for ${u.name}`"
                :aria-label="`Manage roles for ${u.name}`"
                @click="openRoles(u)"
              >
                <ShieldCheck class="size-4" aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :title="`Regenerate token for ${u.name}`"
                :aria-label="`Regenerate token for ${u.name}`"
                @click="regenTarget = u"
              >
                <RefreshCw class="size-4" aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :title="`Delete service user ${u.name}`"
                :aria-label="`Delete service user ${u.name}`"
                @click="deleteTarget = u"
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

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create service user</DialogTitle>
          <DialogDescription>
            The token will be shown <span class="font-semibold">once</span> after creation. Assign roles afterwards to grant service access.
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submitCreate">
          <div class="flex flex-col gap-1.5">
            <Label for="au-name">Name</Label>
            <Input id="au-name" v-model="newUser.name" placeholder="ci-deploy-bot" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="au-desc">Description (optional)</Label>
            <Input id="au-desc" v-model="newUser.description" placeholder="Used by the prod deploy pipeline" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="au-exp">Expires (optional)</Label>
            <Input id="au-exp" v-model="newUser.expires_at" type="datetime-local" />
            <p class="text-xs text-muted-foreground">Leave blank for no expiry.</p>
          </div>
          <p
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ createError || '' }}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" @click="createOpen = false">Cancel</Button>
            <Button type="submit" :disabled="creating || !newUser.name">
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
              Once you close this dialog the token cannot be retrieved again. If you lose it, regenerate it from the table.
            </AlertDescription>
          </Alert>
        </div>
        <DialogFooter>
          <Button @click="justCreated = null">I've saved it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!regenTarget" @update:open="(v) => { if (!v) regenTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Regenerate token?</DialogTitle>
          <DialogDescription>
            The current token for <span class="font-mono">{{ regenTarget?.name }}</span> stops working immediately. Any script using it must be updated with the new token.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" @click="regenTarget = null">Cancel</Button>
          <Button variant="destructive" :disabled="regenerating" @click="confirmRegenerate">
            {{ regenerating ? "Regenerating…" : "Regenerate" }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deleteTarget" @update:open="(v) => { if (!v) deleteTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete service user?</DialogTitle>
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

    <Dialog :open="!!rolesTarget" @update:open="(v) => { if (!v) rolesTarget = null }">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>Manage roles</DialogTitle>
          <DialogDescription>
            Toggle role membership for <span class="font-mono">{{ rolesTarget?.name }}</span>.
            A service user with no roles cannot reach any service.
          </DialogDescription>
        </DialogHeader>
        <Alert v-if="rolesError" variant="destructive">
          <AlertDescription>{{ rolesError }}</AlertDescription>
        </Alert>
        <div v-if="rolesLoading" class="text-muted-foreground font-mono text-xs py-6 text-center">loading…</div>
        <div v-else class="flex flex-col gap-2 max-h-80 overflow-y-auto">
          <label
            v-for="r in allRoles"
            :key="r.id"
            class="flex items-start gap-3 p-2 rounded hairline cursor-pointer"
            :class="{ 'opacity-60 cursor-not-allowed': r.is_system && r.name === 'all' }"
          >
            <Checkbox
              :model-value="isAssigned(r.id)"
              :disabled="r.is_system && r.name === 'all'"
              @update:model-value="toggleRole(r)"
            />
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <span class="font-mono text-xs">{{ r.name }}</span>
                <Badge v-if="r.is_system" variant="outline" class="text-[10px]">system</Badge>
              </div>
              <p v-if="r.description" class="text-xs text-muted-foreground mt-0.5">{{ r.description }}</p>
            </div>
          </label>
        </div>
        <DialogFooter>
          <Button variant="ghost" @click="rolesTarget = null">Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </AdminShell>
</template>
