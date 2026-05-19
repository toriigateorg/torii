<script setup lang="ts">
import { Plus, Trash2, ShieldCheck } from "lucide-vue-next"
import type { AuthUser } from "~/composables/useAuth"
import type { CreateUserPayload, Role } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · Users — torii", robots: "noindex, nofollow" })

const { user: currentUser } = useAuth()
const api = useAdminApi()
const route = useRoute()
const router = useRouter()

function pageFromQuery(q: unknown): number {
  const n = Number.parseInt(Array.isArray(q) ? q[0] ?? "" : (q as string) ?? "", 10)
  return Number.isFinite(n) && n > 0 ? n : 1
}

const items = ref<AuthUser[]>([])
const page = ref(pageFromQuery(route.query.page))
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const isProd = !import.meta.dev

const createOpen = ref(false)
const creating = ref(false)
const createError = ref<string | null>(null)
const newUser = ref<CreateUserPayload>({
  username: "",
  email: "",
  password: "",
  first_name: "",
  last_name: "",
})

const deleteTarget = ref<AuthUser | null>(null)
const deleting = ref(false)

const rolesTarget = ref<AuthUser | null>(null)
const allRoles = ref<Role[]>([])
const userRoles = ref<Role[]>([])
const rolesLoading = ref(false)
const rolesError = ref<string | null>(null)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listUsers(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load users"
  } finally {
    loading.value = false
  }
}

watch(page, (p) => {
  const current = pageFromQuery(route.query.page)
  if (current !== p) {
    const query = { ...route.query }
    if (p === 1) delete query.page
    else query.page = String(p)
    router.replace({ query })
  }
  load()
})
watch(() => route.query.page, (q) => {
  const p = pageFromQuery(q)
  if (p !== page.value) page.value = p
})
onMounted(load)

function resetCreate() {
  newUser.value = {
    username: "",
    email: "",
    password: "",
    first_name: "",
    last_name: "",
  }
  createError.value = null
}

async function submitCreate() {
  creating.value = true
  createError.value = null
  try {
    await api.createUser(newUser.value)
    createOpen.value = false
    resetCreate()
    page.value = 1
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    createError.value = err?.data?.error ?? err?.message ?? "Failed to create user"
  } finally {
    creating.value = false
  }
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await api.deleteUser(deleteTarget.value.id)
    deleteTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete user"
  } finally {
    deleting.value = false
  }
}

function isSelf(u: AuthUser) {
  return currentUser.value?.id === u.id
}

async function openRoles(u: AuthUser) {
  rolesTarget.value = u
  rolesError.value = null
  rolesLoading.value = true
  try {
    const [rolesRes, userRolesRes] = await Promise.all([
      api.listRoles(1, 100),
      api.listUserRoles(u.id),
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
  const userId = rolesTarget.value.id
  rolesError.value = null
  try {
    if (isAssigned(role.id)) {
      await api.revokeUserRole(userId, role.id)
    } else {
      await api.assignUserRole(userId, role.id)
    }
    const userRolesRes = await api.listUserRoles(userId)
    userRoles.value = userRolesRes.items
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    rolesError.value = err?.data?.error ?? err?.message ?? "Failed to update role"
  }
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// users</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">All users</h2>
      </div>
      <Button class="h-9" @click="createOpen = true; resetCreate()">
        <Plus class="size-4 mr-1.5" aria-hidden="true" /> Create user
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">List of user accounts</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Username</TableHead>
            <TableHead>Email</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Roles</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-if="loading && !items.length">
            <TableCell colspan="5" class="text-center py-12 text-muted-foreground font-mono text-xs">
              <span role="status">loading…</span>
            </TableCell>
          </TableRow>
          <TableRow v-else-if="!items.length">
            <TableCell colspan="5" class="text-center py-12 text-muted-foreground font-mono text-xs">
              no users
            </TableCell>
          </TableRow>
          <TableRow v-for="u in items" :key="u.id">
            <TableCell class="font-mono text-xs">{{ u.username }}</TableCell>
            <TableCell class="font-mono text-xs break-all">{{ u.email }}</TableCell>
            <TableCell>{{ [u.first_name, u.last_name].filter(Boolean).join(" ") || "—" }}</TableCell>
            <TableCell>
              <div class="flex flex-wrap gap-1">
                <Badge
                  v-for="r in u.roles"
                  :key="r.id"
                  :variant="r.name === 'admin' ? 'default' : 'secondary'"
                  class="font-mono text-[10px]"
                >{{ r.name }}</Badge>
                <span v-if="!u.roles?.length" class="text-muted-foreground font-mono text-[10px]">—</span>
              </div>
            </TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :title="`Manage roles for ${u.username}`"
                :aria-label="`Manage roles for ${u.username}`"
                @click="openRoles(u)"
              >
                <ShieldCheck class="size-4" aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :disabled="isSelf(u)"
                :title="isSelf(u) ? 'Cannot delete yourself' : `Delete user ${u.username}`"
                :aria-label="isSelf(u) ? `Cannot delete yourself (${u.username})` : `Delete user ${u.username}`"
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
          <DialogTitle>Create user</DialogTitle>
          <DialogDescription>
            {{ isProd ? "Strong password required (8+ chars, upper, lower, digit, symbol)." : "Dev mode: any non-empty password works." }}
            New users are added to the <span class="font-mono">all</span> role only — assign more roles after creation.
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submitCreate">
          <div class="grid grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="cu-username">Username</Label>
              <Input id="cu-username" v-model="newUser.username" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="cu-email">Email</Label>
              <Input id="cu-email" v-model="newUser.email" type="email" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="cu-first">First name</Label>
              <Input id="cu-first" v-model="newUser.first_name" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="cu-last">Last name</Label>
              <Input id="cu-last" v-model="newUser.last_name" />
            </div>
            <div class="flex flex-col gap-1.5 col-span-2">
              <Label for="cu-pw">Password</Label>
              <Input id="cu-pw" v-model="newUser.password" type="password" autocomplete="new-password" />
            </div>
          </div>
          <p
            id="cu-error"
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ createError || '' }}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" @click="createOpen = false">Cancel</Button>
            <Button type="submit" :disabled="creating">
              {{ creating ? "Creating…" : "Create" }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deleteTarget" @update:open="(v) => { if (!v) deleteTarget = null }">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete user?</DialogTitle>
          <DialogDescription>
            This will permanently remove
            <span class="font-mono">{{ deleteTarget?.username }}</span>
            and all of their sessions. This cannot be undone.
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
            Toggle role membership for <span class="font-mono">{{ rolesTarget?.username }}</span>.
            The <span class="font-mono">all</span> role is automatic.
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
