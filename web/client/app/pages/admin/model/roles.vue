<script setup lang="ts">
import { Plus, Trash2, Pencil } from "lucide-vue-next"
import type { AuthUser } from "~/composables/useAuth"
import type { Role, Service, CreateRolePayload } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · Roles — torii", robots: "noindex, nofollow" })

const api = useAdminApi()

const items = ref<Role[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)

const allPermissions = ref<string[]>([])
const allServices = ref<Service[]>([])

const createOpen = ref(false)
const creating = ref(false)
const createError = ref<string | null>(null)
const newRole = ref<CreateRolePayload>({ name: "", description: "", permissions: [] })

const detailRole = ref<Role | null>(null)
const detailPerms = ref<string[]>([])
const detailServices = ref<Service[]>([])
const detailMembers = ref<AuthUser[]>([])
const detailLoading = ref(false)
const detailError = ref<string | null>(null)
const detailTab = ref<"permissions" | "services" | "members">("permissions")

const editOpen = ref(false)
const editForm = ref<{ name: string; description: string }>({ name: "", description: "" })
const editing = ref(false)
const editError = ref<string | null>(null)

const deleteTarget = ref<Role | null>(null)
const deleting = ref(false)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listRoles(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load roles"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(async () => {
  await load()
  try {
    const [permsRes, svcRes] = await Promise.all([
      api.listPermissions(),
      api.listServices(1, 100),
    ])
    allPermissions.value = permsRes.items
    allServices.value = svcRes.items
  } catch {}
})

const groupedPermissions = computed(() => {
  const groups: Record<string, string[]> = {}
  for (const p of allPermissions.value) {
    const [resource] = p.split(".")
    if (!groups[resource!]) groups[resource!] = []
    groups[resource!].push(p)
  }
  return groups
})

function resetCreate() {
  newRole.value = { name: "", description: "", permissions: [] }
  createError.value = null
}

async function submitCreate() {
  creating.value = true
  createError.value = null
  try {
    await api.createRole(newRole.value)
    createOpen.value = false
    resetCreate()
    page.value = 1
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    createError.value = err?.data?.error ?? err?.message ?? "Failed to create role"
  } finally {
    creating.value = false
  }
}

async function openDetail(r: Role) {
  detailRole.value = r
  detailTab.value = "permissions"
  detailError.value = null
  detailLoading.value = true
  try {
    const [fresh, svcs, members] = await Promise.all([
      api.getRole(r.id),
      api.listRoleServices(r.id),
      api.listRoleUsers(r.id, 1, 100),
    ])
    detailRole.value = fresh
    detailPerms.value = [...fresh.permissions]
    detailServices.value = svcs.items
    detailMembers.value = members.items
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    detailError.value = err?.data?.error ?? err?.message ?? "Failed to load role"
  } finally {
    detailLoading.value = false
  }
}

function isAdminLocked() {
  return !!(detailRole.value?.is_system && detailRole.value.name === "admin")
}

function permIsSet(p: string) {
  return detailPerms.value.includes(p)
}

async function togglePermission(p: string) {
  if (!detailRole.value || isAdminLocked()) return
  const next = permIsSet(p)
    ? detailPerms.value.filter((x) => x !== p)
    : [...detailPerms.value, p]
  detailError.value = null
  try {
    const res = await api.setRolePermissions(detailRole.value.id, next)
    detailPerms.value = res.permissions
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    detailError.value = err?.data?.error ?? err?.message ?? "Failed to update permissions"
  }
}

function serviceIsAssigned(svcId: string) {
  return detailServices.value.some((s) => s.id === svcId)
}

async function toggleService(svc: Service) {
  if (!detailRole.value) return
  detailError.value = null
  try {
    if (serviceIsAssigned(svc.id)) {
      await api.revokeRoleService(detailRole.value.id, svc.id)
    } else {
      await api.assignRoleService(detailRole.value.id, svc.id)
    }
    const svcs = await api.listRoleServices(detailRole.value.id)
    detailServices.value = svcs.items
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    detailError.value = err?.data?.error ?? err?.message ?? "Failed to update services"
  }
}

function openEdit(r: Role) {
  editForm.value = { name: r.name, description: r.description }
  editError.value = null
  editOpen.value = true
}

async function submitEdit() {
  if (!detailRole.value) return
  editing.value = true
  editError.value = null
  try {
    const updated = await api.updateRole(detailRole.value.id, {
      name: detailRole.value.is_system ? undefined : editForm.value.name,
      description: editForm.value.description,
    })
    detailRole.value = updated
    editOpen.value = false
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    editError.value = err?.data?.error ?? err?.message ?? "Failed to update role"
  } finally {
    editing.value = false
  }
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await api.deleteRole(deleteTarget.value.id)
    deleteTarget.value = null
    detailRole.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete role"
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// roles</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">All roles</h2>
        <p class="text-sm text-muted-foreground mt-1">
          Roles bundle admin permissions and proxied service access. Members of a role inherit both.
        </p>
      </div>
      <Button class="h-9" @click="createOpen = true; resetCreate()">
        <Plus class="size-4 mr-1.5" aria-hidden="true" /> Create role
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">List of roles</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Permissions</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-if="loading && !items.length">
            <TableCell colspan="4" class="text-center py-12 text-muted-foreground font-mono text-xs">
              <span role="status">loading…</span>
            </TableCell>
          </TableRow>
          <TableRow v-else-if="!items.length">
            <TableCell colspan="4" class="text-center py-12 text-muted-foreground font-mono text-xs">
              no roles
            </TableCell>
          </TableRow>
          <TableRow
            v-for="r in items"
            :key="r.id"
            class="cursor-pointer"
            @click="openDetail(r)"
          >
            <TableCell>
              <div class="flex items-center gap-2">
                <span class="font-mono text-xs">{{ r.name }}</span>
                <Badge v-if="r.is_system" variant="outline" class="text-[10px]">system</Badge>
              </div>
            </TableCell>
            <TableCell class="text-xs text-muted-foreground line-clamp-1">{{ r.description || "—" }}</TableCell>
            <TableCell>
              <Badge variant="secondary">{{ r.permissions.length }}</Badge>
            </TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :disabled="r.is_system"
                :title="r.is_system ? 'System roles cannot be deleted' : `Delete role ${r.name}`"
                :aria-label="r.is_system ? `Cannot delete system role ${r.name}` : `Delete role ${r.name}`"
                @click.stop="deleteTarget = r"
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
          <DialogTitle>Create role</DialogTitle>
          <DialogDescription>
            Pick the permissions this role grants. You can also assign services and members after creation.
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submitCreate">
          <div class="flex flex-col gap-1.5">
            <Label for="cr-name">Name</Label>
            <Input id="cr-name" v-model="newRole.name" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="cr-desc">Description</Label>
            <Input id="cr-desc" v-model="newRole.description" />
          </div>
          <div class="flex flex-col gap-2">
            <Label>Permissions</Label>
            <div class="hairline rounded-md p-3 max-h-64 overflow-y-auto flex flex-col gap-3">
              <div v-for="(perms, group) in groupedPermissions" :key="group">
                <p class="text-mono-label mb-1.5">// {{ group }}</p>
                <div class="grid grid-cols-2 gap-1.5">
                  <label v-for="p in perms" :key="p" class="flex items-center gap-2 text-xs font-mono">
                    <Checkbox
                      :model-value="newRole.permissions.includes(p)"
                      @update:model-value="(v) => {
                        if (v) newRole.permissions = [...newRole.permissions, p]
                        else newRole.permissions = newRole.permissions.filter(x => x !== p)
                      }"
                    />
                    {{ p }}
                  </label>
                </div>
              </div>
            </div>
          </div>
          <p
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
          <DialogTitle>Delete role?</DialogTitle>
          <DialogDescription>
            This will remove
            <span class="font-mono">{{ deleteTarget?.name }}</span>,
            unassigning it from every user and service.
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

    <Sheet :open="!!detailRole" @update:open="(v) => { if (!v) detailRole = null }">
      <SheetContent class="w-full sm:max-w-xl overflow-y-auto gap-0">
        <SheetHeader class="border-b border-border/60">
          <SheetTitle class="flex items-center gap-2 pr-8">
            <span class="font-mono">{{ detailRole?.name }}</span>
            <Badge v-if="detailRole?.is_system" variant="outline" class="text-[10px]">system</Badge>
          </SheetTitle>
          <SheetDescription>{{ detailRole?.description || "No description." }}</SheetDescription>
          <div class="flex items-center gap-2 mt-2">
            <Button variant="outline" size="sm" class="h-8" :disabled="!detailRole" @click="detailRole && openEdit(detailRole)">
              <Pencil class="size-3.5 mr-1.5" aria-hidden="true" /> Edit
            </Button>
          </div>
        </SheetHeader>

        <div class="px-4 py-4 flex flex-col gap-4">
          <Alert v-if="detailError" variant="destructive">
            <AlertDescription>{{ detailError }}</AlertDescription>
          </Alert>

          <Tabs v-model="detailTab">
          <TabsList class="w-full">
            <TabsTrigger value="permissions" class="flex-1">Permissions</TabsTrigger>
            <TabsTrigger value="services" class="flex-1">Services</TabsTrigger>
            <TabsTrigger value="members" class="flex-1">Members</TabsTrigger>
          </TabsList>

          <TabsContent value="permissions" class="mt-4">
            <p v-if="isAdminLocked()" class="text-xs text-muted-foreground mb-3">
              The <span class="font-mono">admin</span> role has all permissions and cannot be edited.
            </p>
            <div v-if="detailLoading" class="text-muted-foreground font-mono text-xs py-6 text-center">loading…</div>
            <div v-else class="flex flex-col gap-3">
              <div v-for="(perms, group) in groupedPermissions" :key="group">
                <p class="text-mono-label mb-1.5">// {{ group }}</p>
                <div class="grid grid-cols-1 gap-1.5">
                  <label v-for="p in perms" :key="p" class="flex items-center gap-2 text-xs font-mono">
                    <Checkbox
                      :model-value="permIsSet(p)"
                      :disabled="isAdminLocked()"
                      @update:model-value="togglePermission(p)"
                    />
                    {{ p }}
                  </label>
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="services" class="mt-4">
            <p class="text-xs text-muted-foreground mb-3">
              Members of this role can reach the checked services through the reverse proxy.
            </p>
            <div v-if="detailLoading" class="text-muted-foreground font-mono text-xs py-6 text-center">loading…</div>
            <div v-else-if="!allServices.length" class="text-muted-foreground font-mono text-xs py-6 text-center">no services configured</div>
            <div v-else class="flex flex-col gap-2">
              <label
                v-for="s in allServices"
                :key="s.id"
                class="flex items-start gap-3 p-2 rounded hairline cursor-pointer"
              >
                <Checkbox
                  :model-value="serviceIsAssigned(s.id)"
                  @update:model-value="toggleService(s)"
                />
                <div class="flex-1 min-w-0">
                  <div class="font-mono text-xs">{{ s.title }}</div>
                  <div class="font-mono text-[10px] text-muted-foreground break-all">{{ s.domain }}</div>
                </div>
              </label>
            </div>
          </TabsContent>

          <TabsContent value="members" class="mt-4">
            <div v-if="detailLoading" class="text-muted-foreground font-mono text-xs py-6 text-center">loading…</div>
            <div v-else-if="!detailMembers.length" class="text-muted-foreground font-mono text-xs py-6 text-center">no members</div>
            <ul v-else class="flex flex-col gap-1">
              <li
                v-for="u in detailMembers"
                :key="u.id"
                class="flex items-center justify-between p-2 hairline rounded"
              >
                <div class="flex flex-col">
                  <span class="font-mono text-xs">{{ u.username }}</span>
                  <span class="font-mono text-[10px] text-muted-foreground break-all">{{ u.email }}</span>
                </div>
              </li>
            </ul>
            <p class="text-xs text-muted-foreground mt-3">
              Add or remove members from the Users page via the role management dialog.
            </p>
          </TabsContent>
        </Tabs>
        </div>
      </SheetContent>
    </Sheet>

    <Dialog v-model:open="editOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit role</DialogTitle>
          <DialogDescription>
            <span v-if="detailRole?.is_system">System role names cannot be changed.</span>
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submitEdit">
          <div class="flex flex-col gap-1.5">
            <Label for="er-name">Name</Label>
            <Input id="er-name" v-model="editForm.name" :disabled="!!detailRole?.is_system" />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="er-desc">Description</Label>
            <Input id="er-desc" v-model="editForm.description" />
          </div>
          <p
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ editError || '' }}</p>
          <DialogFooter>
            <Button type="button" variant="ghost" @click="editOpen = false">Cancel</Button>
            <Button type="submit" :disabled="editing">
              {{ editing ? "Saving…" : "Save" }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </AdminShell>
</template>
