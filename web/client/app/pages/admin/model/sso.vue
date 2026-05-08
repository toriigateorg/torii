<script setup lang="ts">
import { Plus, Trash2, Pencil } from "lucide-vue-next"
import type { SSOProvider, SSOProviderPayload } from "~/composables/useAdminApi"

definePageMeta({ middleware: ["auth", "admin"] })
useSeoMeta({ title: "Admin · SSO — torii", robots: "noindex, nofollow" })

const api = useAdminApi()

const items = ref<SSOProvider[]>([])
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

type Preset = "google" | "custom"
const preset = ref<Preset>("custom")

const form = ref<SSOProviderPayload>({
  slug: "",
  name: "",
  issuer_url: "",
  client_id: "",
  client_secret: "",
  scopes: "openid email profile",
  enabled: true,
  allow_signup: false,
  link_by_email: true,
})

const deleteTarget = ref<SSOProvider | null>(null)
const deleting = ref(false)

const slugRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await api.listSSO(page.value, pageSize.value)
    items.value = res.items
    total.value = res.total
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load providers"
  } finally {
    loading.value = false
  }
}

watch(page, load)
onMounted(load)

function resetForm() {
  form.value = {
    slug: "",
    name: "",
    issuer_url: "",
    client_id: "",
    client_secret: "",
    scopes: "openid email profile",
    enabled: true,
    allow_signup: false,
    link_by_email: true,
  }
  preset.value = "custom"
  formError.value = null
  editTargetId.value = null
}

function applyPreset(p: Preset) {
  preset.value = p
  if (p === "google") {
    form.value.issuer_url = "https://accounts.google.com"
    if (!form.value.name) form.value.name = "Google"
    if (!form.value.slug) form.value.slug = "google"
    form.value.scopes = "openid email profile"
  }
}

function openCreate() {
  resetForm()
  formMode.value = "create"
  formOpen.value = true
}

function openEdit(p: SSOProvider) {
  formMode.value = "edit"
  editTargetId.value = p.id
  form.value = {
    slug: p.slug,
    name: p.name,
    issuer_url: p.issuer_url,
    client_id: p.client_id,
    client_secret: "",
    scopes: p.scopes,
    enabled: p.enabled,
    allow_signup: p.allow_signup,
    link_by_email: p.link_by_email,
  }
  preset.value = p.issuer_url === "https://accounts.google.com" ? "google" : "custom"
  formError.value = null
  formOpen.value = true
}

function validate(): string | null {
  const slug = form.value.slug.trim().toLowerCase()
  if (!slugRe.test(slug) || slug.length > 64) return "slug must be lowercase alphanumeric with optional dashes (1-64 chars)"
  if (!form.value.name.trim()) return "name is required"
  let parsed: URL
  try { parsed = new URL(form.value.issuer_url.trim()) } catch { return "issuer_url must be a valid http(s) URL" }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "issuer_url scheme must be http or https"
  if (parsed.search || parsed.hash) return "issuer_url must not contain a query or fragment"
  if (!form.value.client_id.trim()) return "client_id is required"
  if (formMode.value === "create" && !form.value.client_secret?.trim()) return "client_secret is required"
  const scopes = form.value.scopes.trim() || "openid email profile"
  if (!scopes.split(/\s+/).includes("openid")) return "scopes must include openid"
  return null
}

async function submit() {
  const msg = validate()
  if (msg) { formError.value = msg; return }
  submitting.value = true
  formError.value = null
  try {
    const payload: SSOProviderPayload = {
      slug: form.value.slug.trim().toLowerCase(),
      name: form.value.name.trim(),
      issuer_url: form.value.issuer_url.trim().replace(/\/+$/, ""),
      client_id: form.value.client_id.trim(),
      scopes: (form.value.scopes.trim() || "openid email profile"),
      enabled: form.value.enabled,
      allow_signup: form.value.allow_signup,
      link_by_email: form.value.link_by_email,
    }
    const secret = form.value.client_secret?.trim()
    if (secret) payload.client_secret = secret

    if (formMode.value === "create") {
      await api.createSSO(payload)
    } else if (editTargetId.value) {
      await api.updateSSO(editTargetId.value, payload)
    }
    formOpen.value = false
    resetForm()
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    formError.value = err?.data?.error ?? err?.message ?? "Failed to save provider"
  } finally {
    submitting.value = false
  }
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await api.deleteSSO(deleteTarget.value.id)
    deleteTarget.value = null
    await load()
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to delete provider"
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// sso</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">SSO providers</h2>
      </div>
      <Button class="h-9" @click="openCreate">
        <Plus class="size-4 mr-1.5" aria-hidden="true" /> Add provider
      </Button>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <div class="hairline rounded-lg overflow-hidden bg-card/40" :aria-busy="loading">
      <Table>
        <caption class="sr-only">Configured OIDC SSO providers</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Slug</TableHead>
            <TableHead>Issuer</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Provisioning</TableHead>
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
              no providers configured
            </TableCell>
          </TableRow>
          <TableRow v-for="p in items" :key="p.id">
            <TableCell>
              <div class="font-medium">{{ p.name }}</div>
            </TableCell>
            <TableCell class="font-mono text-xs">{{ p.slug }}</TableCell>
            <TableCell class="font-mono text-xs break-all">{{ p.issuer_url }}</TableCell>
            <TableCell>
              <Badge v-if="p.enabled" variant="secondary">enabled</Badge>
              <Badge v-else variant="outline">disabled</Badge>
            </TableCell>
            <TableCell>
              <div class="flex flex-col gap-0.5 text-[11px] font-mono text-muted-foreground">
                <span>{{ p.allow_signup ? "+ signup" : "no signup" }}</span>
                <span>{{ p.link_by_email ? "+ link by email" : "no email link" }}</span>
              </div>
            </TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :aria-label="`Edit provider ${p.name}`"
                @click="openEdit(p)"
              >
                <Pencil class="size-4" aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="size-8"
                :aria-label="`Delete provider ${p.name}`"
                @click="deleteTarget = p"
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

    <Dialog v-model:open="formOpen">
      <DialogContent class="max-w-xl">
        <DialogHeader>
          <DialogTitle>{{ formMode === "create" ? "Add SSO provider" : "Edit SSO provider" }}</DialogTitle>
          <DialogDescription>
            Any OIDC-compliant identity provider works (Google, Zitadel, Keycloak, Auth0, …).
            The redirect URI is <span class="font-mono">https://&lt;host&gt;/api/v1/oauth/&lt;slug&gt;/callback</span>,
            where <span class="font-mono">&lt;host&gt;</span> is whichever domain the user signs in from.
            Register a callback for every domain that fronts torii (the main UI plus each proxied service host).
          </DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label>Preset</Label>
            <div class="flex gap-2">
              <Button
                type="button"
                :variant="preset === 'google' ? 'default' : 'outline'"
                size="sm"
                @click="applyPreset('google')"
              >Google</Button>
              <Button
                type="button"
                :variant="preset === 'custom' ? 'default' : 'outline'"
                size="sm"
                @click="applyPreset('custom')"
              >Custom OIDC</Button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="sso-slug">Slug</Label>
              <Input id="sso-slug" v-model="form.slug" placeholder="google" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="sso-name">Display name</Label>
              <Input id="sso-name" v-model="form.name" placeholder="Google" />
            </div>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-issuer">Issuer URL</Label>
            <Input id="sso-issuer" v-model="form.issuer_url" placeholder="https://accounts.google.com" />
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="sso-cid">Client ID</Label>
              <Input id="sso-cid" v-model="form.client_id" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="sso-csecret">
                Client secret
                <span v-if="formMode === 'edit'" class="text-muted-foreground font-normal">(blank to keep current)</span>
              </Label>
              <Input id="sso-csecret" v-model="form.client_secret" type="password" autocomplete="new-password" />
            </div>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-scopes">Scopes</Label>
            <Input id="sso-scopes" v-model="form.scopes" placeholder="openid email profile" class="font-mono text-xs" />
          </div>

          <div class="flex flex-col gap-2">
            <label class="flex items-start gap-3 p-2 rounded hairline cursor-pointer">
              <Checkbox :model-value="form.enabled" @update:model-value="(v) => (form.enabled = !!v)" />
              <div class="flex-1 text-sm">
                <div class="font-medium">Enabled</div>
                <div class="text-xs text-muted-foreground">Show this provider on the sign-in page.</div>
              </div>
            </label>
            <label class="flex items-start gap-3 p-2 rounded hairline cursor-pointer">
              <Checkbox :model-value="form.link_by_email" @update:model-value="(v) => (form.link_by_email = !!v)" />
              <div class="flex-1 text-sm">
                <div class="font-medium">Link by verified email</div>
                <div class="text-xs text-muted-foreground">If a torii user already exists with the same email and the IdP confirms <code>email_verified</code>, attach this identity to that user.</div>
              </div>
            </label>
            <label class="flex items-start gap-3 p-2 rounded hairline cursor-pointer">
              <Checkbox :model-value="form.allow_signup" @update:model-value="(v) => (form.allow_signup = !!v)" />
              <div class="flex-1 text-sm">
                <div class="font-medium">Auto-provision new users</div>
                <div class="text-xs text-muted-foreground">If no match is found, create a new torii user from the OIDC profile.</div>
              </div>
            </label>
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
          <DialogTitle>Delete provider?</DialogTitle>
          <DialogDescription>
            Removes the
            <span class="font-mono">{{ deleteTarget?.slug }}</span>
            provider and all linked identities. Users provisioned through this IdP keep their accounts but lose this login method.
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
