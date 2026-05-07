<script setup lang="ts">
definePageMeta({ middleware: ["auth", "admin"] })
useHead({ title: "Admin · Settings — sanmon" })

const api = useAdminApi()

const signupEnabled = ref(true)
const loading = ref(false)
const saving = ref(false)
const error = ref<string | null>(null)
const savedAt = ref<number | null>(null)

async function load() {
  loading.value = true
  error.value = null
  try {
    const s = await api.getSettings()
    signupEnabled.value = s.signup_enabled
  } catch (e: unknown) {
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to load settings"
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function toggleSignup(next: boolean) {
  const prev = signupEnabled.value
  signupEnabled.value = next
  saving.value = true
  error.value = null
  try {
    const s = await api.updateSettings({ signup_enabled: next })
    signupEnabled.value = s.signup_enabled
    savedAt.value = Date.now()
  } catch (e: unknown) {
    signupEnabled.value = prev
    const err = e as { data?: { error?: string }; message?: string }
    error.value = err?.data?.error ?? err?.message ?? "Failed to save"
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <AdminShell>
    <div class="flex items-center justify-between gap-4 flex-wrap mb-6">
      <div>
        <p class="text-mono-label">// settings</p>
        <h2 class="text-xl font-semibold tracking-tight mt-1">Settings</h2>
      </div>
      <p v-if="savedAt" class="text-xs text-muted-foreground font-mono" aria-live="polite">saved</p>
    </div>

    <Alert v-if="error" variant="destructive" class="mb-4">
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <Card class="hairline" :aria-busy="loading || saving">
      <CardHeader>
        <CardTitle class="text-base">Account creation</CardTitle>
        <CardDescription>
          Controls who can register a sanmon account through the public sign-up form. Disabling
          this does not affect SSO provisioning (each SSO provider has its own
          <span class="font-mono">allow_signup</span> toggle) and does not affect admin-created users.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <label class="flex items-start gap-3 p-3 rounded hairline cursor-pointer">
          <Checkbox
            :model-value="signupEnabled"
            :disabled="loading || saving"
            @update:model-value="(v) => toggleSignup(!!v)"
          />
          <div class="flex-1 text-sm">
            <div class="font-medium">Allow public email/password sign-ups</div>
            <div class="text-xs text-muted-foreground">
              When off, <span class="font-mono">/signup</span> returns 403 and the page hides the form.
              Existing users keep their accounts and can still sign in.
            </div>
          </div>
        </label>
      </CardContent>
    </Card>
  </AdminShell>
</template>
