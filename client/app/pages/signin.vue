<script setup lang="ts">
definePageMeta({ middleware: "guest" })

useHead({ title: "Sign in — sanmon" })

const { signin } = useAuth()
const route = useRoute()

interface PublicProvider { slug: string; name: string }

const identifier = ref("")
const password = ref("")
const error = ref<string | null>(null)
const loading = ref(false)
const providers = ref<PublicProvider[]>([])

const ssoErrorMessages: Record<string, string> = {
  sso_no_account: "No matching sanmon account for that identity.",
  sso_no_email: "Provider did not share an email address.",
  sso_state: "Sign-in session expired. Please try again.",
  sso_denied: "Sign-in was cancelled at the provider.",
  sso_unknown: "That SSO provider is no longer available.",
  sso_discovery: "Could not reach the SSO provider.",
  sso_exchange: "SSO token exchange failed.",
  sso_verify: "SSO token could not be verified.",
  sso_no_id_token: "Provider did not return an id_token.",
  sso_claims: "Provider response was missing required claims.",
  sso_internal: "Something went wrong during SSO sign-in.",
}

onMounted(async () => {
  const code = route.query.error
  if (typeof code === "string" && ssoErrorMessages[code]) {
    error.value = ssoErrorMessages[code]
  }
  try {
    const res = await $fetch<{ items: PublicProvider[] }>("/api/v1/auth/providers")
    providers.value = res.items ?? []
  } catch {
    providers.value = []
  }
})

async function onSubmit() {
  error.value = null
  if (!identifier.value.trim() || !password.value) {
    error.value = "Enter your username/email and password."
    return
  }
  loading.value = true
  try {
    await signin(identifier.value.trim(), password.value)
    const expected = useRuntimeConfig().public.sanmonUrl
    if (expected && window.location.host !== expected) {
      window.location.assign("/")
      return
    }
    await navigateTo("/dashboard")
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    error.value = e?.data?.error ?? e?.message ?? "Sign in failed"
  } finally {
    loading.value = false
  }
}

function ssoSignin(slug: string) {
  const sanmonHost = useRuntimeConfig().public.sanmonUrl
  if (sanmonHost && window.location.host !== sanmonHost) {
    window.location.assign(`${window.location.protocol}//${sanmonHost}/api/v1/oauth/${slug}/start`)
    return
  }
  window.location.assign(`/api/v1/oauth/${slug}/start`)
}
</script>

<template>
  <div class="mx-auto max-w-md px-4 sm:px-6 py-16 sm:py-24">
    <Card class="hairline">
      <CardHeader>
        <div class="flex items-center gap-2 mb-1">
          <img src="/sanmon-logo.svg" alt="" aria-hidden="true" width="20" height="20" class="size-5" />
          <span class="text-mono-label">// signin</span>
        </div>
        <h1 class="sr-only">Sign in to sanmon</h1>
        <CardTitle class="text-2xl tracking-tight">Welcome back</CardTitle>
        <CardDescription>Sign in with your username or email.</CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="providers.length" class="flex flex-col gap-2 mb-6">
          <Button
            v-for="p in providers"
            :key="p.slug"
            type="button"
            variant="outline"
            class="w-full"
            @click="ssoSignin(p.slug)"
          >
            Sign in with {{ p.name }}
          </Button>
          <div class="relative my-2">
            <div class="absolute inset-0 flex items-center" aria-hidden="true">
              <span class="w-full border-t border-border" />
            </div>
            <div class="relative flex justify-center text-xs uppercase">
              <span class="bg-card px-2 text-muted-foreground font-mono">or</span>
            </div>
          </div>
        </div>

        <form class="flex flex-col gap-4" novalidate aria-describedby="signin-error" @submit.prevent="onSubmit">
          <div class="flex flex-col gap-1.5">
            <Label for="identifier">Username or email</Label>
            <Input
              id="identifier"
              v-model="identifier"
              autocomplete="username"
              autofocus
              required
              :aria-invalid="error ? 'true' : undefined"
              aria-describedby="signin-error"
            />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="password">Password</Label>
            <Input
              id="password"
              v-model="password"
              type="password"
              autocomplete="current-password"
              required
              :aria-invalid="error ? 'true' : undefined"
              aria-describedby="signin-error"
            />
          </div>
          <p
            id="signin-error"
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ error || '' }}</p>
          <Button type="submit" class="w-full" :disabled="loading" :aria-busy="loading">
            {{ loading ? "Signing in..." : "Sign in" }}
          </Button>
        </form>
        <p class="mt-6 text-sm text-muted-foreground">
          New here?
          <NuxtLink to="/signup" class="text-foreground underline underline-offset-4 hover:text-primary">
            Create an account
          </NuxtLink>
        </p>
      </CardContent>
    </Card>
  </div>
</template>
