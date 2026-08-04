<script setup lang="ts">
definePageMeta({ middleware: "guest" })

useSeoMeta({
  title: "Sign in — torii",
  description: "Sign in to your torii instance.",
  robots: "noindex, follow",
})

const { signin } = useAuth()
const route = useRoute()

interface PublicProvider { slug: string; name: string }

const logo = publicAsset("torii-logo.svg")

const identifier = ref("")
const password = ref("")
const error = ref<string | null>(null)
const loading = ref(false)
const providers = ref<PublicProvider[]>([])
const signupEnabled = ref(true)

const ssoErrorMessages: Record<string, string> = {
  sso_no_account: "No matching torii account for that identity.",
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
  sso_invalid_email: "Provider shared an email address torii cannot accept.",
  sso_email_taken: "An account already uses that email address. Sign in with it, or ask an administrator to link the identity.",
  sso_username_unavailable: "Could not allocate a username for this account. Ask an administrator to create it.",
}

onMounted(async () => {
  const code = route.query.error
  if (typeof code === "string" && ssoErrorMessages[code]) {
    error.value = ssoErrorMessages[code]
  }
  try {
    const cfg = await $fetch<{ providers: PublicProvider[]; signup_enabled: boolean }>("/_torii/api/v1/auth/config")
    providers.value = cfg.providers ?? []
    signupEnabled.value = cfg.signup_enabled
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
    const to = safeRelativePath(route.query.to)
    // return_to_host / handoff_cnf are put on this page's URL by the Go dispatch
    // when it redirected an unauthenticated navigation on a proxied host here.
    // Passing them back lets the server mint a single-use handoff token so the
    // session materialises on that host — the sign-in form itself never leaves the
    // control plane, so no upstream origin ever hosts it.
    const handoffUrl = await signin(identifier.value.trim(), password.value, {
      returnToHost: typeof route.query.return_to_host === "string" ? route.query.return_to_host : undefined,
      handoffCnf: typeof route.query.handoff_cnf === "string" ? route.query.handoff_cnf : undefined,
      returnTo: to,
    })
    if (handoffUrl) {
      window.location.assign(handoffUrl)
      return
    }
    await navigateTo(to !== "/" ? to : "/dashboard")
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    error.value = e?.data?.error ?? e?.message ?? "Sign in failed"
  } finally {
    loading.value = false
  }
}

function ssoSignin(slug: string) {
  // Forward the cross-host return leg the dispatch put on this page's URL. Since
  // this page only ever renders on the control plane, oauthStart's own service-host
  // bounce can't fire from here — without these the correlator dispatch already
  // minted would be dropped and the user would land on the dashboard instead of
  // back on the service they came from. The server ignores return_to_host unless
  // handoff_cnf accompanies it, so they must travel together.
  const params = new URLSearchParams()
  const rh = route.query.return_to_host
  const cnf = route.query.handoff_cnf
  if (typeof rh === "string" && typeof cnf === "string" && rh && cnf) {
    params.set("return_to_host", rh)
    params.set("handoff_cnf", cnf)
  }
  const qs = params.toString()
  window.location.assign(`/_torii/api/v1/oauth/${slug}/start${qs ? `?${qs}` : ""}`)
}
</script>

<template>
  <div class="mx-auto max-w-md px-4 sm:px-6 py-16 sm:py-24">
    <Card class="hairline">
      <CardHeader>
        <div class="flex items-center gap-2 mb-1">
          <img :src="logo" alt="" aria-hidden="true" width="20" height="20" class="size-5" />
          <span class="text-mono-label">// signin</span>
        </div>
        <h1 class="sr-only">Sign in to torii</h1>
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
        <p v-if="signupEnabled" class="mt-6 text-sm text-muted-foreground">
          New here?
          <NuxtLink to="/signup" class="text-foreground underline underline-offset-4 hover:text-primary">
            Create an account
          </NuxtLink>
        </p>
      </CardContent>
    </Card>
  </div>
</template>
