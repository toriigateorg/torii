<script setup lang="ts">
import { UserPlus } from "lucide-vue-next"

definePageMeta({ middleware: "guest" })

useHead({ title: "Sign up — torii" })

const { signup } = useAuth()

const signupEnabled = ref(true)
const configLoaded = ref(false)

onMounted(async () => {
  try {
    const cfg = await $fetch<{ signup_enabled: boolean }>("/api/v1/auth/config")
    signupEnabled.value = cfg.signup_enabled
  } catch {
    /* fall back to enabled; server still gates */
  } finally {
    configLoaded.value = true
  }
})

const username = ref("")
const email = ref("")
const firstName = ref("")
const lastName = ref("")
const password = ref("")
const confirm = ref("")
const error = ref<string | null>(null)
const loading = ref(false)

const isProd = !import.meta.dev

const specialChars = "!@#$%^&*()-_=+[]{};:,.<>/?\\|`~'\""

function validatePassword(pw: string): string | null {
  if (!isProd) {
    return pw.length === 0 ? "Password is required." : null
  }
  if (pw.length < 8) return "Password must be at least 8 characters."
  if (!/[A-Z]/.test(pw)) return "Password must include an uppercase letter."
  if (!/[a-z]/.test(pw)) return "Password must include a lowercase letter."
  if (!/\d/.test(pw)) return "Password must include a digit."
  let hasSpecial = false
  for (const ch of pw) if (specialChars.includes(ch)) hasSpecial = true
  if (!hasSpecial) return "Password must include a special character."
  return null
}

async function onSubmit() {
  error.value = null
  if (password.value !== confirm.value) {
    error.value = "Passwords do not match."
    return
  }
  const pwErr = validatePassword(password.value)
  if (pwErr) {
    error.value = pwErr
    return
  }
  loading.value = true
  try {
    await signup({
      username: username.value.trim(),
      email: email.value.trim(),
      password: password.value,
      first_name: firstName.value.trim(),
      last_name: lastName.value.trim(),
    })
    await navigateTo("/dashboard")
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    error.value = e?.data?.error ?? e?.message ?? "Sign up failed"
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-md px-4 sm:px-6 py-16 sm:py-24">
    <Card class="hairline">
      <CardHeader>
        <div class="flex items-center gap-2 mb-1">
          <UserPlus class="size-4 text-primary" aria-hidden="true" />
          <span class="text-mono-label">// signup</span>
        </div>
        <h1 class="sr-only">Create a torii account</h1>
        <CardTitle class="text-2xl tracking-tight">Create account</CardTitle>
        <CardDescription id="signup-pw-hint">
          {{ isProd
            ? "Use a strong password (8+ chars, upper, lower, digit, symbol)."
            : "Dev mode: any non-empty password works." }}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="configLoaded && !signupEnabled" class="flex flex-col gap-4">
          <Alert>
            <AlertDescription>
              New account sign-ups are currently disabled. If you already have an account you can
              still sign in.
            </AlertDescription>
          </Alert>
          <NuxtLink to="/signin" class="text-sm text-foreground underline underline-offset-4 hover:text-primary">
            Go to sign in
          </NuxtLink>
        </div>
        <form v-else class="flex flex-col gap-4" novalidate aria-describedby="signup-error" @submit.prevent="onSubmit">
          <div class="flex flex-col gap-1.5">
            <Label for="username">Username</Label>
            <Input id="username" v-model="username" autocomplete="username" autofocus />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="email">Email</Label>
            <Input id="email" v-model="email" type="email" autocomplete="email" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="first_name">First name</Label>
              <Input id="first_name" v-model="firstName" autocomplete="given-name" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="last_name">Last name</Label>
              <Input id="last_name" v-model="lastName" autocomplete="family-name" />
            </div>
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="password">Password</Label>
            <Input
              id="password"
              v-model="password"
              type="password"
              autocomplete="new-password"
              required
              :aria-invalid="error ? 'true' : undefined"
              aria-describedby="signup-pw-hint signup-error"
            />
          </div>
          <div class="flex flex-col gap-1.5">
            <Label for="confirm">Confirm password</Label>
            <Input
              id="confirm"
              v-model="confirm"
              type="password"
              autocomplete="new-password"
              required
              :aria-invalid="error ? 'true' : undefined"
              aria-describedby="signup-error"
            />
          </div>
          <p
            id="signup-error"
            class="text-sm text-destructive min-h-[1.25rem]"
            role="alert"
            aria-live="assertive"
          >{{ error || '' }}</p>
          <Button type="submit" class="w-full" :disabled="loading" :aria-busy="loading">
            {{ loading ? "Creating..." : "Create account" }}
          </Button>
        </form>
        <p v-if="signupEnabled" class="mt-6 text-sm text-muted-foreground">
          Already have an account?
          <NuxtLink to="/signin" class="text-foreground underline underline-offset-4 hover:text-primary">
            Sign in
          </NuxtLink>
        </p>
      </CardContent>
    </Card>
  </div>
</template>
