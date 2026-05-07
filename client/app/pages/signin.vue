<script setup lang="ts">
import { LogIn } from "lucide-vue-next"

definePageMeta({ middleware: "guest" })

useHead({ title: "Sign in — sanmon" })

const { signin } = useAuth()

const identifier = ref("")
const password = ref("")
const error = ref<string | null>(null)
const loading = ref(false)

async function onSubmit() {
  error.value = null
  if (!identifier.value.trim() || !password.value) {
    error.value = "Enter your username/email and password."
    return
  }
  loading.value = true
  try {
    await signin(identifier.value.trim(), password.value)
    await navigateTo("/dashboard")
  } catch (err: unknown) {
    const e = err as { data?: { error?: string }; message?: string }
    error.value = e?.data?.error ?? e?.message ?? "Sign in failed"
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
          <LogIn class="size-4 text-primary" aria-hidden="true" />
          <span class="text-mono-label">// signin</span>
        </div>
        <h1 class="sr-only">Sign in to sanmon</h1>
        <CardTitle class="text-2xl tracking-tight">Welcome back</CardTitle>
        <CardDescription>Sign in with your username or email.</CardDescription>
      </CardHeader>
      <CardContent>
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
