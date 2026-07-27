<script setup lang="ts">
import { Loader2 } from "lucide-vue-next"

useSeoMeta({
  title: "Signing in — torii",
  description: "Completing sign-in on this service.",
  robots: "noindex, nofollow",
})

const failed = ref(false)

onMounted(async () => {
  const raw = window.location.hash.replace(/^#/, "")
  const token = new URLSearchParams(raw).get("token")
  // Clear the fragment before doing anything else: the token mints a session
  // on this host, and the page hard-navigates into the upstream next.
  history.replaceState(null, "", window.location.pathname)
  if (!token) {
    failed.value = true
    return
  }
  try {
    await $fetch("/_torii/api/v1/sso_handoff", {
      method: "POST",
      body: { token },
      credentials: "include",
    })
  } catch {
    failed.value = true
    return
  }
  // Hard load so the Go dispatch re-evaluates with the new cookies in place.
  window.location.assign("/")
})

function backToSignin() {
  window.location.assign("/_torii/signin")
}
</script>

<template>
  <div class="mx-auto max-w-md px-4 sm:px-6 py-16 sm:py-24">
    <Card class="hairline">
      <CardHeader>
        <span class="text-mono-label">// handoff</span>
        <CardTitle class="text-xl tracking-tight">
          {{ failed ? "Sign-in could not be completed" : "Finishing sign-in" }}
        </CardTitle>
        <CardDescription>
          {{
            failed
              ? "The sign-in link has already been used or has expired."
              : "Setting up your session on this service."
          }}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="!failed" class="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 class="size-4 animate-spin" aria-hidden="true" />
          <span role="status">One moment...</span>
        </div>
        <Button v-else class="w-full" @click="backToSignin">
          Back to sign in
        </Button>
      </CardContent>
    </Card>
  </div>
</template>
