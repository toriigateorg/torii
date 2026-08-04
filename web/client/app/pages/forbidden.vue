<script setup lang="ts">
import { ShieldOff, ArrowRight, LayoutDashboard, LogOut } from "lucide-vue-next"

useSeoMeta({
  title: "Access denied — torii",
  description: "You don't have access to this service.",
  robots: "noindex, follow",
})

const route = useRoute()
const { signout } = useAuth()

// The query value is attacker-supplied — this page is served on the upstream's
// origin and anyone can link to it with any ?service= — and it is rendered into
// the page body. Vue escapes it, so it is text rather than markup, but text
// under torii's branding on a host the visitor already trusts is still a
// serviceable phishing surface. Clamp it to the shape a real service title has
// and to a length that cannot carry a sentence.
const serviceTitleRe = /^[\w .,'()&-]{1,64}$/

const service = computed(() => {
  const s = route.query.service
  if (typeof s !== "string") return ""
  const trimmed = s.trim()
  return serviceTitleRe.test(trimmed) ? trimmed : ""
})

const host = computed(() => (import.meta.client ? window.location.host : ""))

const detail = computed(() =>
  service.value
    ? `You're signed in, but your account doesn't have a role that grants access to ${service.value}. Ask an administrator to grant you a role for this service.`
    : "You're signed in, but your account doesn't have a role that grants access to this service. Ask an administrator to grant you a role for it.",
)

function goTorii() {
  const toriiHost = useToriiUrl()
  if (import.meta.client && toriiHost && window.location.host !== toriiHost) {
    window.location.assign(`${window.location.protocol}//${toriiHost}/_torii/dashboard`)
    return
  }
  void navigateTo("/dashboard")
}

async function switchAccount() {
  await signout()
  // Sign-in happens on the control plane — the form is never served on a service
  // origin — and the session comes back here through the handoff leg. Passing
  // return_to_host would need a correlator this page cannot mint (it must be set
  // by a server response on this host), so the user is sent to sign in and can
  // navigate back; the dispatch will then run the correlated flow.
  if (import.meta.client) {
    const toriiHost = useToriiUrl()
    if (toriiHost && window.location.host !== toriiHost) {
      window.location.assign(`${window.location.protocol}//${toriiHost}/_torii/signin`)
      return
    }
    window.location.assign("/_torii/signin")
    return
  }
  void navigateTo("/signin")
}
</script>

<template>
  <NuxtLayout name="default">
    <section class="relative overflow-hidden">
      <div aria-hidden="true" class="absolute inset-0 grid-bg pointer-events-none" />
      <div
        aria-hidden="true"
        class="absolute -top-32 left-1/2 -translate-x-1/2 size-[700px] glow-blob float-slow pointer-events-none opacity-60"
      />

      <div class="relative mx-auto max-w-3xl px-4 sm:px-6 lg:px-8 py-12 sm:py-16 lg:py-20">
        <div class="hairline rounded-xl bg-card/60 backdrop-blur-sm overflow-hidden shadow-2xl shadow-primary/5">
          <div class="flex items-center justify-between px-5 py-3 border-b border-border/60 bg-muted/30">
            <div class="flex items-center gap-3">
              <div class="flex items-center gap-1.5">
                <span class="size-2 rounded-full bg-foreground/15" />
                <span class="size-2 rounded-full bg-foreground/15" />
                <span class="size-2 rounded-full bg-foreground/15" />
              </div>
              <span class="ml-2 size-1.5 rounded-full bg-amber-500" />
              <span class="font-mono text-[10px] tracking-[0.2em] uppercase text-muted-foreground">
                edge · response
              </span>
            </div>
            <span class="hidden sm:inline font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              status 403
            </span>
          </div>

          <div class="p-7 sm:p-10 lg:p-14">
            <div class="flex items-start gap-5 sm:gap-6">
              <div
                aria-hidden="true"
                class="hidden sm:inline-flex shrink-0 items-center justify-center size-12 hairline rounded-lg bg-background"
              >
                <ShieldOff class="size-5 text-primary" />
              </div>
              <div class="flex-1 min-w-0">
                <p class="text-mono-label mb-3">// forbidden</p>
                <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight leading-tight mb-4">
                  You don't have access to this service
                </h1>
                <p class="text-muted-foreground leading-relaxed max-w-xl">
                  {{ detail }}
                </p>

                <div v-if="host" class="mt-6 hairline rounded-md bg-muted/30 px-3 py-2.5 inline-block max-w-full">
                  <span class="text-mono-label mr-2">host</span>
                  <span class="font-mono text-xs sm:text-sm text-foreground break-all">{{ host }}</span>
                </div>
              </div>
            </div>

            <div class="mt-9 flex flex-col sm:flex-row gap-3">
              <Button class="group h-11 px-5" @click="goTorii">
                <LayoutDashboard class="size-4 mr-2" aria-hidden="true" />
                Go to torii
                <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" aria-hidden="true" />
              </Button>
              <Button variant="outline" class="h-11 px-5 hairline" @click="switchAccount">
                <LogOut class="size-4 mr-2" aria-hidden="true" />
                Sign out / switch account
              </Button>
            </div>
          </div>

          <div class="border-t border-border/60 px-5 sm:px-6 py-3.5 bg-muted/10 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <span>fig.err · 403</span>
            <span class="hidden sm:inline">torii edge</span>
          </div>
        </div>
      </div>
    </section>
  </NuxtLayout>
</template>
