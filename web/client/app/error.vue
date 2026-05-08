<script setup lang="ts">
import { ShieldOff, ArrowRight, Home, LayoutDashboard, ServerCrash } from "lucide-vue-next"
import type { NuxtError } from "#app"

const props = defineProps<{ error: NuxtError }>()

const code = computed(() => props.error.statusCode || 500)

const isUnknownDomain = computed(() =>
  code.value === 404 && (props.error.statusMessage?.includes("No service configured") ?? false),
)

const label = computed(() => {
  if (isUnknownDomain.value) return "no service bound"
  if (code.value === 401) return "unauthorized"
  if (code.value === 403) return "forbidden"
  if (code.value === 404) return "not found"
  return "unexpected error"
})

const title = computed(() => {
  if (isUnknownDomain.value) return "This domain isn't routed yet"
  if (code.value === 401) return "Unauthorized"
  if (code.value === 403) return "Forbidden"
  if (code.value === 404) return "Not found"
  return "Something went wrong"
})

const host = computed(() => (import.meta.client ? window.location.host : ""))

const detail = computed(() => {
  if (isUnknownDomain.value) {
    return "An administrator hasn't connected a service to this hostname. You're authenticated with torii — head back to the dashboard or sign in elsewhere."
  }
  if (code.value === 401) {
    return "You don't have access to this page. Sign in with an admin account, or head back home."
  }
  return props.error.statusMessage || "An unexpected error occurred."
})

function goDashboard() {
  const toriiHost = useRuntimeConfig().public.toriiUrl
  if (import.meta.client && toriiHost && window.location.host !== toriiHost) {
    window.location.assign(`${window.location.protocol}//${toriiHost}/dashboard`)
    return
  }
  clearError({ redirect: "/dashboard" })
}
function goHome() {
  const toriiHost = useRuntimeConfig().public.toriiUrl
  if (import.meta.client && toriiHost && window.location.host !== toriiHost) {
    window.location.assign(`${window.location.protocol}//${toriiHost}/`)
    return
  }
  clearError({ redirect: "/" })
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
          <!-- Console card -->
          <div class="hairline rounded-xl bg-card/60 backdrop-blur-sm overflow-hidden shadow-2xl shadow-primary/5">
            <!-- Header strip -->
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
                status {{ code }}
              </span>
            </div>

            <div class="p-7 sm:p-10 lg:p-14">
              <div class="flex items-start gap-5 sm:gap-6">
                <div
                  aria-hidden="true"
                  class="hidden sm:inline-flex shrink-0 items-center justify-center size-12 hairline rounded-lg bg-background"
                >
                  <component
                    :is="isUnknownDomain ? ServerCrash : ShieldOff"
                    class="size-5 text-primary"
                  />
                </div>
                <div class="flex-1 min-w-0">
                  <p class="text-mono-label mb-3">// {{ label }}</p>
                  <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight leading-tight mb-4">
                    {{ title }}
                  </h1>
                  <p class="text-muted-foreground leading-relaxed max-w-xl">
                    {{ detail }}
                  </p>

                  <div v-if="isUnknownDomain && host" class="mt-6 hairline rounded-md bg-muted/30 px-3 py-2.5 inline-block max-w-full">
                    <span class="text-mono-label mr-2">host</span>
                    <span class="font-mono text-xs sm:text-sm text-foreground break-all">{{ host }}</span>
                  </div>
                </div>
              </div>

              <div class="mt-9 flex flex-col sm:flex-row gap-3">
                <Button class="group h-11 px-5" @click="goDashboard">
                  <LayoutDashboard class="size-4 mr-2" aria-hidden="true" />
                  Go to dashboard
                  <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" aria-hidden="true" />
                </Button>
                <Button variant="outline" class="h-11 px-5 hairline" @click="goHome">
                  <Home class="size-4 mr-2" aria-hidden="true" />
                  Home
                </Button>
              </div>
            </div>

            <!-- Footer trace -->
            <div class="border-t border-border/60 px-5 sm:px-6 py-3.5 bg-muted/10 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <span>fig.err · {{ code }}</span>
              <span class="hidden sm:inline">torii edge</span>
            </div>
        </div>
      </div>
    </section>
  </NuxtLayout>
</template>
