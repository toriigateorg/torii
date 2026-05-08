<script setup lang="ts">
import {
  ShieldCheck,
  Network,
  KeyRound,
  Activity,
  ArrowRight,
  Terminal,
  Lock,
  Fingerprint,
  Workflow,
  ChevronRight,
} from "lucide-vue-next"

useSeoMeta({
  title: "torii — identity-aware reverse proxy",
  description: "Open-source zero trust gateway. Self-host a single Go binary at your edge for SSO, RBAC, and HTTP-aware reverse proxying — no SDK rewrites in your services.",
  ogTitle: "torii — identity-aware reverse proxy",
  ogDescription: "Open-source zero trust gateway. Self-host SSO, RBAC, and reverse proxy as one Go binary.",
  twitterTitle: "torii — identity-aware reverse proxy",
  twitterDescription: "Open-source zero trust gateway. Self-host SSO, RBAC, and reverse proxy as one Go binary.",
})

useHead({
  meta: [
    { name: "keywords", content: "identity-aware reverse proxy, zero trust gateway, open source SSO, RBAC proxy, auth gateway, self-hosted authentication, OIDC proxy, SAML proxy" },
  ],
})

const features = [
  {
    no: "01",
    label: "IDENTITY",
    title: "Single sign-on, everywhere",
    body: "Bring OIDC, SAML, or your own provider. torii terminates auth at the edge so your services never see a raw request.",
    icon: Fingerprint,
  },
  {
    no: "02",
    label: "POLICY",
    title: "RBAC as configuration",
    body: "Declare who can reach what in plain YAML. Policies compile to a deterministic decision graph evaluated per request.",
    icon: ShieldCheck,
  },
  {
    no: "03",
    label: "ROUTING",
    title: "HTTP-aware reverse proxy",
    body: "Path, host, and header-based routing with health-checked upstreams. WebSocket and SSE pass through cleanly.",
    icon: Network,
  },
  {
    no: "04",
    label: "AUDIT",
    title: "Every request, accounted for",
    body: "Structured access logs with subject, claim, and decision. Stream to your SIEM or query in place.",
    icon: Activity,
  },
]

const stats = [
  { value: "< 0.4ms", label: "policy eval" },
  { value: "10k+", label: "rps per node" },
  { value: "OIDC · SAML", label: "providers" },
  { value: "single binary", label: "deploy" },
]

type TraceSample = {
  method: string
  path: string
  subject: string
  provider: string
  policy: string
  upstream: string
  latency: string
  trace: string
}
const traceSamples: TraceSample[] = [
  { method: "GET", path: "/admin/users", subject: "alice@acme.com", provider: "oidc/google", policy: "#02 role:admin", upstream: "api.internal:8080", latency: "1.2ms", trace: "8f2a" },
  { method: "POST", path: "/api/orders", subject: "bob@acme.com", provider: "oidc/zitadel", policy: "#05 authenticated", upstream: "api.internal:8080", latency: "0.9ms", trace: "c41e" },
  { method: "GET", path: "/dash/ovw", subject: "carol@acme.com", provider: "oidc/keycloak", policy: "#01 any", upstream: "grafana.internal:3000", latency: "2.4ms", trace: "7d33" },
  { method: "DELETE", path: "/api/keys/9f", subject: "dan@acme.com", provider: "oidc/auth0", policy: "#03 role:ops", upstream: "api.internal:8080", latency: "1.7ms", trace: "1b09" },
]
const traceIndex = ref(0)
const currentTrace = computed(() => traceSamples[traceIndex.value]!)
let traceTimer: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  traceTimer = setInterval(() => {
    traceIndex.value = (traceIndex.value + 1) % traceSamples.length
  }, 3200)
})
onBeforeUnmount(() => {
  if (traceTimer) clearInterval(traceTimer)
})
</script>

<template>
  <div class="relative">
    <!-- Hero -->
    <section class="relative overflow-hidden" aria-labelledby="hero-title">
      <div aria-hidden="true" class="absolute inset-0 grid-bg pointer-events-none" />
      <div aria-hidden="true" class="absolute -top-24 left-1/2 -translate-x-1/2 size-[700px] glow-blob float-slow pointer-events-none opacity-70" />

      <div class="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 pt-16 sm:pt-24 lg:pt-32 pb-20 lg:pb-28">
        <div class="grid lg:grid-cols-12 gap-10 lg:gap-12 items-center">
          <div class="lg:col-span-7">
            <div class="inline-flex items-center gap-2 hairline rounded-full px-3 py-1 mb-8 bg-background/40 backdrop-blur">
              <span class="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span class="font-mono text-[11px] tracking-wider uppercase text-muted-foreground">
                v0.1 — early access
              </span>
            </div>

            <p class="text-mono-label mb-5">// open-source identity-aware reverse proxy</p>

            <h1 id="hero-title" class="text-4xl sm:text-5xl lg:text-7xl font-semibold tracking-tight leading-[0.95]">
              The edge between
              <span class="block mt-2">
                <span class="text-muted-foreground/70">your users</span>
                <ChevronRight aria-hidden="true" class="inline-block size-8 sm:size-10 lg:size-14 text-primary mx-1 -translate-y-1" />
                <span class="text-foreground">your services</span>
              </span>
            </h1>

            <p class="mt-7 text-base sm:text-lg text-muted-foreground max-w-xl leading-relaxed">
              torii terminates authentication, enforces RBAC, and routes traffic
              upstream &mdash; so your services can stop reimplementing the same
              middleware in five different languages.
            </p>

            <div class="mt-9 flex flex-col sm:flex-row gap-3">
              <Button size="lg" class="group h-11 px-5 font-medium">
                Get started
                <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" aria-hidden="true" />
              </Button>
              <Button variant="outline" size="lg" class="h-11 px-5 font-mono text-xs hairline">
                <Terminal class="size-3.5 mr-2" aria-hidden="true" />
                docker run torii/torii
              </Button>
            </div>

            <div class="mt-12 flex items-center gap-6 text-mono-label">
              <span class="flex items-center gap-1.5">
                <span class="size-1 rounded-full bg-foreground/40" /> single binary
              </span>
              <span class="flex items-center gap-1.5">
                <span class="size-1 rounded-full bg-foreground/40" /> mit licensed
              </span>
              <span class="hidden sm:flex items-center gap-1.5">
                <span class="size-1 rounded-full bg-foreground/40" /> postgres backed
              </span>
            </div>
          </div>

          <!-- Terminal block -->
          <div class="lg:col-span-5">
            <div class="relative">
              <div class="absolute -inset-px rounded-xl bg-gradient-to-br from-primary/20 via-transparent to-primary/10 blur-sm" />
              <div class="relative hairline rounded-xl bg-card/80 backdrop-blur shadow-2xl shadow-primary/5 overflow-hidden">
                <div class="flex items-center justify-between px-4 py-2.5 border-b border-border/60 bg-muted/40">
                  <div class="flex items-center gap-1.5">
                    <span class="size-2.5 rounded-full bg-foreground/15" />
                    <span class="size-2.5 rounded-full bg-foreground/15" />
                    <span class="size-2.5 rounded-full bg-foreground/15" />
                  </div>
                  <span class="font-mono text-[10px] tracking-wider uppercase text-muted-foreground">
                    torii.yaml
                  </span>
                </div>
                <pre class="font-mono text-[12.5px] leading-relaxed p-5 overflow-x-auto"><span class="text-muted-foreground"># route api.acme.com to internal service</span>
<span class="text-foreground">route</span><span class="text-muted-foreground">:</span> api.acme.com
<span class="text-foreground">upstream</span><span class="text-muted-foreground">:</span> http://api.internal:8080

<span class="text-foreground">auth</span><span class="text-muted-foreground">:</span>
  <span class="text-foreground">provider</span><span class="text-muted-foreground">:</span> oidc
  <span class="text-foreground">issuer</span><span class="text-muted-foreground">:</span> https://id.acme.com

<span class="text-foreground">policy</span><span class="text-muted-foreground">:</span>
  <span class="text-muted-foreground">-</span> <span class="text-foreground">match</span><span class="text-muted-foreground">:</span> { path: /admin/* }
    <span class="text-foreground">require</span><span class="text-muted-foreground">:</span> [role:admin]
  <span class="text-muted-foreground">-</span> <span class="text-foreground">match</span><span class="text-muted-foreground">:</span> { path: /api/* }
    <span class="text-foreground">require</span><span class="text-muted-foreground">:</span> [authenticated]<span class="caret"></span></pre>
                <div class="px-5 py-2.5 border-t border-border/60 bg-muted/30 flex items-center justify-between">
                  <span class="font-mono text-[10px] text-muted-foreground">23 lines · valid</span>
                  <span class="font-mono text-[10px] text-emerald-500 flex items-center gap-1.5">
                    <span class="size-1.5 rounded-full bg-emerald-500" /> compiled
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Stats strip -->
    <section class="border-y border-border/60 bg-muted/20" aria-label="Key metrics">
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-0 md:divide-x divide-border/60">
        <div
          v-for="(s, i) in stats"
          :key="i"
          class="md:px-8 first:md:pl-0 last:md:pr-0 flex flex-col"
        >
          <span class="font-mono text-2xl sm:text-3xl tracking-tight tabular-nums">{{ s.value }}</span>
          <span class="text-mono-label mt-2">{{ s.label }}</span>
        </div>
      </div>
    </section>

    <!-- Features -->
    <section id="features" aria-labelledby="features-title" class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <div class="max-w-2xl mb-14">
        <p class="text-mono-label mb-4">// what it does</p>
        <h2 id="features-title" class="text-3xl sm:text-4xl font-semibold tracking-tight">
          One binary at the edge,<br class="hidden sm:block" />
          four problems off your plate.
        </h2>
      </div>

      <div class="grid sm:grid-cols-2 gap-px bg-border/60 hairline rounded-xl overflow-hidden">
        <div
          v-for="f in features"
          :key="f.no"
          class="group p-7 sm:p-8 bg-card hover:bg-accent/40 transition-colors relative"
        >
          <div class="flex items-start justify-between mb-6">
            <div class="flex items-center gap-3">
              <span class="font-mono text-[11px] tracking-[0.18em] uppercase text-muted-foreground">
                {{ f.no }} / {{ f.label }}
              </span>
            </div>
            <component :is="f.icon" class="size-4 text-muted-foreground group-hover:text-primary transition-colors" aria-hidden="true" />
          </div>
          <h3 class="text-lg sm:text-xl font-semibold tracking-tight mb-2.5">
            {{ f.title }}
          </h3>
          <p class="text-sm text-muted-foreground leading-relaxed">
            {{ f.body }}
          </p>
        </div>
      </div>
    </section>

    <!-- Flow diagram -->
    <section id="flow" aria-labelledby="flow-title" class="border-t border-border/60 relative overflow-hidden">
      <div aria-hidden="true" class="absolute inset-0 grid-bg opacity-40 pointer-events-none" />
      <div aria-hidden="true" class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 size-[700px] glow-blob opacity-30 pointer-events-none" />

      <div class="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
        <div class="max-w-2xl mb-14">
          <p class="text-mono-label mb-4">// request lifecycle</p>
          <h2 id="flow-title" class="text-3xl sm:text-4xl font-semibold tracking-tight">
            Auth, policy, proxy &mdash; in that order.
          </h2>
          <p class="mt-5 text-muted-foreground leading-relaxed">
            Every request crosses three gates before it touches your service. No bypass, no half-checked paths. Watch one make the trip.
          </p>
        </div>

        <!-- Console frame -->
        <div class="hairline rounded-xl bg-card/60 backdrop-blur-sm overflow-hidden shadow-2xl shadow-primary/5">
          <!-- Header strip -->
          <div class="flex items-center justify-between px-5 py-3 border-b border-border/60 bg-muted/30">
            <div class="flex items-center gap-3">
              <div class="flex items-center gap-1.5">
                <span class="size-2 rounded-full bg-foreground/15" />
                <span class="size-2 rounded-full bg-foreground/15" />
                <span class="size-2 rounded-full bg-foreground/15" />
              </div>
              <span class="ml-2 size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span class="font-mono text-[10px] tracking-[0.2em] uppercase text-muted-foreground">live · request stream</span>
            </div>
            <div class="hidden md:flex items-center gap-5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <span><span class="text-foreground/60">region</span> lhr-1</span>
              <span><span class="text-foreground/60">node</span> proxy-3a</span>
              <span><span class="text-foreground/60">p50</span> 1.2ms</span>
            </div>
          </div>

          <!-- Diagram canvas -->
          <div class="relative px-3 sm:px-6 lg:px-10 py-8 sm:py-12">
            <svg
              viewBox="0 0 1000 380"
              role="img"
              aria-labelledby="flow-svg-title flow-svg-desc"
              class="w-full h-auto text-foreground select-none"
              preserveAspectRatio="xMidYMid meet"
            >
              <title id="flow-svg-title">Request lifecycle</title>
              <desc id="flow-svg-desc">A client sends a request that travels through torii's three gates — authn, authz, and route — before being proxied to one of three upstreams.</desc>

              <defs>
                <linearGradient id="wireGrad" x1="0" x2="1" y1="0" y2="0">
                  <stop offset="0" stop-color="currentColor" stop-opacity="0.05" />
                  <stop offset="0.5" stop-color="currentColor" stop-opacity="0.45" />
                  <stop offset="1" stop-color="currentColor" stop-opacity="0.05" />
                </linearGradient>
                <linearGradient id="spineGrad" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0" stop-color="currentColor" stop-opacity="0.04" />
                  <stop offset="1" stop-color="currentColor" stop-opacity="0.10" />
                </linearGradient>
                <radialGradient id="packetCore" cx="0.5" cy="0.5" r="0.5">
                  <stop offset="0" stop-color="oklch(0.85 0.15 220)" stop-opacity="1" />
                  <stop offset="0.6" stop-color="oklch(0.7 0.18 240)" stop-opacity="0.9" />
                  <stop offset="1" stop-color="oklch(0.7 0.18 240)" stop-opacity="0" />
                </radialGradient>
                <filter id="packetGlow" x="-200%" y="-200%" width="500%" height="500%">
                  <feGaussianBlur stdDeviation="3" />
                  <feComposite in2="SourceGraphic" operator="over" />
                </filter>

                <!-- Tickmark pattern for wires -->
                <pattern id="tickPattern" width="14" height="6" patternUnits="userSpaceOnUse">
                  <path d="M 0 3 H 4" stroke="currentColor" stroke-opacity="0.25" stroke-width="0.6" />
                </pattern>

                <!-- Packet journeys: client → spine → fan-out -->
                <path id="path-top" d="M 145 190 L 380 190 L 500 190 L 615 190 C 720 190 770 90 870 90" />
                <path id="path-mid" d="M 145 190 L 380 190 L 500 190 L 615 190 L 870 190" />
                <path id="path-bot" d="M 145 190 L 380 190 L 500 190 L 615 190 C 720 190 770 290 870 290" />
              </defs>

              <!-- ============ Wires (visible) ============ -->
              <!-- Client → spine -->
              <path d="M 145 190 L 380 190" stroke="url(#wireGrad)" stroke-width="1.2" fill="none" />
              <path d="M 145 190 L 380 190" stroke="url(#tickPattern)" stroke-width="1.2" fill="none" opacity="0.6" />
              <!-- Spine → fanout junction -->
              <path d="M 615 190 L 700 190" stroke="url(#wireGrad)" stroke-width="1.2" fill="none" />
              <!-- Fanout to three upstreams -->
              <path d="M 700 190 C 760 190 800 90 870 90" stroke="currentColor" stroke-opacity="0.18" stroke-width="1" fill="none" stroke-dasharray="2 4" />
              <path d="M 700 190 L 870 190" stroke="currentColor" stroke-opacity="0.25" stroke-width="1" fill="none" stroke-dasharray="2 4" />
              <path d="M 700 190 C 760 190 800 290 870 290" stroke="currentColor" stroke-opacity="0.18" stroke-width="1" fill="none" stroke-dasharray="2 4" />

              <!-- Junction node -->
              <circle cx="700" cy="190" r="3" fill="currentColor" opacity="0.4" />
              <circle cx="700" cy="190" r="6" fill="none" stroke="currentColor" stroke-opacity="0.2" />

              <!-- ============ CLIENT ============ -->
              <g>
                <rect x="20" y="158" width="125" height="64" rx="6" fill="var(--color-card)" stroke="currentColor" stroke-opacity="0.35" />
                <!-- corner ticks (blueprint style) -->
                <path d="M 20 158 H 26 M 20 158 V 164" stroke="currentColor" stroke-opacity="0.5" stroke-width="1" />
                <path d="M 145 158 H 139 M 145 158 V 164" stroke="currentColor" stroke-opacity="0.5" stroke-width="1" />
                <path d="M 20 222 H 26 M 20 222 V 216" stroke="currentColor" stroke-opacity="0.5" stroke-width="1" />
                <path d="M 145 222 H 139 M 145 222 V 216" stroke="currentColor" stroke-opacity="0.5" stroke-width="1" />

                <text x="32" y="178" font-family="var(--font-mono)" font-size="8.5" fill="currentColor" fill-opacity="0.5" letter-spacing="2">CLIENT</text>
                <text x="32" y="200" font-family="var(--font-mono)" font-size="11" fill="currentColor" font-weight="500">{{ currentTrace.method }} {{ currentTrace.path }}</text>
                <text x="32" y="214" font-family="var(--font-mono)" font-size="8.5" fill="currentColor" fill-opacity="0.45">{{ currentTrace.subject }}</text>

                <!-- terminal lights -->
                <circle cx="130" cy="167" r="1.6" fill="currentColor" opacity="0.25" />
                <circle cx="124" cy="167" r="1.6" fill="currentColor" opacity="0.25" />
              </g>

              <!-- Annotation under client -->
              <text x="82" y="246" text-anchor="middle" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.4" letter-spacing="2">cookie · bearer</text>

              <!-- ============ TORII SPINE ============ -->
              <g>
                <!-- Spine container -->
                <rect x="380" y="40" width="235" height="300" rx="10" fill="url(#spineGrad)" stroke="currentColor" stroke-opacity="0.35" />
                <!-- Dashed inner outline -->
                <rect x="386" y="46" width="223" height="288" rx="7" fill="none" stroke="currentColor" stroke-opacity="0.12" stroke-dasharray="1 3" />

                <!-- Spine header -->
                <text x="395" y="62" font-family="var(--font-mono)" font-size="8.5" fill="currentColor" fill-opacity="0.5" letter-spacing="2">TORII / EDGE</text>
                <circle cx="601" cy="58" r="2.5" fill="oklch(0.7 0.2 150)">
                  <animate attributeName="opacity" values="0.4;1;0.4" dur="1.6s" repeatCount="indefinite" />
                </circle>

                <!-- Divider under header -->
                <path d="M 386 72 H 609" stroke="currentColor" stroke-opacity="0.15" stroke-width="0.8" />

                <!-- Stage 01: AUTHN -->
                <g transform="translate(394 86)">
                  <rect width="207" height="64" rx="5" fill="none" stroke="currentColor" stroke-opacity="0.22" />
                  <!-- LED -->
                  <circle cx="14" cy="32" r="4" fill="oklch(0.5 0.05 150)" class="led led-1" />
                  <circle cx="14" cy="32" r="9" fill="none" stroke="oklch(0.7 0.2 150)" stroke-opacity="0" class="led-ring led-ring-1" />
                  <!-- Number -->
                  <text x="32" y="22" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">01 / AUTHN</text>
                  <text x="32" y="40" font-family="var(--font-mono)" font-size="11.5" fill="currentColor" font-weight="500">verify identity</text>
                  <text x="32" y="54" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">oidc · saml · session</text>
                  <!-- Right icon area -->
                  <g transform="translate(178 22)" stroke="currentColor" stroke-opacity="0.5" fill="none" stroke-width="1.2">
                    <rect x="0" y="3" width="14" height="10" rx="1.5" />
                    <path d="M 3 3 V 0.5 a 4 4 0 0 1 8 0 V 3" />
                  </g>
                </g>

                <!-- internal connector authn → authz -->
                <path d="M 397 150 V 162" stroke="currentColor" stroke-opacity="0.4" stroke-width="1" />
                <circle cx="397" cy="156" r="1.6" fill="currentColor" fill-opacity="0.5" />

                <!-- Stage 02: AUTHZ -->
                <g transform="translate(394 162)">
                  <rect width="207" height="64" rx="5" fill="none" stroke="currentColor" stroke-opacity="0.22" />
                  <circle cx="14" cy="32" r="4" fill="oklch(0.5 0.05 150)" class="led led-2" />
                  <circle cx="14" cy="32" r="9" fill="none" stroke="oklch(0.7 0.2 150)" stroke-opacity="0" class="led-ring led-ring-2" />
                  <text x="32" y="22" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">02 / AUTHZ</text>
                  <text x="32" y="40" font-family="var(--font-mono)" font-size="11.5" fill="currentColor" font-weight="500">evaluate policy</text>
                  <text x="32" y="54" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">role · path · header</text>
                  <g transform="translate(178 22)" stroke="currentColor" stroke-opacity="0.5" fill="none" stroke-width="1.2">
                    <path d="M 7 0 L 14 4 V 11 a 7 8 0 0 1 -7 6 a 7 8 0 0 1 -7 -6 V 4 Z" />
                    <path d="M 4.5 9 L 6.5 11 L 10 7" />
                  </g>
                </g>

                <!-- internal connector authz → route -->
                <path d="M 397 226 V 238" stroke="currentColor" stroke-opacity="0.4" stroke-width="1" />
                <circle cx="397" cy="232" r="1.6" fill="currentColor" fill-opacity="0.5" />

                <!-- Stage 03: ROUTE -->
                <g transform="translate(394 238)">
                  <rect width="207" height="64" rx="5" fill="none" stroke="currentColor" stroke-opacity="0.22" />
                  <circle cx="14" cy="32" r="4" fill="oklch(0.5 0.05 150)" class="led led-3" />
                  <circle cx="14" cy="32" r="9" fill="none" stroke="oklch(0.7 0.2 150)" stroke-opacity="0" class="led-ring led-ring-3" />
                  <text x="32" y="22" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">03 / ROUTE</text>
                  <text x="32" y="40" font-family="var(--font-mono)" font-size="11.5" fill="currentColor" font-weight="500">forward upstream</text>
                  <text x="32" y="54" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">host · path · headers</text>
                  <g transform="translate(178 22)" stroke="currentColor" stroke-opacity="0.5" fill="none" stroke-width="1.2">
                    <path d="M 0 8 H 14 M 8 2 L 14 8 L 8 14" />
                  </g>
                </g>

                <!-- Spine footer label -->
                <text x="395" y="324" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.35" letter-spacing="2">{{ currentTrace.trace.toUpperCase() }} · {{ currentTrace.latency }}</text>
              </g>

              <!-- ============ UPSTREAMS ============ -->
              <g>
                <!-- top -->
                <g transform="translate(870 60)">
                  <rect width="115" height="58" rx="6" fill="var(--color-card)" stroke="currentColor" stroke-opacity="0.35" />
                  <text x="10" y="20" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">UPSTREAM</text>
                  <text x="10" y="36" font-family="var(--font-mono)" font-size="9.5" fill="currentColor">api.internal</text>
                  <text x="10" y="48" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">:8080 · go</text>
                  <circle cx="105" cy="11" r="2.5" fill="oklch(0.7 0.2 150)">
                    <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />
                  </circle>
                </g>
                <!-- middle -->
                <g transform="translate(870 160)">
                  <rect width="115" height="58" rx="6" fill="var(--color-card)" stroke="currentColor" stroke-opacity="0.35" />
                  <text x="10" y="20" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">UPSTREAM</text>
                  <text x="10" y="36" font-family="var(--font-mono)" font-size="9.5" fill="currentColor">grafana.int</text>
                  <text x="10" y="48" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">:3000 · ui</text>
                  <circle cx="105" cy="11" r="2.5" fill="oklch(0.7 0.2 150)">
                    <animate attributeName="opacity" values="0.5;1;0.5" dur="2.4s" repeatCount="indefinite" />
                  </circle>
                </g>
                <!-- bottom -->
                <g transform="translate(870 260)">
                  <rect width="115" height="58" rx="6" fill="var(--color-card)" stroke="currentColor" stroke-opacity="0.35" />
                  <text x="10" y="20" font-family="var(--font-mono)" font-size="7.5" fill="currentColor" fill-opacity="0.4" letter-spacing="2">UPSTREAM</text>
                  <text x="10" y="36" font-family="var(--font-mono)" font-size="9.5" fill="currentColor">db-admin</text>
                  <text x="10" y="48" font-family="var(--font-mono)" font-size="8" fill="currentColor" fill-opacity="0.5">:80 · php</text>
                  <circle cx="105" cy="11" r="2.5" fill="oklch(0.7 0.2 150)">
                    <animate attributeName="opacity" values="0.5;1;0.5" dur="1.8s" repeatCount="indefinite" />
                  </circle>
                </g>
              </g>

              <!-- ============ MOVING PACKETS ============ -->
              <g class="motion-group">
                <!-- Packet → top upstream -->
                <g>
                  <circle r="9" fill="url(#packetCore)" opacity="0.6">
                    <animateMotion dur="4.8s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-top" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" repeatCount="indefinite"
                      values="0;0.6;0.6;0.6;0.6;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                  <circle r="3" fill="oklch(0.85 0.15 220)">
                    <animateMotion dur="4.8s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-top" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" repeatCount="indefinite"
                      values="0;1;1;1;1;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                </g>

                <!-- Packet → middle upstream (offset start) -->
                <g>
                  <circle r="9" fill="url(#packetCore)" opacity="0.6">
                    <animateMotion dur="4.8s" begin="1.6s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-mid" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" begin="1.6s" repeatCount="indefinite"
                      values="0;0.6;0.6;0.6;0.6;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                  <circle r="3" fill="oklch(0.85 0.15 220)">
                    <animateMotion dur="4.8s" begin="1.6s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-mid" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" begin="1.6s" repeatCount="indefinite"
                      values="0;1;1;1;1;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                </g>

                <!-- Packet → bottom upstream -->
                <g>
                  <circle r="9" fill="url(#packetCore)" opacity="0.6">
                    <animateMotion dur="4.8s" begin="3.2s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-bot" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" begin="3.2s" repeatCount="indefinite"
                      values="0;0.6;0.6;0.6;0.6;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                  <circle r="3" fill="oklch(0.85 0.15 220)">
                    <animateMotion dur="4.8s" begin="3.2s" repeatCount="indefinite" rotate="auto" calcMode="linear"
                      keyTimes="0;0.04;0.32;0.66;0.96;1"
                      keyPoints="0;0.04;0.36;0.36;0.96;1">
                      <mpath href="#path-bot" />
                    </animateMotion>
                    <animate attributeName="opacity" dur="4.8s" begin="3.2s" repeatCount="indefinite"
                      values="0;1;1;1;1;0"
                      keyTimes="0;0.04;0.32;0.66;0.96;1" />
                  </circle>
                </g>
              </g>

              <!-- Coordinate marks (blueprint flair) -->
              <g font-family="var(--font-mono)" font-size="6.5" fill="currentColor" fill-opacity="0.25" letter-spacing="1.5">
                <text x="20" y="30">A1</text>
                <text x="380" y="30">B2</text>
                <text x="615" y="30">B3</text>
                <text x="870" y="30">C4</text>
                <text x="20" y="370">FIG.01 · INGRESS</text>
                <text x="980" y="370" text-anchor="end">REV.0.1</text>
              </g>
            </svg>
          </div>

          <!-- Decision trace + policy snippet -->
          <div class="border-t border-border/60 grid lg:grid-cols-5 divide-y lg:divide-y-0 lg:divide-x divide-border/60 bg-muted/10">
            <!-- Live trace log -->
            <div class="lg:col-span-3 p-5 sm:p-6">
              <div class="flex items-center justify-between mb-3">
                <span class="text-mono-label">decision trace</span>
                <span class="font-mono text-[10px] text-muted-foreground">id: {{ currentTrace.trace }}</span>
              </div>
              <div :key="currentTrace.trace" class="font-mono text-[12px] sm:text-[12.5px] leading-relaxed space-y-1.5 trace-fade">
                <div class="text-foreground">
                  <span class="text-muted-foreground">→</span>
                  <span class="text-primary">{{ currentTrace.method }}</span>
                  {{ currentTrace.path }}
                  <span class="text-muted-foreground/60 ml-1">[{{ currentTrace.trace }}]</span>
                </div>
                <div class="pl-5 text-muted-foreground">
                  <span class="text-emerald-500">✓</span>
                  <span class="text-foreground/80">authn</span> ·
                  subject={{ currentTrace.subject }} <span class="opacity-60">({{ currentTrace.provider }})</span>
                </div>
                <div class="pl-5 text-muted-foreground">
                  <span class="text-emerald-500">✓</span>
                  <span class="text-foreground/80">authz</span> ·
                  matched policy <span class="text-foreground/90">{{ currentTrace.policy }}</span>
                </div>
                <div class="pl-5 text-muted-foreground">
                  <span class="text-emerald-500">✓</span>
                  <span class="text-foreground/80">route</span> ·
                  upstream={{ currentTrace.upstream }}
                </div>
                <div class="pl-5">
                  <span class="text-foreground">→</span>
                  <span class="text-emerald-500">200</span>
                  <span class="text-muted-foreground">{{ currentTrace.latency }} · proxied</span>
                </div>
              </div>
            </div>

            <!-- Right rail: legend / spec -->
            <div class="lg:col-span-2 p-5 sm:p-6">
              <div class="text-mono-label mb-3">contract</div>
              <ul class="space-y-2.5 text-sm">
                <li class="flex items-start gap-3">
                  <span class="font-mono text-[10px] text-muted-foreground tracking-wider mt-1 w-5 shrink-0">01</span>
                  <span class="text-foreground/90">No request reaches your service before <span class="font-mono text-xs">authn</span> succeeds.</span>
                </li>
                <li class="flex items-start gap-3">
                  <span class="font-mono text-[10px] text-muted-foreground tracking-wider mt-1 w-5 shrink-0">02</span>
                  <span class="text-foreground/90">Policy denies are logged with the matched rule, not just a 403.</span>
                </li>
                <li class="flex items-start gap-3">
                  <span class="font-mono text-[10px] text-muted-foreground tracking-wider mt-1 w-5 shrink-0">03</span>
                  <span class="text-foreground/90">Upstream sees a clean request with verified subject in headers.</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>

    </section>

    <!-- CTA band -->
    <section aria-labelledby="cta-title" class="px-4 sm:px-6 lg:px-8 mb-20">
      <div class="mx-auto max-w-7xl">
        <div class="relative hairline rounded-2xl overflow-hidden bg-gradient-to-br from-card via-card to-muted/40 p-10 sm:p-14">
          <div aria-hidden="true" class="absolute inset-0 grid-bg opacity-50 pointer-events-none" />
          <div aria-hidden="true" class="absolute -bottom-20 -right-20 size-96 glow-blob opacity-60 pointer-events-none" />

          <div class="relative max-w-2xl">
            <p class="text-mono-label mb-5">// $ ./torii serve</p>
            <h2 id="cta-title" class="text-3xl sm:text-4xl lg:text-5xl font-semibold tracking-tight leading-tight">
              Stop shipping auth code.<br />
              Start shipping product.
            </h2>
            <p class="mt-5 text-muted-foreground leading-relaxed">
              One binary, one config file, one decision per request. torii
              fronts your services so the rest of your stack can be stateless,
              public, and boring.
            </p>
            <div class="mt-8 flex flex-col sm:flex-row gap-3">
              <Button size="lg" class="group h-11 px-5">
                Read the docs
                <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" aria-hidden="true" />
              </Button>
              <Button variant="outline" size="lg" class="h-11 px-5 font-mono text-xs hairline">
                <KeyRound class="size-3.5 mr-2" aria-hidden="true" />
                request early access
              </Button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.led {
  transition: fill 200ms ease;
}
.led-1, .led-2, .led-3 {
  animation: led-blink 1.6s infinite ease-out;
}
.led-2 { animation-delay: 0.5s; }
.led-3 { animation-delay: 1.0s; }

@keyframes led-blink {
  0%, 22%, 100% {
    fill: oklch(0.5 0.04 150);
    filter: none;
  }
  5%, 16% {
    fill: oklch(0.78 0.22 150);
    filter: drop-shadow(0 0 6px oklch(0.78 0.22 150 / 0.7));
  }
}

.led-ring-1, .led-ring-2, .led-ring-3 {
  animation: led-ring-anim 1.6s infinite ease-out;
}
.led-ring-2 { animation-delay: 0.5s; }
.led-ring-3 { animation-delay: 1.0s; }

@keyframes led-ring-anim {
  0%, 22%, 100% { stroke-opacity: 0; r: 4; }
  5% { stroke-opacity: 0.7; r: 5; }
  21% { stroke-opacity: 0; r: 14; }
}

.trace-fade {
  animation: trace-fade-in 320ms ease-out;
}
@keyframes trace-fade-in {
  0% { opacity: 0; transform: translateY(4px); }
  100% { opacity: 1; transform: translateY(0); }
}

@media (prefers-reduced-motion: reduce) {
  .led-1, .led-2, .led-3, .led-ring-1, .led-ring-2, .led-ring-3, .trace-fade {
    animation: none !important;
  }
}
</style>
