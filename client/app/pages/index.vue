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

useHead({
  title: "sanmon — identity-aware reverse proxy",
  meta: [
    { name: "description", content: "A reverse HTTP proxy with built-in authentication and role-based access control. Front your services with policy, not plumbing." },
  ],
})

const features = [
  {
    no: "01",
    label: "IDENTITY",
    title: "Single sign-on, everywhere",
    body: "Bring OIDC, SAML, or your own provider. sanmon terminates auth at the edge so your services never see a raw request.",
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
</script>

<template>
  <div class="relative">
    <!-- Hero -->
    <section class="relative overflow-hidden">
      <div class="absolute inset-0 grid-bg pointer-events-none" />
      <div class="absolute -top-24 left-1/2 -translate-x-1/2 size-[700px] glow-blob float-slow pointer-events-none opacity-70" />

      <div class="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 pt-16 sm:pt-24 lg:pt-32 pb-20 lg:pb-28">
        <div class="grid lg:grid-cols-12 gap-10 lg:gap-12 items-center">
          <div class="lg:col-span-7">
            <div class="inline-flex items-center gap-2 hairline rounded-full px-3 py-1 mb-8 bg-background/40 backdrop-blur">
              <span class="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span class="font-mono text-[11px] tracking-wider uppercase text-muted-foreground">
                v0.1 — early access
              </span>
            </div>

            <p class="text-mono-label mb-5">// reverse proxy / auth / rbac</p>

            <h1 class="text-4xl sm:text-5xl lg:text-7xl font-semibold tracking-tight leading-[0.95]">
              The edge between
              <span class="block mt-2">
                <span class="text-muted-foreground/70">your users</span>
                <ChevronRight class="inline-block size-8 sm:size-10 lg:size-14 text-primary mx-1 -translate-y-1" />
                <span class="text-foreground">your services</span>
              </span>
            </h1>

            <p class="mt-7 text-base sm:text-lg text-muted-foreground max-w-xl leading-relaxed">
              sanmon terminates authentication, enforces RBAC, and routes traffic
              upstream &mdash; so your services can stop reimplementing the same
              middleware in five different languages.
            </p>

            <div class="mt-9 flex flex-col sm:flex-row gap-3">
              <Button size="lg" class="group h-11 px-5 font-medium">
                Get started
                <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" />
              </Button>
              <Button variant="outline" size="lg" class="h-11 px-5 font-mono text-xs hairline">
                <Terminal class="size-3.5 mr-2" />
                docker run sanmon/sanmon
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
                    sanmon.yaml
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
    <section class="border-y border-border/60 bg-muted/20">
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
    <section id="features" class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <div class="max-w-2xl mb-14">
        <p class="text-mono-label mb-4">// what it does</p>
        <h2 class="text-3xl sm:text-4xl font-semibold tracking-tight">
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
            <component :is="f.icon" class="size-4 text-muted-foreground group-hover:text-primary transition-colors" />
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
    <section id="flow" class="border-t border-border/60">
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
        <div class="max-w-2xl mb-14">
          <p class="text-mono-label mb-4">// request lifecycle</p>
          <h2 class="text-3xl sm:text-4xl font-semibold tracking-tight">
            Auth, policy, proxy &mdash; in that order.
          </h2>
        </div>

        <div class="hairline rounded-xl bg-card/40 p-6 sm:p-10 lg:p-14">
          <div class="grid grid-cols-1 md:grid-cols-7 gap-4 md:gap-2 items-stretch">
            <!-- Client -->
            <div class="md:col-span-2 flex">
              <div class="flex-1 hairline rounded-lg p-5 bg-background">
                <div class="flex items-center gap-2 mb-3">
                  <span class="size-2 rounded-full bg-foreground/40" />
                  <span class="text-mono-label">client</span>
                </div>
                <p class="font-mono text-sm">browser / cli / agent</p>
                <p class="text-xs text-muted-foreground mt-2">cookie or bearer token</p>
              </div>
            </div>

            <!-- Connector -->
            <div class="hidden md:flex items-center justify-center">
              <div class="w-full h-px border-t border-dashed border-border" />
            </div>

            <!-- Sanmon (the heart) -->
            <div class="md:col-span-1 flex">
              <div class="flex-1 hairline rounded-lg p-5 bg-gradient-to-br from-primary/10 via-card to-card relative overflow-hidden">
                <div class="absolute top-0 right-0 size-16 -translate-y-4 translate-x-4 glow-blob opacity-50" />
                <div class="relative">
                  <div class="flex items-center gap-2 mb-3">
                    <span class="size-2 rounded-full bg-primary animate-pulse" />
                    <span class="text-mono-label text-foreground">sanmon</span>
                  </div>
                  <div class="space-y-1.5">
                    <div class="flex items-center gap-2 text-xs">
                      <Lock class="size-3 text-primary" />
                      <span>authn</span>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                      <ShieldCheck class="size-3 text-primary" />
                      <span>authz</span>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                      <Workflow class="size-3 text-primary" />
                      <span>route</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Connector -->
            <div class="hidden md:flex items-center justify-center">
              <div class="w-full h-px border-t border-dashed border-border" />
            </div>

            <!-- Upstreams -->
            <div class="md:col-span-2 grid gap-2">
              <div class="hairline rounded-lg p-3 bg-background flex items-center justify-between">
                <span class="font-mono text-xs">api.internal:8080</span>
                <span class="size-1.5 rounded-full bg-emerald-500" />
              </div>
              <div class="hairline rounded-lg p-3 bg-background flex items-center justify-between">
                <span class="font-mono text-xs">grafana.internal:3000</span>
                <span class="size-1.5 rounded-full bg-emerald-500" />
              </div>
              <div class="hairline rounded-lg p-3 bg-background flex items-center justify-between">
                <span class="font-mono text-xs">db-admin.internal:80</span>
                <span class="size-1.5 rounded-full bg-emerald-500" />
              </div>
            </div>
          </div>

          <!-- Decision trace -->
          <div class="mt-10 pt-6 border-t border-dashed border-border/60">
            <div class="font-mono text-xs space-y-1.5 text-muted-foreground">
              <div><span class="text-foreground">→</span> GET /admin/users <span class="text-muted-foreground/60">[trace: 8f2a]</span></div>
              <div class="pl-4"><span class="text-emerald-500">✓</span> authn: subject=alice@acme.com (oidc)</div>
              <div class="pl-4"><span class="text-emerald-500">✓</span> authz: matched policy #2 (role:admin)</div>
              <div class="pl-4"><span class="text-foreground">→</span> proxy: api.internal:8080 (1.2ms)</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA band -->
    <section class="px-4 sm:px-6 lg:px-8 mb-20">
      <div class="mx-auto max-w-7xl">
        <div class="relative hairline rounded-2xl overflow-hidden bg-gradient-to-br from-card via-card to-muted/40 p-10 sm:p-14">
          <div class="absolute inset-0 grid-bg opacity-50 pointer-events-none" />
          <div class="absolute -bottom-20 -right-20 size-96 glow-blob opacity-60 pointer-events-none" />

          <div class="relative max-w-2xl">
            <p class="text-mono-label mb-5">// $ ./sanmon serve</p>
            <h2 class="text-3xl sm:text-4xl lg:text-5xl font-semibold tracking-tight leading-tight">
              Stop shipping auth code.<br />
              Start shipping product.
            </h2>
            <p class="mt-5 text-muted-foreground leading-relaxed">
              One binary, one config file, one decision per request. sanmon
              fronts your services so the rest of your stack can be stateless,
              public, and boring.
            </p>
            <div class="mt-8 flex flex-col sm:flex-row gap-3">
              <Button size="lg" class="group h-11 px-5">
                Read the docs
                <ArrowRight class="size-4 ml-1 group-hover:translate-x-0.5 transition-transform" />
              </Button>
              <Button variant="outline" size="lg" class="h-11 px-5 font-mono text-xs hairline">
                <KeyRound class="size-3.5 mr-2" />
                request early access
              </Button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>
