<script setup lang="ts">
import { Users, KeyRound, Server, Shield, LogIn, Settings, ScrollText, BarChart3, Terminal } from "lucide-vue-next"

const route = useRoute()
const links = [
  { to: "/admin/stats", label: "Stats", icon: BarChart3 },
  { to: "/admin/model/users", label: "Users", icon: Users },
  { to: "/admin/model/roles", label: "Roles", icon: Shield },
  { to: "/admin/model/tokens", label: "Tokens", icon: KeyRound },
  { to: "/admin/model/api-tokens", label: "API tokens", icon: Terminal },
  { to: "/admin/model/services", label: "Services", icon: Server },
  { to: "/admin/model/sso", label: "SSO", icon: LogIn },
  { to: "/admin/audit", label: "Audit log", icon: ScrollText },
  { to: "/admin/settings", label: "Settings", icon: Settings },
]

function isActive(to: string) {
  return route.path === to
}
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
    <p class="text-mono-label mb-3">// admin</p>
    <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight mb-10">
      Control plane
    </h1>

    <div class="grid lg:grid-cols-[200px_1fr] gap-8">
      <aside aria-label="Admin sections">
        <nav class="flex lg:flex-col gap-1 hairline rounded-lg p-2 bg-card/40" aria-label="Admin">
          <NuxtLink
            v-for="link in links"
            :key="link.to"
            :to="link.to"
            class="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            :class="isActive(link.to)
              ? 'bg-accent text-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'"
            :aria-current="isActive(link.to) ? 'page' : undefined"
          >
            <component :is="link.icon" class="size-4" aria-hidden="true" />
            {{ link.label }}
          </NuxtLink>
        </nav>
      </aside>

      <section aria-label="Admin content">
        <slot />
      </section>
    </div>
  </div>
</template>
