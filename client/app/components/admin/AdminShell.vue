<script setup lang="ts">
import { Users, KeyRound } from "lucide-vue-next"

const route = useRoute()
const links = [
  { to: "/admin/model/users", label: "Users", icon: Users },
  { to: "/admin/model/tokens", label: "Tokens", icon: KeyRound },
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
      <aside>
        <nav class="flex lg:flex-col gap-1 hairline rounded-lg p-2 bg-card/40">
          <NuxtLink
            v-for="link in links"
            :key="link.to"
            :to="link.to"
            class="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
            :class="isActive(link.to)
              ? 'bg-accent text-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'"
          >
            <component :is="link.icon" class="size-4" />
            {{ link.label }}
          </NuxtLink>
        </nav>
      </aside>

      <section>
        <slot />
      </section>
    </div>
  </div>
</template>
