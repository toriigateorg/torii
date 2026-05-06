<script setup lang="ts">
import { Menu, Github, Activity } from "lucide-vue-next"

const navLinks = [
  { to: "/#features", label: "Features" },
  { to: "/#flow", label: "How it works" },
  { to: "/health", label: "Status" },
] as const

const mobileOpen = ref(false)
</script>

<template>
  <div class="min-h-screen bg-background text-foreground flex flex-col">
    <header
      class="sticky top-0 z-40 w-full border-b border-border/60 bg-background/70 backdrop-blur-xl"
    >
      <div class="mx-auto max-w-7xl flex h-14 items-center justify-between px-4 sm:px-6 lg:px-8">
        <NuxtLink to="/" class="flex items-center gap-2 group">
          <div class="relative size-7 rounded-md hairline overflow-hidden bg-gradient-to-br from-primary/15 to-transparent flex items-center justify-center">
            <span class="font-mono text-[11px] font-semibold tracking-tight">sm</span>
            <span class="absolute inset-0 ring-1 ring-inset ring-primary/10 rounded-md" />
          </div>
          <span class="font-semibold tracking-tight">sanmon</span>
          <span class="text-mono-label hidden sm:inline ml-2">v0.1</span>
        </NuxtLink>

        <nav class="hidden md:flex items-center gap-1">
          <NuxtLink
            v-for="link in navLinks"
            :key="link.to"
            :to="link.to"
            class="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors rounded-md"
          >
            {{ link.label }}
          </NuxtLink>
        </nav>

        <div class="flex items-center gap-2">
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener"
            class="hidden sm:inline-flex items-center justify-center size-9 hairline rounded-md text-muted-foreground hover:text-foreground transition-colors"
            aria-label="GitHub"
          >
            <Github class="size-4" />
          </a>
          <ThemeToggle />
          <Sheet v-model:open="mobileOpen">
            <SheetTrigger as-child>
              <Button variant="ghost" size="icon" class="md:hidden hairline rounded-md size-9" aria-label="Open menu">
                <Menu class="size-4" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" class="w-72">
              <SheetHeader>
                <SheetTitle class="font-mono text-sm tracking-wider uppercase">Navigation</SheetTitle>
              </SheetHeader>
              <nav class="flex flex-col gap-1 mt-6 px-4">
                <NuxtLink
                  v-for="link in navLinks"
                  :key="link.to"
                  :to="link.to"
                  class="px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors"
                  @click="mobileOpen = false"
                >
                  {{ link.label }}
                </NuxtLink>
              </nav>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>

    <main class="flex-1">
      <slot />
    </main>

    <footer class="border-t border-border/60 mt-24">
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <Activity class="size-3.5 text-primary" />
          <span class="font-mono text-xs text-muted-foreground">
            sanmon &middot; identity-aware reverse proxy
          </span>
        </div>
        <div class="flex items-center gap-6 text-xs text-muted-foreground">
          <NuxtLink to="/health" class="hover:text-foreground transition-colors">/health</NuxtLink>
          <a href="#" class="hover:text-foreground transition-colors">docs</a>
          <a href="#" class="hover:text-foreground transition-colors">github</a>
        </div>
      </div>
    </footer>
  </div>
</template>
