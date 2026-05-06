<script setup lang="ts">
import { Menu, Github, Activity, LogIn, LogOut, LayoutDashboard, ShieldCheck } from "lucide-vue-next"

const { isAuthed, user, signout } = useAuth()

const navLinks = computed(() => {
  const base = [
    { to: "/#features", label: "Features" },
    { to: "/#flow", label: "How it works" },
    { to: "/health", label: "Status" },
  ]
  if (isAuthed.value) base.push({ to: "/dashboard", label: "Dashboard" })
  return base
})

const mobileOpen = ref(false)

async function onSignout() {
  await signout()
  mobileOpen.value = false
  await navigateTo("/")
}
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

          <template v-if="isAuthed">
            <DropdownMenu>
              <DropdownMenuTrigger as-child>
                <Button variant="outline" size="sm" class="hairline hidden sm:inline-flex font-mono text-xs h-9">
                  {{ user?.username }}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" class="w-48">
                <DropdownMenuItem as-child>
                  <NuxtLink to="/dashboard" class="cursor-pointer">
                    <LayoutDashboard class="size-4 mr-2" /> Dashboard
                  </NuxtLink>
                </DropdownMenuItem>
                <DropdownMenuItem v-if="user?.user_type === 'admin'" as-child>
                  <NuxtLink to="/admin/model/users" class="cursor-pointer">
                    <ShieldCheck class="size-4 mr-2" /> Admin
                  </NuxtLink>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem class="cursor-pointer" @select="onSignout">
                  <LogOut class="size-4 mr-2" /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </template>
          <template v-else>
            <NuxtLink to="/signin" class="hidden sm:inline-flex">
              <Button variant="outline" size="sm" class="hairline h-9">
                <LogIn class="size-4 mr-2" /> Sign in
              </Button>
            </NuxtLink>
          </template>

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
                <div class="mt-4 pt-4 border-t border-border/60">
                  <template v-if="isAuthed">
                    <p class="px-3 py-2 text-xs text-muted-foreground font-mono">
                      signed in as {{ user?.username }}
                    </p>
                    <button
                      class="w-full text-left px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors flex items-center"
                      @click="onSignout"
                    >
                      <LogOut class="size-4 mr-2" /> Sign out
                    </button>
                  </template>
                  <template v-else>
                    <NuxtLink
                      to="/signin"
                      class="px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors flex items-center"
                      @click="mobileOpen = false"
                    >
                      <LogIn class="size-4 mr-2" /> Sign in
                    </NuxtLink>
                    <NuxtLink
                      to="/signup"
                      class="px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors"
                      @click="mobileOpen = false"
                    >
                      Create account
                    </NuxtLink>
                  </template>
                </div>
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
