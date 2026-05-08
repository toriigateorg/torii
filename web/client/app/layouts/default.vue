<script setup lang="ts">
import { Menu, Github, LogIn, LogOut, LayoutDashboard, ShieldCheck } from "lucide-vue-next"

const { isAuthed, isAdmin, user, signout } = useAuth()
const route = useRoute()

const navLinks: { to: string; label: string }[] = []

const isLanding = computed(() => route.path === "/")

const mobileOpen = ref(false)

async function onSignout() {
  await signout()
  mobileOpen.value = false
  await navigateTo("/")
}
</script>

<template>
  <div class="min-h-screen bg-background text-foreground flex flex-col">
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <header
      class="sticky top-0 z-40 w-full backdrop-blur-xl transition-colors"
      :class="isLanding ? 'border-b border-border/30 bg-background/30' : 'border-b border-border/60 bg-background/70'"
    >
      <div class="mx-auto max-w-7xl flex h-14 items-center justify-between px-4 sm:px-6 lg:px-8">
        <NuxtLink to="/" class="flex items-center gap-2 group" aria-label="torii — home">
          <img
            src="/torii-logo.svg"
            alt=""
            aria-hidden="true"
            width="28"
            height="28"
            class="size-7 rounded-md"
          />
          <span class="font-semibold tracking-tight">torii</span>
          <span class="text-mono-label hidden sm:inline ml-2">v0.1</span>
        </NuxtLink>

        <div class="flex items-center gap-2">
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener"
            class="hidden sm:inline-flex items-center justify-center size-9 hairline rounded-md text-muted-foreground hover:text-foreground transition-colors"
            aria-label="GitHub (opens in a new tab)"
          >
            <Github class="size-4" aria-hidden="true" />
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
                    <LayoutDashboard class="size-4 mr-2" aria-hidden="true" /> Dashboard
                  </NuxtLink>
                </DropdownMenuItem>
                <DropdownMenuItem v-if="isAdmin" as-child>
                  <NuxtLink to="/admin/model/users" class="cursor-pointer">
                    <ShieldCheck class="size-4 mr-2" aria-hidden="true" /> Admin
                  </NuxtLink>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem class="cursor-pointer" @select="onSignout">
                  <LogOut class="size-4 mr-2" aria-hidden="true" /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </template>
          <template v-else>
            <NuxtLink to="/signin" class="hidden sm:inline-flex">
              <Button variant="outline" size="sm" class="hairline h-9">
                <LogIn class="size-4 mr-2" aria-hidden="true" /> Sign in
              </Button>
            </NuxtLink>
          </template>

          <Sheet v-model:open="mobileOpen">
            <SheetTrigger as-child>
              <Button variant="ghost" size="icon" class="md:hidden hairline rounded-md size-9" aria-label="Open menu">
                <Menu class="size-4" aria-hidden="true" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" class="w-72">
              <SheetHeader>
                <SheetTitle class="font-mono text-sm tracking-wider uppercase">Navigation</SheetTitle>
              </SheetHeader>
              <nav class="flex flex-col gap-1 mt-6 px-4" aria-label="Mobile">
                <NuxtLink
                  v-for="link in navLinks"
                  :key="link.to"
                  :to="link.to"
                  class="px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
                      type="button"
                      class="w-full text-left px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors flex items-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      @click="onSignout"
                    >
                      <LogOut class="size-4 mr-2" aria-hidden="true" /> Sign out
                    </button>
                  </template>
                  <template v-else>
                    <NuxtLink
                      to="/signin"
                      class="px-3 py-2.5 text-sm rounded-md hover:bg-accent transition-colors flex items-center"
                      @click="mobileOpen = false"
                    >
                      <LogIn class="size-4 mr-2" aria-hidden="true" /> Sign in
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

    <main id="main-content" tabindex="-1" class="flex-1 focus:outline-none">
      <slot />
    </main>

    <div id="route-announcer" class="sr-only" role="status" aria-live="polite" aria-atomic="true" />

    <footer class="border-t border-border/60 mt-24">
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <span class="font-mono text-xs text-muted-foreground">
          &copy; 2026 torii
        </span>
        <span class="font-mono text-xs text-muted-foreground">
          crafted by
          <a
            href="https://codingcoffee.dev"
            target="_blank"
            rel="noopener"
            class="text-foreground/80 hover:text-foreground underline-offset-4 hover:underline transition-colors"
          >Ameya Shenoy</a>
        </span>
      </div>
    </footer>
  </div>
</template>
