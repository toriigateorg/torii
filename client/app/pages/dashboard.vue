<script setup lang="ts">
import { LogOut, ShieldCheck } from "lucide-vue-next"

definePageMeta({ middleware: "auth" })

useHead({ title: "Dashboard — sanmon" })

const { user, signout } = useAuth()

async function onSignout() {
  await signout()
  await navigateTo("/")
}

const greeting = computed(() => {
  const u = user.value
  if (!u) return "there"
  return u.first_name?.trim() || u.username
})
</script>

<template>
  <div class="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-16 sm:py-24">
    <div class="flex items-start justify-between gap-4 flex-wrap">
      <div>
        <p class="text-mono-label mb-3">// dashboard</p>
        <h1 class="text-3xl sm:text-4xl font-semibold tracking-tight">
          Welcome, <span class="text-primary">{{ greeting }}</span>.
        </h1>
        <p class="mt-3 text-muted-foreground max-w-xl leading-relaxed">
          You're signed in. This is a placeholder home for everything that lives behind the auth wall.
        </p>
      </div>
      <Button variant="outline" class="hairline" @click="onSignout">
        <LogOut class="size-4 mr-2" aria-hidden="true" />
        Sign out
      </Button>
    </div>

    <Card v-if="user" class="hairline mt-10">
      <CardHeader>
        <div class="flex items-center gap-2 mb-1">
          <ShieldCheck class="size-4 text-primary" aria-hidden="true" />
          <span class="text-mono-label">// session</span>
        </div>
        <CardTitle class="text-lg tracking-tight">Account</CardTitle>
        <CardDescription>What we know about you right now.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl class="grid sm:grid-cols-2 gap-x-8 gap-y-3 font-mono text-sm">
          <div class="flex justify-between sm:block">
            <dt class="text-muted-foreground">username</dt>
            <dd>{{ user.username }}</dd>
          </div>
          <div class="flex justify-between sm:block">
            <dt class="text-muted-foreground">email</dt>
            <dd class="break-all">{{ user.email }}</dd>
          </div>
          <div class="flex justify-between sm:block">
            <dt class="text-muted-foreground">roles</dt>
            <dd class="flex flex-wrap gap-1">
              <Badge
                v-for="r in user.roles"
                :key="r.id"
                :variant="r.name === 'admin' ? 'default' : 'secondary'"
                class="font-mono text-[10px]"
              >{{ r.name }}</Badge>
              <span v-if="!user.roles?.length">—</span>
            </dd>
          </div>
          <div class="flex justify-between sm:block">
            <dt class="text-muted-foreground">id</dt>
            <dd class="break-all">{{ user.id }}</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  </div>
</template>
