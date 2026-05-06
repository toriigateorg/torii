<script setup lang="ts">
import { Sun, Moon, Monitor, Check } from "lucide-vue-next"

const colorMode = useColorMode()

const options = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const

function setMode(value: "light" | "dark" | "system") {
  colorMode.preference = value
}
</script>

<template>
  <ClientOnly>
    <DropdownMenu>
      <DropdownMenuTrigger as-child>
        <Button
          variant="ghost"
          size="icon"
          class="relative size-9 hairline rounded-md"
          aria-label="Toggle theme"
        >
          <Sun class="size-4 scale-100 rotate-0 transition-all duration-300 dark:-rotate-90 dark:scale-0" />
          <Moon class="absolute size-4 scale-0 rotate-90 transition-all duration-300 dark:rotate-0 dark:scale-100" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" class="w-40">
        <DropdownMenuItem
          v-for="opt in options"
          :key="opt.value"
          class="flex items-center justify-between gap-2 cursor-pointer"
          @select="setMode(opt.value)"
        >
          <span class="flex items-center gap-2">
            <component :is="opt.icon" class="size-4" />
            <span>{{ opt.label }}</span>
          </span>
          <Check v-if="colorMode.preference === opt.value" class="size-3.5 text-primary" />
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>

    <template #fallback>
      <div class="size-9 rounded-md hairline" />
    </template>
  </ClientOnly>
</template>
