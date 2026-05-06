<script setup lang="ts">
import { ChevronLeft, ChevronRight } from "lucide-vue-next"

const props = defineProps<{
  page: number
  pageSize: number
  total: number
}>()

const emit = defineEmits<{
  (e: "update:page", value: number): void
}>()

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const start = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.pageSize + 1))
const end = computed(() => Math.min(props.page * props.pageSize, props.total))

function prev() { if (props.page > 1) emit("update:page", props.page - 1) }
function next() { if (props.page < totalPages.value) emit("update:page", props.page + 1) }
</script>

<template>
  <div class="flex items-center justify-between gap-4 mt-4">
    <p class="font-mono text-xs text-muted-foreground tabular-nums">
      {{ start }}–{{ end }} of {{ total }}
    </p>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" class="hairline h-8" :disabled="page <= 1" @click="prev">
        <ChevronLeft class="size-3.5" />
      </Button>
      <span class="font-mono text-xs tabular-nums px-2">
        {{ page }} / {{ totalPages }}
      </span>
      <Button variant="outline" size="sm" class="hairline h-8" :disabled="page >= totalPages" @click="next">
        <ChevronRight class="size-3.5" />
      </Button>
    </div>
  </div>
</template>
