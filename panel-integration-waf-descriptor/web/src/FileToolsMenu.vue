<script setup lang="ts">
import { ArrowRight, MoreFilled } from "@element-plus/icons-vue";

defineProps<{
  compact?: boolean;
  items: { command: string; label: string; disabled?: boolean; divided?: boolean; className?: string }[];
}>();
const emit = defineEmits<{ (event: "command", command: string): void }>();
</script>

<template>
  <el-dropdown class="file-tools-menu" trigger="click" @command="(command: string) => emit('command', command)">
    <button type="button" aria-label="更多文件功能" title="更多文件功能" :class="{ compact }">
      <el-icon><component :is="compact ? MoreFilled : ArrowRight" /></el-icon>
    </button>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item v-for="item in items" :key="item.command" :command="item.command" :disabled="item.disabled" :divided="item.divided" :class="item.className">
          {{ item.label }}
        </el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<style scoped>
button { display: grid; place-items: center; width: 24px; height: 24px; padding: 0; border: 0; border-radius: 4px; color: #71819a; background: transparent; font-size: 14px; cursor: pointer; }
button:hover { color: #07964f; }
button:focus-visible { outline: 2px solid #0aad60; outline-offset: 2px; }
button.compact { width: 34px; height: 34px; border: 1px solid #dce5ec; background: var(--panel-surface, #fff); color: var(--panel-text, #344965); font-size: 18px; }
:global(html.dark) button.compact { border-color: #405068; }
</style>
