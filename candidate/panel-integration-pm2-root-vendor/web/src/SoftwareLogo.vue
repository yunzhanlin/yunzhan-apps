<script setup lang="ts">
import { computed } from "vue";
import {
  siApache,
  siDocker,
  siMariadb,
  siMysql,
  siNginx,
  siNodedotjs,
  siPhp,
  siRedis,
  siWordpress,
} from "simple-icons";

const props = defineProps<{ family: string }>();
const icons = {
  apache: siApache,
  docker: siDocker,
  mariadb: siMariadb,
  mysql: siMysql,
  nginx: siNginx,
  node: siNodedotjs,
  php: siPhp,
  redis: siRedis,
  wordpress: siWordpress,
} as const;
const icon = computed(() => icons[props.family as keyof typeof icons]);
</script>

<template>
  <span :class="['software-icon', 'software-logo', family]" aria-hidden="true">
    <svg v-if="family === 'redis'" viewBox="0 0 64 64" focusable="false">
      <path d="M6 42 32 54 58 42v8L32 62 6 50Z" fill="currentColor" />
      <path d="M6 31 32 43 58 31v8L32 51 6 39Z" fill="currentColor" />
      <path d="M6 20 32 32 58 20v8L32 40 6 28Z" fill="currentColor" />
      <path d="M32 3 59 16 32 29 5 16Z" fill="currentColor" />
      <path d="m20 15 12-6 12 6-12 6Z" fill="#fff" /><path d="m14 23 18 8 18-8M14 34l18 8 18-8M14 45l18 8 18-8" fill="none" stroke="#fff" stroke-width="2.3" stroke-linecap="round" />
    </svg>
    <svg v-else-if="icon" viewBox="0 0 24 24" focusable="false">
      <path :d="icon.path" />
    </svg>
    <span v-else>{{ family.slice(0, 2).toUpperCase() }}</span>
  </span>
</template>
