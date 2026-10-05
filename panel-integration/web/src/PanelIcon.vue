<script setup lang="ts">
defineProps<{ name: string }>();
</script>

<template>
  <svg class="panel-icon" viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <template v-if="name === 'brand'">
      <rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M6 7.5h8M6 16.5h8"/><circle cx="18" cy="7.5" r=".6" fill="currentColor" stroke="none"/><circle cx="18" cy="16.5" r=".6" fill="currentColor" stroke="none"/>
    </template>
    <template v-else-if="name === 'overview'">
      <path d="m3 10 9-7 9 7M5 9v11h5v-7h4v7h5V9"/>
    </template>
    <template v-else-if="name === 'sites'">
      <circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-2.5 2.6-3.8 5.6-3.8 9s1.3 6.4 3.8 9M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21"/>
    </template>
    <template v-else-if="name === 'databases'">
      <ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v14c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>
    </template>
    <template v-else-if="name === 'files'">
      <path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/><path d="M3 9h18"/>
    </template>
    <template v-else-if="name === 'security'">
      <path d="M12 2 20 5v6c0 5.2-3 8.6-8 11-5-2.4-8-5.8-8-11V5Z"/><path d="m9 12 2 2 4-4"/>
    </template>
    <template v-else-if="name === 'runtimes'">
      <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
    </template>
    <template v-else-if="name === 'schedules'">
      <rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4M17 3v4M3 10h18M8 14h2M14 14h2M8 18h2"/>
    </template>
    <template v-else-if="name === 'monitor'">
      <rect x="3" y="3" width="18" height="18" rx="2"/><path d="m5 16 4-4 3 2 4-6 3 3"/>
    </template>
    <template v-else-if="name === 'terminal'">
      <rect x="3" y="4" width="18" height="16" rx="2"/><path d="m6 9 3 3-3 3M11 16h5"/>
    </template>
    <template v-else-if="name === 'panel-access'">
      <circle cx="12" cy="12" r="3"/><path d="M10 2h4l.5 2.3a8 8 0 0 1 2.2 1.3l2.3-.8 2 3.4-1.8 1.5a8 8 0 0 1 0 2.6l1.8 1.5-2 3.4-2.3-.8a8 8 0 0 1-2.2 1.3L14 22h-4l-.5-2.3a8 8 0 0 1-2.2-1.3l-2.3.8-2-3.4 1.8-1.5a8 8 0 0 1 0-2.6L3 10.2l2-3.4 2.3.8a8 8 0 0 1 2.2-1.3Z" transform="translate(0 -1) scale(1 .95)"/>
    </template>
    <template v-else-if="name === 'audit'">
      <path d="M5 3h14v18H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2ZM8 8h8M8 12h8M8 16h5"/><circle cx="18" cy="18" r="2" fill="currentColor" stroke="none"/>
    </template>
    <template v-else-if="name === 'system-tools'">
      <path d="M15.2 4.4a5 5 0 0 0-6.4 6.4L3 16.6a2.5 2.5 0 0 0 3.5 3.5l5.8-5.8a5 5 0 0 0 6.4-6.4l-3 3-3.6-.7-.7-3.6Z"/>
    </template>
    <template v-else-if="name === 'theme'">
      <path d="m8 3 4 2 4-2 4 3 2 5-3 2-2-2v10H7V11l-2 2-3-2 2-5 4-3Z"/>
      <path d="M9 4.5c.3 1.5 1.4 2.3 3 2.3s2.7-.8 3-2.3"/>
    </template>
  </svg>
</template>
