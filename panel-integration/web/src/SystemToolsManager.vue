<script setup lang="ts">
import {
  ArrowRight,
  Box,
  Clock,
  Key,
  Lock,
  Tickets,
  User,
} from "@element-plus/icons-vue";
const emit = defineEmits<{ (event: "open", value: string): void }>();
const tools = [
  {
    key: "certificates",
    title: "SSL 证书",
    text: "上传、续期并为网站绑定证书。",
    icon: Key,
  },
  {
    key: "backups",
    title: "备份管理",
    text: "网站、数据库与面板整包备份。",
    icon: Box,
  },
  {
    key: "jobs",
    title: "任务中心",
    text: "查看安装、部署和恢复任务。",
    icon: Clock,
  },
  {
    key: "audit",
    title: "操作日志",
    text: "核对管理员操作与执行结果。",
    icon: Tickets,
  },
  {
    key: "account",
    title: "账户安全",
    text: "密码、双重验证与恢复码。",
    icon: User,
  },
  {
    key: "security",
    title: "主机安全",
    text: "防火墙规则与 SSH 安全检查。",
    icon: Lock,
  },
];
</script>

<template>
  <div class="system-tools-grid">
    <button
      v-for="item in tools"
      :key="item.key"
      class="panel-card tool-card"
      @click="emit('open', item.key)"
    >
      <span class="tool-icon"
        ><el-icon><component :is="item.icon" /></el-icon
      ></span>
      <span
        ><strong>{{ item.title }}</strong
        ><small>{{ item.text }}</small></span
      >
      <el-icon class="tool-arrow"><ArrowRight /></el-icon>
    </button>
  </div>
</template>

<style scoped>
.system-tools-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.tool-card {
  min-height: 118px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 15px;
  text-align: left;
}
.tool-card:hover {
  border-color: #9fd8ba;
  box-shadow: 0 4px 12px rgb(8 173 91 / 8%);
}
.tool-icon {
  width: 52px;
  height: 52px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  background: #e8f8ef;
  color: #08ad5b;
  font-size: 25px;
}
.tool-card > span:nth-child(2) {
  display: grid;
  gap: 8px;
  flex: 1;
}
.tool-card strong {
  color: #14233d;
  font-size: 15px;
}
.tool-card small {
  color: #75869d;
  font-size: 12px;
}
.tool-arrow {
  color: #08ad5b;
}
@media (max-width: 850px) {
  .system-tools-grid {
    grid-template-columns: 1fr 1fr;
  }
}
@media (max-width: 560px) {
  .system-tools-grid {
    grid-template-columns: 1fr;
  }
}
</style>
