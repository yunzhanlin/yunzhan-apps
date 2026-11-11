<script setup lang="ts">
import { computed, ref } from "vue";
import { userManagementListKnown } from "./userManagementReceipt";

type Role = "admin" | "operator" | "viewer";
interface AccountRow {
  id: string;
  username: string;
  role: Role;
  site_ids: string[];
  menu_ids: string[];
  revision: number;
  full_admin: boolean;
  totp_enabled: boolean;
  sessions: number;
}
interface AccountMenu { id: string; label: string; admin_only: boolean; }
interface SiteOption { id: string; name: string; domain: string; }

const props = defineProps<{ report: unknown; sites: SiteOption[]; busy: boolean }>();
const emit = defineEmits<{ select: [account: AccountRow] }>();
const query = ref("");
const roleFilter = ref<Role | "">("");
const menuFilter = ref("");
const roles: Record<Role, string> = { admin: "管理员", operator: "网站操作员", viewer: "只读账户" };
const snapshot = computed(() => userManagementListKnown(props.report)
  ? props.report as { users: AccountRow[]; menu_catalog: AccountMenu[] } : undefined);
const menuLabels = computed(() => new Map(snapshot.value?.menu_catalog.map(menu => [menu.id, menu.label])));
const siteLabels = computed(() => new Map(props.sites.map(site => [site.id, `${site.name} · ${site.domain}`])));
const visibleAccounts = computed(() => {
  const term = query.value.trim().toLocaleLowerCase();
  return snapshot.value?.users.filter(account => {
    if (roleFilter.value && account.role !== roleFilter.value) return false;
    if (menuFilter.value && !account.menu_ids.includes(menuFilter.value)) return false;
    const searchable = [account.username, ...account.site_ids.map(id => siteLabels.value.get(id) || id)];
    return !term || searchable.some(value => value.toLocaleLowerCase().includes(term));
  }) ?? [];
});
</script>

<template>
  <section v-if="snapshot" class="user-access-overview" aria-label="账户权限总览">
    <div class="user-access-filters">
      <el-input v-model="query" aria-label="搜索账户或网站" placeholder="搜索账户或网站" clearable />
      <el-select v-model="roleFilter" aria-label="筛选账户角色" placeholder="全部角色" clearable>
        <el-option v-for="(label, role) in roles" :key="role" :value="role" :label="label" />
      </el-select>
      <el-select v-model="menuFilter" aria-label="筛选已授权菜单" placeholder="全部菜单" clearable filterable>
        <el-option v-for="menu in snapshot.menu_catalog" :key="menu.id" :value="menu.id" :label="menu.label" />
      </el-select>
    </div>
    <el-table :data="visibleAccounts" row-key="id" empty-text="没有符合筛选条件的账户">
      <el-table-column prop="username" label="账户" min-width="135" />
      <el-table-column label="角色" min-width="115">
        <template #default="{ row }">{{ row.full_admin ? '完整管理员' : roles[row.role as Role] }}</template>
      </el-table-column>
      <el-table-column label="网站范围" min-width="175">
        <template #default="{ row }">
          <span v-if="row.role === 'admin'">按菜单授权访问所有网站</span>
          <span v-else-if="row.site_ids.length === 0">无网站授权</span>
          <ul v-else class="user-access-sites">
            <li v-for="site in new Set<string>(row.site_ids)" :key="site">{{ siteLabels.get(site) || `未列出的网站 · ${site}` }}</li>
          </ul>
        </template>
      </el-table-column>
      <el-table-column label="已授权菜单" min-width="230">
        <template #default="{ row }">
          <span v-if="row.menu_ids.length === 0">仅自身账户安全</span>
          <div v-else class="user-access-menus">
            <el-tag v-for="menu in row.menu_ids" :key="menu" size="small">{{ menuLabels.get(menu) }}</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="账户安全" min-width="125">
        <template #default="{ row }">
          <div>{{ row.totp_enabled ? '双重验证已开启' : '双重验证关闭' }}</div>
          <div>{{ row.sessions }} 个有效会话</div>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="98">
        <template #default="{ row }">
          <el-button type="primary" link :disabled="busy" :aria-label="`编辑账户 ${row.username}`"
            @click="emit('select', row)">编辑权限</el-button>
        </template>
      </el-table-column>
    </el-table>
  </section>
</template>

<style scoped>
.user-access-overview { display: grid; gap: 12px; }
.user-access-filters { display: grid; grid-template-columns: minmax(12rem, 1.5fr) repeat(2, minmax(9rem, 1fr)); gap: 10px; }
.user-access-sites { margin: 0; padding-left: 1rem; overflow-wrap: anywhere; }
.user-access-menus { display: flex; flex-wrap: wrap; gap: 4px; }
@media (max-width: 660px) {
  .user-access-filters { grid-template-columns: 1fr; }
}
</style>
