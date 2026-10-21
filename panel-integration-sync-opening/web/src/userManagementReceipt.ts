export type UserMutation = 'create' | 'update' | 'revoke' | 'delete';
export type UserMutationObservation = {
  action: UserMutation;
  username: string;
  state: 'acknowledged' | 'unverified' | 'refresh_failed';
};
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
export const isUserMutation = (action: string): action is UserMutation => ['create', 'update', 'revoke', 'delete'].includes(action);
export function userMutationReplyMatches(action: UserMutation, username: unknown, value: unknown): boolean {
  return typeof username === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{2,31}$/.test(username) && object(value) &&
    Object.keys(value).length === 3 && Object.hasOwn(value, 'username') && Object.hasOwn(value, 'action') && Object.hasOwn(value, 'ok') &&
    value.username === username && value.action === action && value.ok === true;
}
export function userMutationNeedsRead(observation: UserMutationObservation | undefined, action: string): boolean {
  return isUserMutation(action) && !!observation && observation.state !== 'acknowledged';
}
export function userManagementListKnown(value: unknown): boolean {
  if (!object(value) || !Array.isArray(value.users) || !Array.isArray(value.menu_catalog) || !value.menu_catalog.length || value.menu_catalog.length > 64) return false;
  const menus = value.menu_catalog;
  if (!menus.every(menu => object(menu) && typeof menu.id === 'string' && /^[a-z][a-z-]{1,63}$/.test(menu.id) && typeof menu.label === 'string' && typeof menu.admin_only === 'boolean')) return false;
  const ids = menus.map(menu => menu.id);
  if (new Set(ids).size !== ids.length) return false;
  const names: string[] = [];
  for (const user of value.users) {
    if (!object(user) || typeof user.id !== 'string' || !/^[a-f0-9]{32}$/.test(user.id) || typeof user.username !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]{2,31}$/.test(user.username) ||
      typeof user.role !== 'string' || !['admin', 'operator', 'viewer'].includes(user.role) || !Number.isSafeInteger(user.revision) || (user.revision as number) <= 0 ||
      !Number.isSafeInteger(user.sessions) || (user.sessions as number) < 0 || typeof user.full_admin !== 'boolean' || typeof user.totp_enabled !== 'boolean' ||
      !Array.isArray(user.site_ids) || !user.site_ids.every(id => typeof id === 'string' && /^[a-f0-9]{32}$/.test(id)) ||
      !Array.isArray(user.menu_ids) || !user.menu_ids.every(id => typeof id === 'string' && ids.includes(id)) || new Set(user.menu_ids).size !== user.menu_ids.length ||
      user.full_admin !== (user.role === 'admin' && user.menu_ids.length === ids.length)) return false;
    const granted = user.menu_ids;
    if (user.role !== 'admin' && menus.some(menu => menu.admin_only && granted.includes(menu.id))) return false;
    names.push(user.username);
  }
  return new Set(names).size === names.length;
}
