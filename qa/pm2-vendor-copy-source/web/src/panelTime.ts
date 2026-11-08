import { ref } from "vue";

const storageKey = "panel-display-time-zone";
const browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Shanghai";

function validTimeZone(value: string): boolean {
  try {
    Intl.DateTimeFormat("zh-CN", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

function savedTimeZone(): string {
  try {
    const value = localStorage.getItem(storageKey);
    if (value && validTimeZone(value)) return value;
  } catch { /* Private browsing can deny storage. */ }
  return browserTimeZone;
}

export const panelTimeZone = ref(savedTimeZone());

export function setPanelTimeZone(value: string): void {
  if (!validTimeZone(value)) throw new Error("时区无效");
  panelTimeZone.value = value;
  try { localStorage.setItem(storageKey, value); } catch { /* Current tab still applies the choice. */ }
}

export function formatPanelDateTime(value: string | number | Date, options: Intl.DateTimeFormatOptions = {}): string {
  const date = new Date(value instanceof Date ? value.getTime() : value);
  return date.toLocaleString("zh-CN", { hour12: false, ...options, timeZone: panelTimeZone.value });
}

export function formatPanelDate(value: string | number | Date, options: Intl.DateTimeFormatOptions = {}): string {
  const date = new Date(value instanceof Date ? value.getTime() : value);
  return date.toLocaleDateString("zh-CN", { ...options, timeZone: panelTimeZone.value });
}
