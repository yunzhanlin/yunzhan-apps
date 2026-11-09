import { computed, nextTick, onMounted, onUnmounted, ref, shallowRef, watch, type Ref } from "vue";

// Keep the breakpoint identical to the sidebar CSS. Desktop navigation remains
// available; only the off-canvas mobile menu and its background become inert.
export function useMobileNavigation(opened: Ref<boolean>) {
  const isMobile = ref(false);
  const sidebarElement = shallowRef<HTMLElement | null>(null);
  const menuButtonElement = shallowRef<HTMLButtonElement | null>(null);
  const sidebarInert = computed(() => isMobile.value && !opened.value);
  const backgroundInert = computed(() => isMobile.value && opened.value);
  let media: MediaQueryList | undefined;
  let disposed = false;
  let focusEpoch = 0;

  function closeNavigation() { opened.value = false; }
  function openNavigation() { if (isMobile.value) opened.value = true; }
  function focusableItems(): HTMLElement[] {
    const sidebar = sidebarElement.value;
    if (!sidebar) return [];
    return Array.from(sidebar.querySelectorAll<HTMLElement>(
      'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )).filter(element => element.tabIndex >= 0 && !element.closest("[inert]") &&
      element.getClientRects().length > 0 && getComputedStyle(element).visibility === "visible");
  }
  async function focusAfterRender(action: () => void) {
    const epoch = ++focusEpoch;
    await nextTick();
    if (!disposed && epoch === focusEpoch) action();
  }
  const stopWatching = watch([isMobile, opened], ([mobile, open], [wasMobile, wasOpen]) => {
    if (!mobile) {
      if (open) closeNavigation();
      void focusAfterRender(() => {
        const items = focusableItems();
        if (sidebarElement.value?.contains(document.activeElement) &&
            !items.some(element => element === document.activeElement)) {
          (items[0] || sidebarElement.value)?.focus();
        }
      });
      return;
    }
    if (open) {
      void focusAfterRender(() => (focusableItems()[0] || sidebarElement.value)?.focus());
    } else if (wasMobile && wasOpen || sidebarElement.value?.contains(document.activeElement)) {
      void focusAfterRender(() => menuButtonElement.value?.focus());
    }
  }, { flush: "post" });

  function onKeydown(event: KeyboardEvent) {
    if (!isMobile.value || !opened.value || event.defaultPrevented) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeNavigation();
      return;
    }
    if (event.key !== "Tab") return;
    const items = focusableItems();
    const index = items.findIndex(element => element === document.activeElement);
    if (!items.length) {
      event.preventDefault();
      sidebarElement.value?.focus();
    } else if (index < 0 || event.shiftKey && index === 0 || !event.shiftKey && index === items.length - 1) {
      event.preventDefault();
      items[event.shiftKey ? items.length - 1 : 0]?.focus();
    }
  }
  function onBreakpoint() {
    const mobile = !!media?.matches;
    // Capture before Vue applies inert: browsers blur the active descendant
    // synchronously when its ancestor becomes inert.
    const returnFocus = mobile && !opened.value &&
      sidebarElement.value?.contains(document.activeElement);
    isMobile.value = mobile;
    if (returnFocus) void focusAfterRender(() => menuButtonElement.value?.focus());
  }
  onMounted(() => {
    media = window.matchMedia("(max-width: 640px)");
    onBreakpoint();
    media.addEventListener("change", onBreakpoint);
    window.addEventListener("keydown", onKeydown);
  });
  onUnmounted(() => {
    disposed = true;
    ++focusEpoch;
    stopWatching();
    media?.removeEventListener("change", onBreakpoint);
    window.removeEventListener("keydown", onKeydown);
  });
  return { isMobile, sidebarElement, menuButtonElement, sidebarInert, backgroundInert, openNavigation, closeNavigation };
}
