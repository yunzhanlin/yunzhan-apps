// Appended inside the first-party analytics closure only for sites that
// enabled visual replay. A site integration must grant visitor consent.
(() => {
  const sample = config.replaySample;
  if (!Number.isInteger(sample) || sample < 1 || sample > 100) return;
  const privateSelector = 'form,input,textarea,select,[contenteditable],iframe,video,canvas,object,embed,script,style,[hidden],[aria-hidden="true" i],[data-analytics-ignore],[data-yunzhan-private]';
  const sampleSession = id => Number.parseInt(id.slice(0, 8), 16) < sample * 0x100000000 / 100;
  const maxFrames = 180;
  let consent = window.yunzhanAnalyticsReplayConsent === true;
  let blocked = false, timer, pointer, previous = "", recordedSession = "", frames = 0;
  let capturePage = "", lastCapture = 0;
  let trackingChanges = false, inflight;
  const observer = new MutationObserver(() => { trackingChanges = true; });
  const visibleStyle = style => style.display !== "none" && style.visibility === "visible" &&
    style.contentVisibility !== "hidden" && Number(style.opacity) >= 0.1;
  const privateElement = element => element.matches(privateSelector) ||
    element.shadowRoot !== null || element.localName.includes("-");
  const ratio = (value, limit) => Math.min(1000, Math.max(0, Math.round(value * 1000 / limit)));

  function countFor(id) {
    if (recordedSession === id) return;
    recordedSession = id;
    frames = 0;
    try {
      const saved = JSON.parse(sessionStorage.getItem("yz.analytics.replay-budget") || "null");
      if (saved?.session === id && Number.isInteger(saved.frames) && saved.frames >= 0 && saved.frames <= maxFrames) frames = saved.frames;
    } catch {}
  }

  function rgba(value, fallback) {
    const rgb = /^rgba?\(\s*(\d+),\s*(\d+),\s*(\d+)(?:,\s*([.\d]+))?\s*\)$/i.exec(value);
    if (!rgb || (rgb[4] !== undefined && Number(rgb[4]) < 0.15)) return fallback;
    const [r, g, b] = rgb.slice(1,4).map(Number);
    return r <= 255 && g <= 255 && b <= 255 ? (r << 16) | (g << 8) | b : fallback;
  }

  function viewport() {
    const width = window.innerWidth, height = window.innerHeight;
    if (!document.body || width < 1 || height < 1 || width > 8192 || height > 8192) return;
    const tiles = [];
    // Visit each node at most once and skip whole hidden or confidential
    // subtrees. The traversal budget includes rejected nodes.
    const root = document.body;
    const html = document.documentElement;
    const rootStyle = getComputedStyle(root);
    if (privateElement(root) || privateElement(html) ||
        !visibleStyle(rootStyle) || !visibleStyle(getComputedStyle(html))) return;
    const bg = rgba(rootStyle.backgroundColor, 0xffffff);
    tiles.push([0, 0, 1000, 1000, bg, 0]);
    const colors = [bg, 0x475569, 0xcbd5e1, 0x93a5bd, 0xdbe5f1];
    const next = (current, descend) => {
      if (descend && current.firstElementChild) return current.firstElementChild;
      for (let node = current; node && node !== root; node = node.parentElement) {
        if (node.nextElementSibling) return node.nextElementSibling;
      }
      return null;
    };
    for (let node = root.firstElementChild, inspected = 0; node && inspected < 1600 && tiles.length < 60; inspected++) {
      const element = node;
      const style = privateElement(element) ? null : getComputedStyle(element);
      const visible = style && visibleStyle(style);
      node = next(element, visible);
      if (!visible) continue;
      const rect = element.getBoundingClientRect();
      const left = Math.max(0, rect.left), top = Math.max(0, rect.top);
      const right = Math.min(width, rect.right), bottom = Math.min(height, rect.bottom);
      if (right - left < 3 || bottom - top < 3) continue;
      const kind = element.matches("h1,h2,h3,h4,h5,h6") ? 1
        : element.matches("p,span,li,label,dt,dd,small,blockquote") ? 2
        : element.matches("a,button,[role=button]") ? 3
        : element.matches("img,picture,svg") ? 4 : 0;
      const color = rgba(style.backgroundColor, -1);
      if (kind === 0 && color < 0) continue;
      const x = ratio(left, width), y = ratio(top, height);
      const w = ratio(right, width) - x, h = ratio(bottom, height) - y;
      if (w > 0 && h > 0) tiles.push([x, y, w, h, color >= 0 ? color : colors[kind], kind]);
    }
    const scroller = document.scrollingElement;
    const scroll = ratio(window.scrollY, Math.max(1, (scroller?.scrollHeight || height) - height));
    return {width, height, scroll, tiles, ...(pointer ? {pointer} : {})};
  }

  function capture() {
    if (!consent || blocked || stopped || inflight || document.visibilityState !== "visible" || !sampleSession(session)) return;
    if (location.pathname !== path || Date.now() - sessionLast >= 1800000 || Date.now() < sessionLast) return;
    countFor(session);
    if (frames >= maxFrames) return;
    const now = performance.now();
    // Mutation and input activity mark the viewport dirty; a low-frequency
    // fallback catches CSS-only rendering changes without polling every frame.
    if (capturePage === pageID && !trackingChanges && now - lastCapture < 8000) return;
    const frame = viewport();
    if (!frame) return;
    trackingChanges = false;
    lastCapture = now;
    const signature = JSON.stringify(frame);
    if (signature === previous && capturePage === pageID) return;
    previous = signature;
    capturePage = pageID;
    const payload = JSON.stringify({kind:"replay",id:identifier(),page_id:pageID,visitor,session,replay:frame});
    if (payload.length > 4096) return;
    frames++;
    try { sessionStorage.setItem("yz.analytics.replay-budget", JSON.stringify({session,frames})); } catch {}
    if (pointer?.[2] === 1) pointer = [pointer[0], pointer[1], 0];
    const controller = new AbortController();
    inflight = controller;
    void fetch(endpoint.href,{method:"POST",body:payload,headers:{"Content-Type":"application/json"},credentials:"omit",cache:"no-store",keepalive:true,signal:controller.signal,redirect:"error",mode:"same-origin"})
      .then(reply => {
        if (inflight !== controller || !consent) return;
        if ([403,429,503].includes(reply.status)) { blocked = true; end(); }
        if (reply.status === 409) previous = "";
      })
      .catch(() => {})
      .finally(() => { if (inflight === controller) inflight = undefined; });
  }

  function mark() { trackingChanges = true; }
  function onPointer(event) {
    if (!event.isTrusted || !(event.target instanceof Element)) return;
    const concealed = event.composedPath().some(node => node instanceof Element && privateElement(node));
    if (concealed) {
      pointer = undefined;
    } else if (event.type === "click" || pointer?.[2] !== 1) {
      pointer = [ratio(event.clientX, window.innerWidth), ratio(event.clientY, window.innerHeight), event.type === "click" ? 1 : 0];
    }
    mark();
  }
  function begin() {
    if (!consent || blocked || timer !== undefined) return;
    previous = "";
    pointer = undefined;
    trackingChanges = true;
    observer.observe(document.documentElement, {subtree:true, childList:true, attributes:true});
    window.addEventListener("scroll", mark, {capture:true, passive:true});
    window.addEventListener("resize", mark, {passive:true});
    document.addEventListener("pointermove", onPointer, {capture:true, passive:true});
    document.addEventListener("click", onPointer, {capture:true, passive:true});
    timer = window.setInterval(capture, 2000);
  }
  function end() {
    if (timer !== undefined) window.clearInterval(timer);
    timer = undefined;
    inflight?.abort();
    inflight = undefined;
    pointer = undefined;
    observer.disconnect();
    window.removeEventListener("scroll", mark, true);
    window.removeEventListener("resize", mark);
    document.removeEventListener("pointermove", onPointer, true);
    document.removeEventListener("click", onPointer, true);
  }
  window.addEventListener("yunzhan:analytics-replay-consent", event => {
    consent = event.detail === true;
    if (consent) begin(); else end();
  });
  window.addEventListener("pagehide", end);
  window.addEventListener("pageshow", begin);
  begin();
})();
