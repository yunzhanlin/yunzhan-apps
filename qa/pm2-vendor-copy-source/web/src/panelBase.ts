// Public HTTP is served below /<entry>/; the loopback and HTTPS entries use /.
export function panelBase(): string {
  const match = /^\/([A-Za-z0-9]{8,10}|[a-f0-9]{32,64})\//.exec(window.location.pathname);
  return match ? `/${match[1]}` : "";
}

export function apiURL(path: string): string {
  return `${panelBase()}/api${path}`;
}
