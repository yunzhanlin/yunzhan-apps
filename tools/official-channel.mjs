// Publisher-controlled build metadata, never a client-supplied URL or key.
export function officialCatalogBaseURL(channel = 'stable') {
  if (channel === 'stable') return 'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main';
  if (channel === 'candidate') return 'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/refs/heads/codex/app-candidate/candidate';
  throw new Error('unknown official application channel; no fallback or URL override');
}
