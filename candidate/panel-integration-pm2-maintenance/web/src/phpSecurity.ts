export interface PHPReleaseSafety {
  id: string;
  installation_allowed?: boolean;
  security?: { status: string; message: string; fixed_version: string; advisory: string; cves: string[] };
}

// Never infer a patch from an application-package revision, binary health,
// install receipt, or a similar version string. The server still enforces all
// mutation admission; these functions only present its reviewed source list.
export function phpSecurityFor(releases: readonly PHPReleaseSafety[], id: string) {
  const rows = releases.filter(release => release.id === id);
  return rows.length === 1 ? rows[0]?.security : undefined;
}

export function phpSecurityExposure(
  releases: readonly PHPReleaseSafety[],
  installed: readonly { id: string; family: string }[],
  sites: readonly { php_version_id: string }[],
) {
  const affected = new Set(releases.filter(row => row.security?.status === 'affected').map(row => row.id));
  return {
    installed: installed.filter(row => row.family === 'php' && affected.has(row.id)).map(row => row.id),
    sites: sites.filter(site => affected.has(site.php_version_id)).length,
  };
}
