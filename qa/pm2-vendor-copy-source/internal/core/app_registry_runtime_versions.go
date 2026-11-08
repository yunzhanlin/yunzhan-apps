package core

import (
	"strings"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

type registryInstalledRuntime struct {
	ID      string `json:"id"`
	Family  string `json:"family"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Program versions and application-package revisions are different namespaces.
// First compare actual programs against the fixed reviewed runtime; only then
// compare an actual, correctly scoped package receipt against the catalog.
// A read never creates a receipt or implies that a native install was performed.
func applyRegistryRuntimeStatus(status *AppRegistryStatus, app appcatalog.CatalogItem, rows []registryInstalledRuntime, receipts map[string]registryReceipt, platform string) {
	target := app.Target
	if target == "docker-auto" {
		releases := runtimecatalog.DockerReleaseOn(platform)
		if len(releases) == 1 {
			target = releases[0].ID
		}
	}
	release, reviewed := runtimecatalog.Find(target)
	family := map[string]string{"nginx": "nginx", "apache": "apache", "mysql": "mysql", "redis": "redis", "docker-manager": "docker"}[app.ID]
	if strings.HasPrefix(app.ID, "php-") {
		family = "php"
	}
	branch := versionBranch(app.Version)
	if reviewed && family == "php" {
		branch = versionBranch(release.Version)
	}
	seen := map[string]bool{}
	maximum := ""
	exact := false
	for _, row := range rows {
		if row.ID != target && (family == "" || row.Family != family) {
			continue
		}
		if reviewed && row.ID == target && row.Status == "installed" && (row.Family != release.Family || row.Version != release.Version) {
			status.StateKnown = false
			return
		}
		if family == "php" && !strings.HasPrefix(row.Version, branch+".") {
			continue
		}
		if seen[row.ID] {
			status.StateKnown = false
			return
		}
		seen[row.ID] = true
		if row.Status != "installed" {
			continue
		}
		if row.ID == "" || !appcatalog.ValidVersion(row.Version) {
			status.StateKnown = false
			return
		}
		status.Installed = true
		cmp, valid := appcatalog.CompareVersions(row.Version, maximum)
		if maximum == "" || valid && cmp > 0 {
			maximum = row.Version
		}
		if reviewed && row.ID == target {
			exact = true
		}
	}
	if !status.Installed {
		return
	}
	status.InstalledVersion, status.VersionSource, status.VersionKnown, status.Healthy = maximum, "upstream-runtime", true, true
	if !reviewed {
		// A signed publisher may announce a newer exact program before this
		// panel knows its source allowlist. This is an informational upgrade
		// notice only, never permission to fetch, install or adopt a receipt.
		if announced, valid := announcedUnreviewedRuntimeVersion(app, family); valid {
			if comparison, comparable := appcatalog.CompareVersions(maximum, announced); comparable && comparison < 0 {
				status.UpdateAvailable = true
				status.UpdateSupported = false
				status.UpdateKind = "panel-upgrade"
				status.UpdateDetail = "仓库已公布更新运行时，但当前面板没有已审核安装源；请先升级面板"
			}
		}
		return
	}
	cmp, valid := appcatalog.CompareVersions(maximum, release.Version)
	if !valid {
		status.StateKnown = false
		return
	}
	if cmp > 0 {
		return
	} // Never offer an older fixed program as an automatic update.
	if cmp < 0 {
		status.UpdateAvailable = true
		return
	}
	receipt, exists := receipts[app.ID+":"+target]
	if !exact || !exists {
		status.UpdateAvailable, status.UpdateKind = true, "runtime-package-review"
		return
	}
	if receipt.AppID != app.ID || receipt.Scope != target || (receipt.Target != target && !(app.Target == "docker-auto" && receipt.Target == "docker-auto")) || !appcatalog.ValidVersion(receipt.Version) || !registryDigestValid(receipt.SHA256) {
		status.StateKnown = false
		return
	}
	// Same-version different digest is not proof of the current immutable package.
	if receipt.Version == app.Version && registryDigestValid(app.SHA256) && receipt.SHA256 != app.SHA256 {
		status.StateKnown = false
		return
	}
	status.InstalledVersion, status.VersionSource = receipt.Version, "application-receipt"
	cmp, valid = appcatalog.CompareVersions(receipt.Version, app.Version)
	status.UpdateAvailable = valid && cmp < 0
}

// Parse only the presentation identity of a signed runtime announcement.
// Runtime approval remains exclusively runtimecatalog.Find and the fixed
// manifest/feature validators. Arbitrary labels and foreign PHP branches do not
// become updates merely because their application revision sorts higher.
func announcedUnreviewedRuntimeVersion(app appcatalog.CatalogItem, family string) (string, bool) {
	if app.Provider != "runtime" || family == "" || family == "docker" || !strings.HasPrefix(app.Target, family+"-") {
		return "", false
	}
	version := strings.TrimPrefix(app.Target, family+"-")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return "", false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return "", false
			}
		}
	}
	if _, comparable := appcatalog.CompareVersions(version, version); !comparable {
		return "", false
	}
	if app.Version != version {
		base, revision, found := strings.Cut(app.Version, "-compat")
		if !found || base != version || len(revision) == 0 || len(revision) > 4 || revision[0] == '0' {
			return "", false
		}
		for _, digit := range revision {
			if digit < '0' || digit > '9' {
				return "", false
			}
		}
	}
	if family == "php" {
		branch := map[string]string{"php-82": "8.2", "php-83": "8.3", "php-84": "8.4", "php-85": "8.5"}[app.ID]
		if branch == "" || parts[0]+"."+parts[1] != branch {
			return "", false
		}
	} else if app.ID != family {
		return "", false
	}
	return version, true
}
