package core

import "local/panel/internal/appcatalog"

// A protocol migration notice, never a package receipt or operation authority.
// The exact owned legacy template may predate package receipts, and semver
// correctly places upstream 1.6.45 above prerelease-shaped compat4. Keep that
// upstream display and old receipt policy unchanged. Existing Unix/foreign
// profiles, changed images, other apps, future catalogs and real newer receipts
// cannot borrow this notice to request a duplicate or in-place replacement.
func registryLegacyMemcachedUnixReview(app appcatalog.CatalogItem, profile string, images []string, hasPackageReceipt bool) bool {
	if hasPackageReceipt || app.ID != "memcached" || app.Provider != "compose" || app.Target != "memcached-cache" || app.Version != appcatalog.MemcachedUnixVersion || profile != "" || len(images) != 1 {
		return false
	}
	return images[0] == "memcached:1.6.45-alpine" || images[0] == appcatalog.MemcachedDigestImage
}
