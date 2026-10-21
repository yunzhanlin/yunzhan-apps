package runtimecatalog

// Archived upstream releases keep the same bytes/digest and runtime identity.
// A fallback must not change an existing installation's immutable manifest.
func SourceArchiveURL(release Release) string {
	known, ok := Find(release.ID)
	if !ok || known != release {
		return ""
	}
	switch release.Family {
	case "apache":
		return "https://archive.apache.org/dist/httpd/httpd-" + release.Version + ".tar.gz"
	}
	return ""
}
