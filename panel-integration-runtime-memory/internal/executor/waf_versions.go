package executor

import "local/panel/internal/core"

// A version-bound application update is required; historical rules remain
// byte-exact so the normal migration can verify the original installation.
func wafBoundHealthVersion(version string) bool { return version == "2.5.2" }

func wafRetentionVersion(version string) bool {
	return version == "2.5.0" || version == "2.5.1" || version == core.WAFVersion
}
func wafBodyRotationVersion(version string) bool {
	return version == "2.4.0" || wafRetentionVersion(version)
}
