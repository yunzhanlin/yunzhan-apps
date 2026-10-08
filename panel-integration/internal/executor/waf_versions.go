package executor

import "local/panel/internal/core"

func wafRetentionVersion(version string) bool {
	return version == "2.5.0" || version == core.WAFVersion
}
func wafBodyRotationVersion(version string) bool {
	return version == "2.4.0" || wafRetentionVersion(version)
}
