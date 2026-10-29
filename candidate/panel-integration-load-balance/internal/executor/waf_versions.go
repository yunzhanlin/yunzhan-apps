package executor

import "local/panel/internal/core"

// Closed prototype/future versions only until the normal signed app update.
// 2.6 includes this boundary as part of its complete country handler contract.
func wafBoundHealthVersion(version string) bool {
	return version == "2.5.2" || version == core.WAFCountryDataVersion
}

func wafRetentionVersion(version string) bool {
	return version == "2.5.0" || version == "2.5.1" || version == "2.5.2" || version == core.WAFCountryDataVersion
}
func wafBodyRotationVersion(version string) bool {
	return version == "2.4.0" || wafRetentionVersion(version)
}
