package core

// AnalyticsSessionAppVersion fixes the existing browser session contract. A
// manifest must require the compiled session handler, not merely claim a new
// installed version. It grants no new collection scope or telemetry opt-in.
const AnalyticsSessionAppVersion = "2.3.1"

// The session patch preserves the already explicit HTML engine opt-in. Do not
// silently enable future or aliased application versions via a numeric range.
func AnalyticsHTMLAppVersionSupported(version string) bool {
	return version == "2.3.0" || version == AnalyticsSessionAppVersion
}
