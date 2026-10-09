package executor

// These sources are part of the signed panel, never settings supplied by a
// catalog, website or request. The archive SHA is mandatory in addition to TLS.
func analyticsHTMLSources(version string) ([]wafEngineSource, bool) {
	nginx, ok := wafNginxBuildSource(version)
	if !ok || version == "1.18.0" {
		return nil, false
	}
	return []wafEngineSource{
		{"analytics-njs", "1.0.1", "https://github.com/nginx/njs/releases/download/1.0.1/njs-1.0.1.tar.gz", "8bb0eb931a934da5d2efc87032f60072242145760a77f2396656930bb60ad2c7", "official fixed release SHA-256; original C file pinned before the reviewed deletion fix; no PGP claim"},
		{"analytics-quickjs", "535a7c250ff4a577ec36c3e103daab6dadeea650", "https://codeload.github.com/bellard/quickjs/tar.gz/535a7c250ff4a577ec36c3e103daab6dadeea650", "23ceaa703c8e88716f33720f893221b65faa3ac6375b8a1eb7516af4b5d5f5da", "official repository fixed commit, SHA-256 and archive Git metadata; no PGP claim"},
		nginx,
	}, true
}

func reviewedAnalyticsHTMLSource(source wafEngineSource) bool {
	// The reviewed nginx source lookup already restricts versions/URL/hash.
	if source.Name == "nginx-build" {
		want, ok := wafNginxBuildSource(source.Version)
		return ok && source.Version != "1.18.0" && want == source
	}
	sources, _ := analyticsHTMLSources("1.24.0")
	for _, want := range sources[:2] {
		if want == source {
			return true
		}
	}
	return false
}
