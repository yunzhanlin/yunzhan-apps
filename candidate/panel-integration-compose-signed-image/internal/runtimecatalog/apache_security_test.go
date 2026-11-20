package runtimecatalog

import "testing"

func TestApacheSecurityAdmissionPreservesHistoricalManifestAndBlocksRebuild(t *testing.T) {
	old, ok := Find(ApacheLegacyID)
	if !ok || old.Version != "2.4.68" || old.SHA256 != "ed9a9d4500fb48bb28eaffb3ba71d06ccf86d498fa13ab9f781da010cc488498" || old.Source != "Apache HTTP Server 官方源码 · 官方 SHA-256 清单" {
		t.Fatal("legacy immutable identity changed")
	}
	if RuntimeInstallAdmission(old) == nil {
		t.Fatal("historical affected runtime admitted for new build")
	}
	fixed, ok := Find(ApacheCurrentID)
	if !ok || RuntimeInstallAdmission(fixed) != nil || fixed.SHA256 != "6b0433674ded858d2ac01e95345935ce127d5d287471762f0a7f10f4969cbfe8" {
		t.Fatal("fixed verified runtime unavailable")
	}
	altered := fixed
	altered.URL = "https://example.invalid/unreviewed.tar.gz"
	if RuntimeInstallAdmission(altered) == nil {
		t.Fatal("unreviewed source admitted")
	}
	choices := ApacheReleaseChoices()
	if len(choices) != 2 || !choices[0].InstallationAllowed || choices[1].InstallationAllowed {
		t.Fatal("catalogue failed to separate history from new installation")
	}
}
