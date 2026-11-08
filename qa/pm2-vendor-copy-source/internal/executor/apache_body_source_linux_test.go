//go:build linux

package executor

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
)

func TestApacheBodySourceClosedTLSRedirectAndUnreviewedBeforeIO(t *testing.T) {
	for _, raw := range []string{
		apacheBodySources()[0].URL,
		apacheBodySources()[1].URL,
		"https://release-assets.githubusercontent.com/github-production-release-asset/123/pinned?signature=opaque",
	} {
		u, err := url.Parse(raw)
		if err != nil || !apacheBodySourceRedirectAllowed(u, 3) {
			t.Fatal("reviewed official redirect rejected", err)
		}
	}
	for _, raw := range []string{
		"http://deb.debian.org/debian/pool/main/y/yajl/yajl_2.1.0.orig.tar.gz",
		"https://deb.debian.org:443/debian/pool/main/y/yajl/yajl_2.1.0.orig.tar.gz",
		"https://user:secret@deb.debian.org/debian/pool/main/y/yajl/yajl_2.1.0.orig.tar.gz",
		apacheBodySources()[1].URL + "?token=x",
		apacheBodySources()[0].URL + "#other",
		"https://deb.debian.org/debian/pool/main/y/yajl/yajl_2.1.0-5.debian.tar.xz",
		"https://github.com/owasp-modsecurity/ModSecurity/releases/download/v3.0.17/modsecurity-v3.0.17.tar.gz",
		"https://release-assets.githubusercontent.com/other/path",
		"https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/123/source",
	} {
		u, _ := url.Parse(raw)
		if apacheBodySourceRedirectAllowed(u, 1) {
			t.Fatal("unreviewed redirect accepted", raw)
		}
	}
	u, _ := url.Parse(apacheBodySources()[0].URL)
	if apacheBodySourceRedirectAllowed(u, 4) || apacheBodySourceRedirectAllowed(nil, 0) {
		t.Fatal("redirect limit/nil accepted")
	}
	bad := apacheBodySources()[0]
	bad.URL = "http://127.0.0.1:1/not-contacted"
	root := t.TempDir()
	if downloadApacheBodySource(context.Background(), bad, filepath.Join(root, "not-created")) == nil || extractApacheBodySource(context.Background(), bad, "/does-not-exist", filepath.Join(root, "not-created")) == nil {
		t.Fatal("unreviewed source reached shared IO")
	}
}
