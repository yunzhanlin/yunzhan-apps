package runtimecatalog

import (
	"strings"
	"testing"
)

func TestNodeCatalogPinsArchitectureAndDigests(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		releases := NodeForArch(arch)
		if len(releases) != 2 {
			t.Fatalf("%s releases=%d", arch, len(releases))
		}
		want := map[string]string{"amd64": "linux-x64.tar.gz", "arm64": "linux-arm64.tar.gz"}[arch]
		for _, r := range releases {
			if r.Family != "node" || !strings.HasSuffix(r.URL, want) || len(r.SHA256) != 64 {
				t.Fatalf("bad %s release: %+v", arch, r)
			}
		}
	}
}

func TestRedisCatalogUsesOfficialPinnedSources(t *testing.T) {
	if len(Redis) != 2 {
		t.Fatalf("releases=%d", len(Redis))
	}
	for _, r := range Redis {
		if r.Family != "redis" || !strings.HasPrefix(r.URL, "https://download.redis.io/releases/") || len(r.SHA256) != 64 {
			t.Fatalf("bad redis release: %+v", r)
		}
	}
}

func TestMariaDBCatalogIsPinnedToOfficialX86Archives(t *testing.T) {
	if releases := MariaDBForArch("arm64"); len(releases) != 0 {
		t.Fatalf("arm64 unexpectedly advertised: %+v", releases)
	}
	releases := MariaDBForArch("amd64")
	if len(releases) != 2 {
		t.Fatalf("amd64 releases=%d", len(releases))
	}
	for _, r := range releases {
		if r.Family != "mariadb" || !strings.HasPrefix(r.URL, "https://archive.mariadb.org/") || !strings.HasSuffix(r.URL, "linux-systemd-x86_64.tar.gz") || len(r.SHA256) != 64 {
			t.Fatalf("bad MariaDB release: %+v", r)
		}
	}
}
