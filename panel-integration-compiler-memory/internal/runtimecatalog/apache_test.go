package runtimecatalog

import (
	"strings"
	"testing"
)

func TestApacheCatalogIsPinnedToOfficialHTTPS(t *testing.T) {
	if len(Apache) == 0 {
		t.Fatal("Apache catalog is empty")
	}
	for _, r := range Apache {
		if r.Family != "apache" || !strings.HasPrefix(r.ID, "apache-") {
			t.Fatalf("invalid Apache release identity: %#v", r)
		}
		if !strings.HasPrefix(r.URL, "https://downloads.apache.org/httpd/httpd-") {
			t.Fatalf("Apache source is not on the official host: %s", r.URL)
		}
		if len(r.SHA256) != 64 {
			t.Fatalf("Apache release does not have a pinned SHA-256: %s", r.ID)
		}
		if got := r.CLI(); !strings.HasSuffix(got, "/bin/httpd") {
			t.Fatalf("Apache CLI path is wrong: %s", got)
		}
	}
}
