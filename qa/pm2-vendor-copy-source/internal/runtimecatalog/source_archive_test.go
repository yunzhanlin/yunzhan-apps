package runtimecatalog

import "testing"

func TestArchiveFallbackPreservesReviewedIdentity(t *testing.T) {
	r := Apache[0]
	if got := SourceArchiveURL(r); got != "https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.gz" {
		t.Fatal(got)
	}
	r.SHA256 = "tampered"
	if SourceArchiveURL(r) != "" {
		t.Fatal("unreviewed metadata obtained archive fallback")
	}
	if SourceArchiveURL(Redis[0]) != "" {
		t.Fatal("arbitrary source family accepted")
	}
}
