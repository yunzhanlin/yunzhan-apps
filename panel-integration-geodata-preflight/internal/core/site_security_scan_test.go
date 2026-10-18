package core

import (
	"path/filepath"
	"testing"
)

func TestSiteSecurityScanPersistsAcrossStoreReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	report := SiteSecurityScanReport{ScannedAt: Now(), Sites: []SiteSecurityScan{{SiteID: ID(), Domain: "example.test", Status: "attention", Findings: []SiteSecurityFinding{{Path: ".env", Rule: "environment_file", Severity: "high"}}}}}
	if e = s.SaveSiteSecurityScan(report); e != nil {
		t.Fatal(e)
	}
	s.DB.Close()
	s, e = OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	loaded, e := s.LastSiteSecurityScan()
	if e != nil || len(loaded.Sites) != 1 || loaded.Sites[0].Findings[0].Path != ".env" {
		t.Fatalf("reopened scan: %+v %v", loaded, e)
	}
}
