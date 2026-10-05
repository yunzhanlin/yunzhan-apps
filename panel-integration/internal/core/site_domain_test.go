package core

import "testing"

func TestPrimaryDomainPreservesLegacyAndReservesExplicitDomain(t *testing.T) {
	s := testStore(t)
	old, err := s.CreateSite("old", "old-site", "legacy", "admin")
	if err != nil {
		t.Fatal(err)
	}
	var oldDomain string
	if err = s.DB.QueryRow(`SELECT s.domain FROM sites s JOIN jobs j ON j.site_id=s.id WHERE j.id=?`, old).Scan(&oldDomain); err != nil || oldDomain != "old-site.localhost" {
		t.Fatal("legacy domain", err)
	}
	job, err := s.CreateSiteAtDomain("web", "public-site", "www.example.test", "new", "admin")
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.CreateSiteAtDomain("web", "public-site", "www.example.test", "new", "admin")
	if err != nil || same != job {
		t.Fatal("idempotency", err)
	}
	if _, err = s.CreateSiteAtDomain("web", "public-site", "changed.example.test", "new", "admin"); err == nil {
		t.Fatal("changed domain reused request")
	}
	if _, err = s.CreateSiteAtDomain("other", "other-site", "www.example.test", "duplicate", "admin"); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	var sid string
	if err = s.DB.QueryRow(`SELECT site_id FROM site_domains WHERE domain='www.example.test'`).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO site_domains(domain,site_id,source_job) VALUES('reserved.example.test',?,?)`, sid, job); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSiteAtDomain("other", "other-site", "reserved.example.test", "reserved", "admin"); err == nil {
		t.Fatal("pending alias was stolen")
	}
	var count int
	if err = s.DB.QueryRow(`SELECT count(*) FROM sites`).Scan(&count); err != nil || count != 2 {
		t.Fatal("failed create left a site", count, err)
	}
}

func TestPrimaryDomainRejectsConfigurationInjection(t *testing.T) {
	s := testStore(t)
	for _, domain := range []string{"www.example.test;", "www.example.test\ninclude /etc/passwd", "https://www.example.test", "www.example.test:80", "www.example.test/path", "*.example.test", "127.0.0.1", "Example.test", "localhost", ".example.test"} {
		if _, err := s.CreateSiteAtDomain("bad", "invalid-site", domain, ID(), "admin"); err == nil {
			t.Fatal("accepted", domain)
		}
	}
}
