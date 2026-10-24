package core

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPanelAccessValidationCommitAndRevision(t *testing.T) {
	s := testStore(t)
	initial, e := s.PanelAccess()
	if e != nil || initial.Domain != "panel.localhost" || initial.Port != 19443 || initial.HTTPSEnabled || initial.Revision != 1 {
		t.Fatal("unexpected initial panel access", initial, e)
	}
	key, e := s.accountKey(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s.encryptionKey = key
	now := time.Now()
	leaf, private, ca := certificateFixture(t, []string{"panel.localhost"}, now.Add(-time.Hour), now.Add(24*time.Hour), x509.ExtKeyUsageServerAuth)
	cert, e := s.SaveCertificate("panel", leaf+ca, private, "panel-certificate", "admin")
	if e != nil {
		t.Fatal(e)
	}
	requested := PanelAccess{Domain: " PANEL.LOCALHOST ", Port: 19444, CertificateID: cert.ID, AllowedCIDRs: []string{"192.168.1.17/24", "192.168.1.0/24", " 10.0.0.0/8 "}, HTTPSEnabled: true, Revision: initial.Revision}
	updated, e := s.CommitPanelAccess(requested, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if updated.Domain != "panel.localhost" || updated.Port != 19444 || updated.Revision != 2 || len(updated.AllowedCIDRs) != 2 || updated.AllowedCIDRs[0] != "192.168.1.0/24" {
		t.Fatal("panel access was not normalized", updated)
	}
	if _, e = s.CommitPanelAccess(requested, "admin"); e == nil {
		t.Fatal("stale revision accepted")
	}
	for _, invalid := range []PanelAccess{
		{Domain: "panel.localhost", Port: 19100, Revision: updated.Revision},
		{Domain: "panel.localhost", Port: 65536, Revision: updated.Revision},
		{Domain: "bad domain", Revision: updated.Revision},
		{Domain: "panel.localhost", AllowedCIDRs: []string{"127.0.0.1"}, Revision: updated.Revision},
		{Domain: "other.localhost", CertificateID: cert.ID, HTTPSEnabled: true, Revision: updated.Revision},
		{Domain: "panel.localhost", HTTPSEnabled: true, Revision: updated.Revision},
	} {
		if _, e = s.ValidatePanelAccess(invalid); e == nil {
			t.Fatal("invalid panel access accepted", invalid)
		}
	}
}

func TestHTTPSProxyOriginAndSecureCookie(t *testing.T) {
	a := &Server{Config: Config{Origin: "http://127.0.0.1:19100"}}
	r := httptest.NewRequest(http.MethodPost, "http://panel.localhost:19443/api/login", strings.NewReader(`{}`))
	r.Host = "panel.localhost:19443"
	r.Header.Set("X-Forwarded-Proto", "https")
	if !a.originAllowed(r, "https://panel.localhost:19443") {
		t.Fatal("same HTTPS proxy origin rejected")
	}
	if a.originAllowed(r, "https://attacker.invalid") || a.originAllowed(r, "http://panel.localhost:19443") {
		t.Fatal("foreign or downgraded origin accepted")
	}
	w := httptest.NewRecorder()
	a.cookie(w, r, "secret", 60)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("HTTPS proxy cookie flags missing", cookies)
	}
}

func TestPublicHTTPEntryValidationAndOriginBoundary(t *testing.T) {
	s := testStore(t)
	entry := "aB3dE5fG7h"
	v, e := s.PanelAccess()
	if e != nil {
		t.Fatal(e)
	}
	v.HTTPEnabled, v.HTTPIP, v.HTTPPort, v.HTTPEntry = true, "192.0.2.10", 27727, entry
	updated, e := s.CommitPanelAccess(v, "admin")
	if e != nil || !updated.HTTPEnabled || updated.HTTPEntry != entry {
		t.Fatal(updated, e)
	}
	for _, bad := range []PanelAccess{
		{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "bad", HTTPPort: 27727, HTTPEntry: entry},
		{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 19443, HTTPEntry: entry},
		{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 27727, HTTPEntry: "../../api/login"},
		{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 27727, HTTPEntry: "abcdefghijk"},
	} {
		if _, e := s.ValidatePanelAccess(bad); e == nil {
			t.Fatal("unsafe public entry accepted", bad)
		}
	}
	a := &Server{Config: Config{Origin: "http://127.0.0.1:19100"}}
	r := httptest.NewRequest(http.MethodPost, "http://192.0.2.10:27727/api/login", strings.NewReader(`{}`))
	r.Host = "192.0.2.10:27727"
	r.Header.Set("X-Forwarded-Proto", "http")
	if a.originAllowed(r, "http://192.0.2.10:27727") {
		t.Fatal("HTTP proxy origin accepted without managed ingress")
	}
	r.Header.Set("X-Panel-Connection", "public-http")
	if !a.originAllowed(r, "http://192.0.2.10:27727") {
		t.Fatal("managed same-origin HTTP rejected")
	}
	if a.originAllowed(r, "http://attacker.invalid") || a.originAllowed(r, "https://192.0.2.10:27727") {
		t.Fatal("foreign HTTP origin accepted")
	}
}

func TestPanelEntryGeneratedOnFirstStoreOpen(t *testing.T) {
	s := testStore(t)
	v, e := s.PanelAccess()
	if e != nil || !panelHTTPEntryPattern.MatchString(v.HTTPEntry) || len(v.HTTPEntry) != 10 {
		t.Fatal("missing cryptographic install entry", v.HTTPEntry, e)
	}
	if _, e = s.CommitPanelAccess(v, "admin"); e != nil {
		t.Fatal("disabled entry should persist", e)
	}
	again, e := s.PanelAccess()
	if e != nil || again.HTTPEntry != v.HTTPEntry {
		t.Fatal("disabled entry changed", again.HTTPEntry, e)
	}
}

func TestPanelAccessPortMigrationPreservesExistingEntry(t *testing.T) {
	s := testStore(t)
	if _, e := s.DB.Exec(`UPDATE panel_access SET domain='panel.example.test',revision=7; DELETE FROM schema_migrations WHERE version=34; ALTER TABLE panel_access DROP COLUMN port;`); e != nil {
		t.Fatal(e)
	}
	if e := s.migratePanelAccess(); e != nil {
		t.Fatal(e)
	}
	v, e := s.PanelAccess()
	if e != nil || v.Domain != "panel.example.test" || v.Revision != 7 || v.Port != 19443 {
		t.Fatal("panel entry lost during migration", v, e)
	}
	if e = s.migratePanelAccess(); e != nil {
		t.Fatal("repeat migration failed", e)
	}
}
