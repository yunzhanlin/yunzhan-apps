package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Direct inserts here are private unit-test data, not installation receipts.
func wafSiteFixture(t *testing.T, s *Store, n int, server, status string, enabled *bool) string {
	t.Helper()
	id := fmt.Sprintf("%032x", n)
	settings := SiteSettings{WebServer: server, WAFEnabled: enabled, DocumentRoot: "private-document-root", ProxyURL: "https://private:fixture-password@upstream.test", PHP: &PHPSettings{}, TLS: &SiteTLS{CertificateID: ID()}, Domains: []string{"private-alias.example.test"}, Rewrite: "private-rewrite"}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at,settings_json) VALUES(?,?,?,?,?,'2026-10-11T00:00:00Z','2026-10-11T00:00:00Z',?)`, id, "fixture website", "site-"+id, "site-"+id+".example.test", status, string(raw)); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestWAFSiteChoicesRequireWAFMenusWithoutWebsiteAccess(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	nginx := wafSiteFixture(t, s, 1, "", "running", nil)
	off := false
	stopped := wafSiteFixture(t, s, 2, "nginx", "stopped", &off)
	apache := wafSiteFixture(t, s, 3, "apache", "running", nil)
	wafSiteFixture(t, s, 4, "nginx", "archived", nil)
	path := "/api/software/nginx-waf/sites"
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal("anonymous site read", w.Code)
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(name)); w.Code != 403 {
			t.Fatal("broadened site grant", name, w.Code)
		}
	}
	cookie := login("waf-admin")
	for _, denied := range []string{"/api/sites", "/api/sites/" + nginx + "/settings", "/api/sites/" + nginx + "/files", "/api/sites/" + nginx + "/logs", "/api/certificates"} {
		if w := wafTaskTestRead(a, denied, cookie); w.Code != 403 {
			t.Fatal("general website access added", denied, w.Code)
		}
	}
	for _, app := range []string{"nginx-waf", "apache-waf"} {
		w := wafTaskTestRead(a, "/api/software/"+app+"/sites", cookie)
		var out wafSitePage
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.NextCursor != "" {
			t.Fatal("scoped website list", app, w.Code)
		}
		if app == "nginx-waf" {
			if len(out.Sites) != 2 || out.Sites[0].ID != nginx || out.Sites[1].ID != stopped || !out.Sites[0].Settings.WAFEnabled || out.Sites[1].Settings.WAFEnabled || out.Sites[1].Status != "stopped" {
				t.Fatal("default, opt-out, stopped or archived website contract", out)
			}
		} else if len(out.Sites) != 1 || out.Sites[0].ID != apache || out.Sites[0].Settings.WebServer != "apache" {
			t.Fatal("Apache selector leaked Nginx sites", out)
		}
		for _, hidden := range []string{"document_root", "proxy_url", "php", "tls", "domains", "rewrite", "slug", "created_at", "settings_revision", "fixture-password", "private-"} {
			if strings.Contains(w.Body.String(), hidden) {
				t.Fatal("website/private field leaked", hidden)
			}
		}
		var shape map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &shape); err != nil || len(shape) != 2 {
			t.Fatal("page shape", err)
		}
		for _, v := range shape["sites"].([]any) {
			site := v.(map[string]any)
			if len(site) != 5 || len(site["settings"].(map[string]any)) != 2 {
				t.Fatal("non-minimal website reply", site)
			}
		}
	}
}

func TestWAFSiteChoicesBoundedStablePaginationIsReadOnly(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	for i := 1; i <= 260; i++ {
		wafSiteFixture(t, s, i, "nginx", "running", nil)
	}
	before, err := s.Sites()
	if err != nil {
		t.Fatal(err)
	}
	var auditBefore int
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	cookie := login("waf-admin")
	// Login itself is audited. Record after login before any read.
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	cursor := ""
	seen := []string{}
	for _, count := range []int{128, 128, 4} {
		path := "/api/software/nginx-waf/sites"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		w := wafTaskTestRead(a, path, cookie)
		var page wafSitePage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Sites) != count {
			t.Fatal("page bound", w.Code, len(page.Sites))
		}
		for _, site := range page.Sites {
			if len(seen) > 0 && site.ID <= seen[len(seen)-1] {
				t.Fatal("duplicate or unordered keyset page")
			}
			seen = append(seen, site.ID)
		}
		if count == 128 && page.NextCursor != page.Sites[count-1].ID || count == 4 && page.NextCursor != "" {
			t.Fatal("incorrect next cursor", page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if len(seen) != 260 {
		t.Fatal("silently partial inventory")
	}
	for _, suffix := range []string{"?", "?limit=1", "?cursor=", "?cursor=bad", "?cursor=" + ID() + "&cursor=" + ID(), "?cursor=" + ID() + "&extra=1", "?%ZZ=value"} {
		if w := wafTaskTestRead(a, "/api/software/nginx-waf/sites"+suffix, cookie); w.Code != 400 {
			t.Fatal("invalid pagination accepted", suffix, w.Code)
		}
	}
	if w := wafTaskTestRead(a, "/api/software/redis/sites", cookie); w.Code != 400 {
		t.Fatal("non-WAF selector", w.Code)
	}
	if w := wafTaskTestRead(a, "/api/software/nginx-waf/sites?cursor="+strings.Repeat("f", 32), cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"sites":[]`) {
		t.Fatal("valid empty page", w.Code)
	}
	after, err := s.Sites()
	var auditAfter, jobs int
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("GET modified website state", err)
	}
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&auditAfter); err != nil || auditBefore != auditAfter {
		t.Fatal("GET changed audit", err)
	}
	if err = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("GET queued executor jobs", err, jobs)
	}
}

func TestWAFSiteChoicesRejectCorruptionWithoutPartialOrInternalLeak(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	wafSiteFixture(t, s, 1, "nginx", "running", nil)
	bad := wafSiteFixture(t, s, 2, "nginx", "running", nil)
	for _, raw := range []string{`{"web_server":"nginx","waf_enabled":"no"}`, `{"web_server":"nginx","document_root":"` + strings.Repeat("x", 65536) + `"}`, `{not-json`} {
		if _, err := s.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, raw, bad); err != nil {
			t.Fatal(err)
		}
		w := wafTaskTestRead(a, "/api/software/nginx-waf/sites", cookie)
		if w.Code != 409 && w.Code != 503 || strings.Contains(w.Body.String(), `"sites"`) || strings.Contains(w.Body.String(), "SQL") || strings.Contains(w.Body.String(), "settings_json") {
			t.Fatal("corrupt inventory accepted or leaked partial data", w.Code, w.Body.String())
		}
	}
	if _, err := s.DB.Exec(`DROP TABLE sites`); err != nil {
		t.Fatal(err)
	}
	if w := wafTaskTestRead(a, "/api/software/nginx-waf/sites", cookie); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "SQL") {
		t.Fatal("database failure leaked details", w.Code)
	}
}
