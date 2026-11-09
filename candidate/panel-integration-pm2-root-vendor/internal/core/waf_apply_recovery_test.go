package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"local/panel/internal/appcatalog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func wafRecoveryQueue(t *testing.T, s *Store, app, key string, u identity) string {
	t.Helper()
	cfg := DefaultWAFConfig()
	if app == "apache-waf" {
		cfg = DefaultApacheWAFConfig()
	}
	job, err := s.queueWAFApplyRequest(app, "configure", WAFSettings(cfg), key, u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	return job
}

func TestWAFApplyRecoveryActualStoreReopenOwnAccountAndClosedReadOnlyAPIs(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	cookie := login(u.Username)
	job := wafRecoveryQueue(t, s, "nginx-waf", "owned-original-configure", u)
	var index int
	var name, path string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&index, &name, &path); err != nil || name != "main" || path == "" {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.DB = reopened.DB
	base := "/api/software/nginx-waf/requests"
	w := wafTaskTestRead(a, base, cookie)
	var page wafApplyRequestPage
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &page) != nil || !page.ReadOnly || len(page.Entries) != 1 || page.Entries[0].ID != job || page.NextCursor != "" || page.Entries[0].SignedInstall {
		t.Fatal("actual reopened own metadata", w.Code, w.Body.String())
	}
	w = wafTaskTestRead(a, base+"/"+job, cookie)
	var original wafApplyOriginalRequest
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &original) != nil || !original.ReadOnly || original.Request.ID != job || original.Request.Kind != "software_configure" || original.Request.State != "succeeded" || original.Error != "" || !reflect.DeepEqual(original.Settings, WAFSettings(DefaultWAFConfig())) {
		t.Fatal("original normalized settings read", w.Code, w.Body.String())
	}
	for _, private := range []string{"actor_id", "username", "idempotency_key", "payload", "password", "steps"} {
		if strings.Contains(w.Body.String(), `"`+private+`"`) {
			t.Fatal("unrelated/private metadata exposed", private)
		}
	}
	other := accessUser(t, s, "other-recovery-admin", "admin", []string{"runtimes", "security"})
	otherCookie := login(other.Username)
	w = wafTaskTestRead(a, base, otherCookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Entries) != 0 {
		t.Fatal("other actor inherited requests", w.Code, w.Body.String())
	}
	if w := wafTaskTestRead(a, base+"/"+job, otherCookie); w.Code != 404 {
		t.Fatal("other actor selected original", w.Code)
	}
	// Reuse actual authenticated cookies across read-only routes; do not
	// disable or relax the real per-IP login limiter to satisfy this fixture.
	forbiddenCookies := map[string]*http.Cookie{}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		forbiddenCookies[name] = login(name)
	}
	for _, p := range []string{base, base + "/" + job} {
		if w := wafTaskTestRead(a, p, nil); w.Code != 401 {
			t.Fatal("anonymous recovery", w.Code)
		}
		for name, cookie := range forbiddenCookies {
			if w := wafTaskTestRead(a, p, cookie); w.Code != 403 {
				t.Fatal("expanded recovery grant", name, w.Code)
			}
		}
		for _, suffix := range []string{"?", "?actor_id=" + u.ID, "?cursor=BAD", "?path=/etc/shadow"} {
			if w := wafTaskTestRead(a, p+suffix, cookie); w.Code != 400 {
				t.Fatal("caller selected recovery ownership/path", w.Code)
			}
		}
	}
	for _, table := range []string{"runtime_jobs", "waf_apply_requests", "audit_logs WHERE action='software.configure'"} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 1 {
			t.Fatal("read-only recovery changed original records", table, count, err)
		}
	}
	t.Log("Actual private SQLite close/reopen, authenticated UID-bound reads and original stored settings; not executor, signature verification, installation, process crash, cold boot or power loss")
}

func TestWAFApplyRecoveryKeysetBoundAndCorruptLookaheadNeverReturnPartialPage(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	cookie := login(u.Username)
	ids := []string{}
	for i := 0; i < 25; i++ {
		ids = append(ids, wafRecoveryQueue(t, s, "nginx-waf", ID(), u))
	}
	sort.Strings(ids)
	base := "/api/software/nginx-waf/requests"
	w := wafTaskTestRead(a, base, cookie)
	var first, second wafApplyRequestPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Entries) != 20 || first.NextCursor != ids[19] {
		t.Fatal("bounded first keyset", w.Code, w.Body.String())
	}
	for i, row := range first.Entries {
		if row.ID != ids[i] {
			t.Fatal("unordered/replaced page identity")
		}
	}
	w = wafTaskTestRead(a, base+"?cursor="+first.NextCursor, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || len(second.Entries) != 5 || second.NextCursor != "" {
		t.Fatal("last keyset", w.Code, w.Body.String())
	}
	for i, row := range second.Entries {
		if row.ID != ids[i+20] {
			t.Fatal("second page identity")
		}
	}
	// The 21st lookahead is checked too; corruption there cannot manufacture
	// a complete first page or quietly conceal a remaining original identity.
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET payload=payload||' ' WHERE id=?`, ids[20]); err != nil {
		t.Fatal(err)
	}
	w = wafTaskTestRead(a, base, cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"entries"`) {
		t.Fatal("corrupt lookahead became partial page", w.Code, w.Body.String())
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_apply_requests`).Scan(&count); err != nil || count != 25 {
		t.Fatal("corrupt evidence repaired/deleted", count, err)
	}
}

func TestWAFApplyRecoveryBothWAFKindsRetainEvidenceWithoutSameNameAccountInheritance(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	cookie := login(u.Username)
	jobs := map[string]string{}
	for _, app := range []string{"nginx-waf", "apache-waf"} {
		job := wafRecoveryQueue(t, s, app, ID(), u)
		jobs[app] = job
		if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='cancelled',error='Explicit cancelled outcome fixture, not a native execution' WHERE id=?`, job); err != nil {
			t.Fatal(err)
		}
		w := wafTaskTestRead(a, "/api/software/"+app+"/requests/"+job, cookie)
		var original wafApplyOriginalRequest
		cfg := DefaultWAFConfig()
		if app == "apache-waf" {
			cfg = DefaultApacheWAFConfig()
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &original) != nil || original.Request.TargetID != app || original.Request.State != "cancelled" || original.Error == "" || !reflect.DeepEqual(original.Settings, WAFSettings(cfg)) {
			t.Fatal("both engine original cancelled identities", app, w.Code, w.Body.String())
		}
	}
	// Exercise the actual account-removal transaction, including session
	// revocation. Do not disable SQLite foreign keys to remove a live session.
	owner := accessUser(t, s, "recovery-owner", "admin", nil)
	if _, err := a.manageAppUsers(context.Background(), owner, "delete", AppModuleInput{Username: u.Username}); err != nil {
		t.Fatal(err)
	}
	recreated := accessUser(t, s, u.Username, "admin", []string{"runtimes", "security"})
	if recreated.ID == u.ID {
		t.Fatal("fixture reused deleted UID")
	}
	newCookie := login(recreated.Username)
	for app, job := range jobs {
		base := "/api/software/" + app + "/requests"
		w := wafTaskTestRead(a, base, newCookie)
		var page wafApplyRequestPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || !page.ReadOnly || len(page.Entries) != 0 || page.NextCursor != "" {
			t.Fatal("recreated account inherited original directory", app, w.Code, w.Body.String())
		}
		if w := wafTaskTestRead(a, base+"/"+job, newCookie); w.Code != 404 {
			t.Fatal("recreated UID adopted deleted actor's original", app, w.Code)
		}
		if w := wafTaskTestRead(a, base, cookie); w.Code != 401 {
			t.Fatal("deleted actor session still authorized", app, w.Code)
		}
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_apply_requests WHERE actor_id=?`, u.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("deleted actor's immutable evidence removed or reattributed", count, err)
	}
	t.Log("Both WAF request/settings/terminal-state HTTP contracts and retained deleted-actor evidence in real private SQLite; terminal outcomes are explicit fixtures, not native execution")
}

func TestWAFApplyRecoveryLegacySignedBindingIsReadWithoutBackfillOrLiveFetch(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	cookie := login(u.Username)
	item := appcatalog.CatalogItem{ID: "nginx-waf", Version: WAFVersion, SHA256: strings.Repeat("1", 64), Provider: "panel-module", Target: "nginx-waf"}
	settings := WAFSettings(DefaultWAFConfig())
	in := registryInstallInput{Settings: settings}
	job, err := s.queueSoftwareActionBound("nginx-waf", "install", settings, "", "legacy-registry-owned", u.Username, s.bindRegistryInstall(item, "nginx-waf", "legacy-registry-owned", u.ID, in))
	if err != nil {
		t.Fatal(err)
	}
	w := wafTaskTestRead(a, "/api/software/nginx-waf/requests/"+job, cookie)
	var out wafApplyOriginalRequest
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.ReadOnly || !out.Request.SignedInstall || out.Request.Kind != "software_install" || out.Request.State != "queued" {
		t.Fatal("legacy immutable store binding", w.Code, w.Body.String())
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_apply_requests`).Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy request backfilled", count, err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	unbound, err := s.QueueSoftwareAction("nginx-waf", "configure", settings, "unbound-hidden", u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if w := wafTaskTestRead(a, "/api/software/nginx-waf/requests/"+unbound, cookie); w.Code != 404 {
		t.Fatal("unbound old job adopted", w.Code)
	}
	t.Log("Synthetic CatalogItem is an explicit SQLite binding fixture, not actual detached signature/catalog verification or installed software evidence")
}

func TestWAFApplyRecoveryUnavailableAndChangedKindFailClosed(t *testing.T) {
	for _, kind := range []string{"table-unavailable", "kind-replaced", "digest-replaced", "creation-time-replaced", "binding-time-missing"} {
		t.Run(kind, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			job := wafRecoveryQueue(t, s, "nginx-waf", ID(), u)
			cookie := login(u.Username)
			statement := `ALTER TABLE waf_apply_requests RENAME TO owned_unavailable_waf_requests`
			args := []any{}
			if kind == "kind-replaced" {
				statement = `UPDATE runtime_jobs SET kind='software_install' WHERE id=?`
				args = []any{job}
			}
			if kind == "digest-replaced" {
				statement = `UPDATE waf_apply_requests SET payload_sha256=? WHERE job_id=?`
				args = []any{strings.Repeat("b", 64), job}
			}
			if kind == "creation-time-replaced" {
				statement = `UPDATE runtime_jobs SET created_at='2026-10-10T00:00:00Z' WHERE id=?`
				args = []any{job}
			}
			if kind == "binding-time-missing" {
				statement = `UPDATE waf_apply_requests SET created_at='' WHERE job_id=?`
				args = []any{job}
			}
			if _, err := s.DB.Exec(statement, args...); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/software/nginx-waf/requests", "/api/software/nginx-waf/requests/" + job} {
				w := wafTaskTestRead(a, path, cookie)
				if w.Code != 503 || strings.Contains(w.Body.String(), `"entries":[]`) || strings.Contains(w.Body.String(), "owned_unavailable") {
					t.Fatal("unavailable/corrupt became empty or raw SQL", w.Code, w.Body.String())
				}
			}
			if _, err := s.readWAFApplyOriginal("nginx-waf", ID(), job); kind != "table-unavailable" && !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("foreign actor could inspect malformed original", err)
			}
		})
	}
}
