package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"strings"
	"testing"
)

func phpSecurityRows(t *testing.T, s *Store) string {
	t.Helper()
	result := map[string][]map[string]any{}
	for _, table := range []string{"runtime_jobs", "audit_logs", "runtime_installations", "runtime_native_retry_grants", "runtime_install_bundles", "sites"} {
		rows, e := s.DB.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if e != nil {
			t.Fatal(e)
		}
		cols, e := rows.Columns()
		if e != nil {
			t.Fatal(e)
		}
		result[table] = []map[string]any{}
		for rows.Next() {
			values := make([]any, len(cols))
			pointers := make([]any, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if e = rows.Scan(pointers...); e != nil {
				t.Fatal(e)
			}
			row := map[string]any{}
			for i, c := range cols {
				row[c] = values[i]
			}
			result[table] = append(result[table], row)
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
	}
	raw, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func TestPHPSecurityNewAffectedInstallsAndBundlesFailWithoutMutation(t *testing.T) {
	for _, release := range runtimecatalog.PHP {
		t.Run(release.ID, func(t *testing.T) {
			s := testStore(t)
			before := phpSecurityRows(t, s)
			if _, e := s.QueueInstall(release.ID, ID(), "admin"); e == nil || !strings.Contains(e.Error(), "CVE-2026-109618") {
				t.Fatal(e)
			}
			if _, e := s.QueueInstallBundle([]string{runtimecatalog.Nginx[0].ID, release.ID}, ID(), "admin"); e == nil {
				t.Fatal("partial insecure bundle accepted")
			}
			if phpSecurityRows(t, s) != before {
				t.Fatal("denial wrote jobs, audits, grants, bindings or bundles")
			}
		})
	}
}
func TestPHPSecurityOldTicketReplayDoesNotGrantRebuildOrRewriteFailure(t *testing.T) {
	s := testStore(t)
	old := runtimecatalog.PHP[0]
	id, key := ID(), ID()
	if _, e := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,error,steps,idempotency_key,created_at,updated_at) VALUES(?,?,'install_runtime','failed','retained original failure','[]',?,?,?)", id, old.ID, key, Now(), Now()); e != nil {
		t.Fatal(e)
	}
	before := phpSecurityRows(t, s)
	got, e := s.QueueInstall(old.ID, key, "admin")
	if e != nil || got != id {
		t.Fatal(got, e)
	}
	if e = s.RetryRuntime(id, "admin"); e == nil {
		t.Fatal("affected retry granted")
	}
	if _, e = s.QueueInstall(runtimecatalog.PHPSecurity20261021[0].ID, key, "admin"); e == nil {
		t.Fatal("old key rebound")
	}
	if phpSecurityRows(t, s) != before {
		t.Fatal("old evidence changed or retry grant created")
	}
}
func TestPHPSecurityExistingAffectedInstallationCanBeReviewedWithoutSiteMigration(t *testing.T) {
	s := testStore(t)
	old := runtimecatalog.PHP[0]
	if e := s.RecordInstallation(old, "amd64"); e != nil {
		t.Fatal(e)
	}
	job, e := s.QueueInstall(old.ID, "old-installed-review", "admin")
	if e != nil || job == "" {
		t.Fatal(job, e)
	}
	before := phpSecurityRows(t, s)
	same, e := s.QueueInstall(old.ID, "old-installed-review", "admin")
	if e != nil || same != job || phpSecurityRows(t, s) != before {
		t.Fatal("review replay changed state", same, e)
	}
	bundle, e := s.QueueInstallBundle([]string{old.ID}, "skip-already-present", "admin")
	if e != nil || len(bundle.JobIDs) != 0 || len(bundle.Installed) != 1 {
		t.Fatal(bundle, e)
	}
	if _, e = s.DB.Exec("UPDATE runtime_installations SET status='retired' WHERE id=?", old.ID); e != nil {
		t.Fatal(e)
	}
	before = phpSecurityRows(t, s)
	if _, e = s.QueueInstall(old.ID, "no-rebuild-retired", "admin"); e == nil || phpSecurityRows(t, s) != before {
		t.Fatal("retired history allowed insecure reconstruction", e)
	}
}
func TestPHPSecurityPatchedQueueUsesSeparateExactIdentities(t *testing.T) {
	s := testStore(t)
	for _, r := range runtimecatalog.PHPSecurity20261021 {
		key := ID()
		id, e := s.QueueInstall(r.ID, key, "admin")
		if e != nil || id == "" {
			t.Fatal(r.ID, id, e)
		}
		before := phpSecurityRows(t, s)
		same, e := s.QueueInstall(r.ID, key, "admin")
		if e != nil || same != id || phpSecurityRows(t, s) != before {
			t.Fatal(r.ID, same, e)
		}
	}
	var sites int
	if e := s.DB.QueryRow("SELECT count(*) FROM sites").Scan(&sites); e != nil || sites != 0 {
		t.Fatal("install changed bindings", sites, e)
	}
}
