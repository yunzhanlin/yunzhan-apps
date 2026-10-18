package core

import (
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestRuntimeBundleAtomicQueueAndIdempotency(t *testing.T) {
	s := testStore(t)
	releases := []string{runtimecatalog.Nginx[0].ID, runtimecatalog.PHP[0].ID}
	first, e := s.QueueInstallBundle(releases, "bundle-test-1", "admin")
	if e != nil || len(first.JobIDs) != 2 || len(first.Installed) != 0 {
		t.Fatal(first, e)
	}
	repeated, e := s.QueueInstallBundle(releases, "bundle-test-1", "admin")
	if e != nil || repeated.JobIDs[0] != first.JobIDs[0] || repeated.JobIDs[1] != first.JobIDs[1] {
		t.Fatal("retry did not return the original complete result", repeated, e)
	}
	var jobs, audits int
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&jobs)
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='runtime.install'`).Scan(&audits)
	if jobs != 2 || audits != 2 {
		t.Fatal("retry created duplicate jobs or audit records", jobs, audits)
	}
	if _, e = s.QueueInstallBundle([]string{releases[1], releases[0]}, "bundle-test-1", "admin"); e == nil {
		t.Fatal("idempotency key accepted a different ordered request")
	}
}

func TestRuntimeBundleRollsBackOnActiveConflict(t *testing.T) {
	s := testStore(t)
	php := runtimecatalog.PHP[0].ID
	nginx := runtimecatalog.Nginx[0].ID
	if _, e := s.QueueInstall(php, "single-php", "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QueueInstallBundle([]string{nginx, php}, "conflicted-bundle", "admin"); e == nil {
		t.Fatal("active job conflict accepted")
	}
	var jobs, bundles int
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id=?`, nginx).Scan(&jobs)
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_install_bundles WHERE idempotency_key='conflicted-bundle'`).Scan(&bundles)
	if jobs != 0 || bundles != 0 {
		t.Fatal("partial bundle was committed", jobs, bundles)
	}
}

func TestRuntimeBundleSkipsInstalledAndRejectsDuplicateFamily(t *testing.T) {
	s := testStore(t)
	nginx := runtimecatalog.Nginx[0]
	php := runtimecatalog.PHP[0].ID
	if e := s.RecordInstallation(nginx, "amd64"); e != nil {
		t.Fatal(e)
	}
	result, e := s.QueueInstallBundle([]string{nginx.ID, php}, "installed-bundle", "admin")
	if e != nil || len(result.JobIDs) != 1 || len(result.Installed) != 1 || result.Installed[0] != nginx.ID {
		t.Fatal(result, e)
	}
	if _, e = s.QueueInstallBundle([]string{runtimecatalog.Nginx[0].ID, runtimecatalog.Nginx[1].ID}, "duplicate-family", "admin"); e == nil {
		t.Fatal("two Nginx versions in one bundle accepted")
	}
	if _, e = s.QueueInstallBundle([]string{nginx.ID, "unverified-version"}, "unknown-version", "admin"); e == nil {
		t.Fatal("unknown runtime release accepted")
	}
}
