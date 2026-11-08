package core

import (
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestLifecycleTransactionsAndUncertainProtection(t *testing.T) {
	s := testStore(t)
	r, _ := runtimecatalog.Find("php-8.4.25")
	if e := s.RecordInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	key := ID()
	id, e := s.QueueRuntimeLifecycle(r.ID, "retire", key, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if repeated, e := s.QueueRuntimeLifecycle(r.ID, "retire", key, "admin"); e != nil || id != repeated {
		t.Fatal("idempotency", e)
	}
	if s.RuntimeInstalled(r.ID) {
		t.Fatal("retiring version remains available")
	}
	// Insert directly to simulate a caller whose preflight completed before the lifecycle transaction.
	_, e = s.DB.Exec(`INSERT INTO mysql_servers(id,name,release_id,port,status,created_at) VALUES(?,?,?,13306,'provisioning',?)`, ID(), "race", r.ID, Now())
	if e == nil {
		t.Fatal("racing binding bypassed transaction guard")
	}
	if _, e = s.CreateSite("race php", "race-php", ID(), "admin", r.ID); e == nil {
		t.Fatal("racing PHP create accepted")
	}
	j, e := s.NextRuntimeJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.finishRuntime(j, "connection lost", nil, true); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueInstall(r.ID, ID(), "admin"); e == nil {
		t.Fatal("new install bypasses uncertain job")
	}
	if e = s.RetryRuntime(id, "admin"); e != nil {
		t.Fatal(e)
	}
	j, e = s.NextRuntimeJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRuntime(j, "", nil); e != nil {
		t.Fatal(e)
	}
	if s.RuntimeInstalled(r.ID) {
		t.Fatal("quarantined version still available")
	}
	// A stale inventory response must not resurrect a retired installation.
	if e = s.RecordObservedInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	if s.RuntimeInstalled(r.ID) {
		t.Fatal("stale inventory overwrote lifecycle result")
	}
	if _, e = s.QueueRuntimeLifecycle(r.ID, "restore", ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	j, e = s.NextRuntimeJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRuntime(j, "", nil); e != nil {
		t.Fatal(e)
	}
	if !s.RuntimeInstalled(r.ID) {
		t.Fatal("restored installation unavailable")
	}
}
func TestLifecycleSQLGuardsCoverPendingPHPSwitchAndNginx(t *testing.T) {
	s := testStore(t)
	php, _ := runtimecatalog.Find("php-8.4.25")
	nginx, _ := runtimecatalog.Find("nginx-1.31.5")
	for _, r := range []runtimecatalog.Release{php, nginx} {
		if e := s.RecordInstallation(r, "arm64"); e != nil {
			t.Fatal(e)
		}
	}
	s.CreateSite("static fixture", "lifecycle-static", ID(), "admin", "")
	j, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	s.Finish(j, "running", "", nil)
	switchID, e := s.QueuePHP(j.SiteID, php.ID, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueRuntimeLifecycle(php.ID, "retire", ID(), "admin"); e == nil {
		t.Fatal("pending PHP switch not protected")
	}
	s.DB.Exec(`UPDATE jobs SET state='failed' WHERE id=?`, switchID)
	if _, e = s.QueueRuntimeLifecycle(php.ID, "retire", ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE jobs SET state='queued' WHERE id=?`, switchID); e == nil {
		t.Fatal("retry bypassed pending retirement")
	}
	if _, e = s.QueueRuntimeLifecycle(nginx.ID, "retire", ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,'switch_nginx','queued',?,?,?)`, ID(), nginx.ID, ID(), Now(), Now()); e == nil {
		t.Fatal("Nginx transaction guard bypassed")
	}
	if _, e = s.QueueRuntimeLifecycle("nginx-system", "retire", ID(), "admin"); e == nil {
		t.Fatal("system nginx accepted")
	}
}
