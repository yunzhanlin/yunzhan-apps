package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPHPScheduleUsesCurrentBindingAndImmutableRun(t *testing.T) {
	s := testStore(t)
	job, e := s.CreateSite("PHP schedule", "php-schedule", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE sites SET status='running',php_version_id='php-8.2.33' WHERE id=?`, siteID); e != nil {
		t.Fatal(e)
	}
	base := time.Now()
	v, e := s.CreateSchedule(Schedule{Name: "PHP cron", Kind: "admin_script", TargetID: strings.Repeat("0", 32), ScriptSiteID: siteID, Script: "cron/task.php", TimeoutSeconds: 8, ScheduleType: "daily", Timezone: "UTC", RetentionCount: 1, Enabled: true}, "admin", base)
	if e != nil || v.TargetName != "PHP schedule" || v.ReleaseID != "php-8.2.33" {
		t.Fatal(v, e)
	}
	if _, e = s.QueueScheduleRun(v.ID, "manual", "admin", base); e != nil {
		t.Fatal(e)
	}
	// A queued run uses the site's binding at start, not at schedule creation.
	if _, e = s.DB.Exec(`UPDATE sites SET php_version_id='php-8.3.33' WHERE id=?`, siteID); e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(base); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE sites SET php_version_id='php-8.5.10' WHERE id=?`, siteID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE schedule_scripts SET script='changed.php' WHERE schedule_id=?`, v.ID); e != nil {
		t.Fatal(e)
	}
	calls := 0
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var in AdminScriptRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.SiteID != siteID || in.PHPVersionID != "php-8.3.33" || in.Script != "cron/task.php" || in.ScriptSHA256 != AdminScriptHash(in.Script, siteID, "php-8.3.33") {
			t.Fatalf("run changed: %+v", in)
		}
		return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader(`{"error":"网站 PHP 绑定已变更"}`)), Header: make(http.Header)}, nil
	})}}
	if e = s.executeAdminScriptScheduleRun(context.Background(), ex, base); e != nil {
		t.Fatal(e)
	}
	if e = s.executeAdminScriptScheduleRun(context.Background(), ex, base); e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
	runs, _ := s.ScheduleRuns(5)
	if runs[0].State != "failed" || !strings.Contains(runs[0].Error, "绑定已变更") {
		t.Fatal(runs)
	}
	// Unbinding PHP makes future executions fail before reaching the executor.
	if _, e = s.DB.Exec(`UPDATE sites SET php_version_id='' WHERE id=?`, siteID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueScheduleRun(v.ID, "manual", "admin", base.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(base.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.ScheduleRuns(5)
	if runs[0].State != "failed" || !strings.Contains(runs[0].Error, "尚未绑定 PHP") {
		t.Fatal(runs)
	}
}

func TestSitePHPScriptPathsAndReceiptBinding(t *testing.T) {
	for _, p := range []string{"/etc/a.php", "../a.php", "jobs/../../a.php", "jobs/../a.php", "a.php\n", "-a.php", "a.sh", "a\\b.php"} {
		if ValidSitePHPScriptPath(p) {
			t.Fatal("unsafe path", p)
		}
	}
	if !ValidSitePHPScriptPath("cron/task.php") {
		t.Fatal("valid path rejected")
	}
	if AdminScriptHash("echo ok", "", "") != Hash("echo ok") {
		t.Fatal("Shell receipts changed")
	}
	if AdminScriptHash("cron.php", ID(), "php-8.2.33") == AdminScriptHash("cron.php", ID(), "php-8.2.33") {
		t.Fatal("site identity missing")
	}
	v := Schedule{Kind: "site_backup", ScriptSiteID: ID()}
	if validScheduleScript(v) == nil {
		t.Fatal("PHP binding accepted for backup")
	}
}
