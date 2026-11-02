package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type retentionFixture struct {
	s                                                                      *Store
	engine, table, backups, kind, scheduleID, databaseID, serverID, siteID string
	ids                                                                    []string
	cleanup                                                                func(context.Context, *ExecutorClient) error
}

func newRetentionFixture(t *testing.T, engine string, count int) retentionFixture {
	t.Helper()
	s := testStore(t)
	f := retentionFixture{s: s, engine: engine, scheduleID: ID(), databaseID: ID(), serverID: ID(), siteID: ID()}
	f.table, _ = retentionTable(engine)
	kind, target := "database_backup", f.databaseID
	switch engine {
	case "mysql":
		server, db := scheduleDatabaseFixture(t, s)
		f.databaseID, f.serverID = db.ID, server.ID
		target = db.ID
		f.backups, f.kind, f.cleanup = "mysql_backups", "database_backup", s.cleanupScheduleRetention
	case "mariadb":
		f.backups, f.kind, f.cleanup = "mariadb_schedule_backups", "mariadb_backup", s.cleanupMariaDBScheduleRetention
	case "site":
		job, err := s.CreateSite("retention fixture", "retention-fixture", ID(), "admin")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&f.siteID); err != nil {
			t.Fatal(err)
		}
		kind, target = "site_backup", f.siteID
		f.backups, f.kind, f.cleanup = "site_backups", "site_backup", s.cleanupSiteScheduleRetention
	default:
		t.Fatal(engine)
	}
	base := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if _, err := s.DB.Exec(`INSERT INTO schedules(id,name,kind,target_id,schedule_type,timezone,minute,hour,weekday,retention_count,enabled,revision,next_run_at,created_at,updated_at) VALUES(?,?,?,?,'daily','UTC',0,3,1,2,1,1,?,?,?)`, f.scheduleID, "retention "+engine, kind, target, base.Add(time.Hour).Unix(), base.Format(time.RFC3339), base.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		id, run := ID(), ID()
		f.ids = append(f.ids, id)
		at := base.Add(time.Duration(i) * time.Hour)
		var err error
		switch engine {
		case "mysql":
			_, err = s.DB.Exec(`INSERT INTO mysql_backups VALUES(?,?,?,?,?,?,?)`, id, f.databaseID, f.serverID, "8.4.11", 100+i, Hash(id), at.Format(time.RFC3339))
		case "mariadb":
			_, err = s.DB.Exec(`INSERT INTO mariadb_schedule_backups VALUES(?,?,?,?,?,?,?,?,?)`, id, f.databaseID, f.serverID, "app", "instance", "mariadb-11.8.9", 100+i, Hash(id), at.Format(time.RFC3339))
		case "site":
			_, err = s.DB.Exec(`INSERT INTO site_backups VALUES(?,?,?,?,?,?,?,?)`, id, f.siteID, "zip", 1, 100+i, 100+i, Hash(id), at.Format(time.RFC3339))
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,artifact_id,created_at)VALUES(?,?,?,'scheduled','succeeded',?,?,?,?,?)`, run, f.scheduleID, "retention "+engine, at.Unix(), at.Unix(), at.Unix(), id, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.Exec(`INSERT INTO schedule_artifacts VALUES(?,?,?,?,?)`, f.scheduleID, run, f.kind, id, at.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func retentionExecutor(t *testing.T, f retentionFixture, action func(*http.Request) error, calls *atomic.Int32) *ExecutorClient {
	t.Helper()
	return &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != http.MethodDelete {
			t.Fatalf("unexpected mutation %s", r.Method)
		}
		var attempts int
		var diagnostic string
		if err := f.s.DB.QueryRow(`SELECT attempts,last_error FROM `+f.table+` WHERE artifact_id=?`, f.ids[0]).Scan(&attempts, &diagnostic); err != nil {
			t.Fatal(err)
		}
		if attempts != 1 || diagnostic != scheduleCleanupUnconfirmed {
			t.Fatal("DELETE crossed an uncommitted dispatch boundary", attempts, diagnostic)
		}
		if err := action(r); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"deleted":true}`)), Request: r}, nil
	})}}
}

func TestRetentionDispatchIsDurableAndUnknownResultsNeverReplay(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 3)
			var calls atomic.Int32
			ex := retentionExecutor(t, f, func(r *http.Request) error { return errors.New("connection lost after dispatch") }, &calls)
			if err := f.cleanup(t.Context(), ex); err == nil {
				t.Fatal("lost reply accepted as success")
			}
			before, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil {
				t.Fatal(err)
			}
			if before.Counts["needs_attention"] != 1 || len(before.Items) != 1 || before.Items[0].Attempts != 1 || !strings.Contains(before.Items[0].LastError, "connection lost") {
				t.Fatal(before)
			}
			for i := 0; i < 5; i++ {
				if err = f.cleanup(t.Context(), ex); err != nil {
					t.Fatal(err)
				}
			}
			after, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil {
				t.Fatal(err)
			}
			x, _ := json.Marshal(before)
			y, _ := json.Marshal(after)
			if string(x) != string(y) || calls.Load() != 1 {
				t.Fatal("unknown result replayed or original diagnostic changed", calls.Load())
			}
			var backups int
			if err = f.s.DB.QueryRow(`SELECT count(*) FROM ` + f.backups).Scan(&backups); err != nil || backups != 3 {
				t.Fatal("failed deletion changed backup inventory", backups, err)
			}
		})
	}
}

func TestRetentionFailedHeadDoesNotStarveOtherEligibleBackups(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 4)
			calls := 0
			ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					if !strings.Contains(r.URL.Path, f.ids[0]) {
						t.Fatal(r.URL.Path)
					}
					return nil, errors.New("unverified private directory")
				}
				if calls != 2 || !strings.Contains(r.URL.Path, f.ids[1]) {
					t.Fatal("failed head repeated or retained backup selected", calls, r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"deleted":true}`)), Request: r}, nil
			})}}
			if err := f.cleanup(t.Context(), ex); err == nil {
				t.Fatal("first refusal accepted")
			}
			if err := f.cleanup(t.Context(), ex); err != nil {
				t.Fatal(err)
			}
			if err := f.cleanup(t.Context(), ex); err != nil {
				t.Fatal(err)
			}
			records, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil || records.Counts["needs_attention"] != 1 || records.Counts["completed"] != 1 || calls != 2 {
				t.Fatal(records, calls, err)
			}
			var count int
			if err = f.s.DB.QueryRow(`SELECT count(*) FROM ` + f.backups).Scan(&count); err != nil || count != 3 {
				t.Fatal(count, err)
			}
			for _, id := range []string{f.ids[0], f.ids[2], f.ids[3]} {
				var kept int
				if err = f.s.DB.QueryRow(`SELECT count(*) FROM `+f.backups+` WHERE id=?`, id).Scan(&kept); err != nil || kept != 1 {
					t.Fatal("original failed or retained backup lost", id, err)
				}
			}
		})
	}
}

func TestRetentionPostDeleteDatabaseFailureDoesNotDispatchAgain(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 3)
			var calls atomic.Int32
			if _, err := f.s.DB.Exec(`CREATE TRIGGER fail_retention_commit BEFORE UPDATE OF state ON ` + f.table + ` WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'durability failure'); END`); err != nil {
				t.Fatal(err)
			}
			ex := retentionExecutor(t, f, func(r *http.Request) error { return nil }, &calls)
			if err := f.cleanup(t.Context(), ex); err == nil {
				t.Fatal("completion failure hidden")
			}
			if _, err := f.s.DB.Exec(`DROP TRIGGER fail_retention_commit`); err != nil {
				t.Fatal(err)
			}
			if err := f.cleanup(t.Context(), ex); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("successful executor deletion dispatched again after DB failure")
			}
			records, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil || records.Counts["needs_attention"] != 1 || records.Items[0].LastError != scheduleCleanupUnconfirmed {
				t.Fatal(records, err)
			}
		})
	}
}

func TestRetentionRegistrationFailureCannotReachExecutor(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 3)
			var calls atomic.Int32
			if _, err := f.s.DB.Exec(`CREATE TRIGGER fail_retention_audit BEFORE INSERT ON audit_logs WHEN NEW.action='schedule.retention.dispatch' BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
				t.Fatal(err)
			}
			ex := retentionExecutor(t, f, func(r *http.Request) error { return nil }, &calls)
			if err := f.cleanup(t.Context(), ex); err == nil || calls.Load() != 0 {
				t.Fatal("unregistered deletion sent", err, calls.Load())
			}
			var attempts int
			var diagnostic string
			if err := f.s.DB.QueryRow(`SELECT attempts,last_error FROM `+f.table+` WHERE artifact_id=?`, f.ids[0]).Scan(&attempts, &diagnostic); err != nil || attempts != 0 || diagnostic != "" {
				t.Fatal("reservation did not roll back", attempts, diagnostic, err)
			}
		})
	}
}

func TestRetentionClaimRechecksEnabledPolicyAndBackupIdentity(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		for _, change := range []string{"disabled", "archived", "retention", "backup_identity", "remote_pending"} {
			t.Run(engine+"/"+change, func(t *testing.T) {
				f := newRetentionFixture(t, engine, 3)
				var err error
				// Create only a pending candidate, before any request is registered.
				switch engine {
				case "mysql":
					_, err = f.s.claimScheduleCleanup()
				case "mariadb":
					_, err = f.s.claimMariaDBScheduleCleanup()
				case "site":
					_, err = f.s.claimSiteScheduleCleanup()
				}
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "disabled":
					_, err = f.s.DB.Exec(`UPDATE schedules SET enabled=0 WHERE id=?`, f.scheduleID)
				case "archived":
					_, err = f.s.DB.Exec(`UPDATE schedules SET deleted_at=1 WHERE id=?`, f.scheduleID)
				case "retention":
					_, err = f.s.DB.Exec(`UPDATE schedules SET retention_count=3 WHERE id=?`, f.scheduleID)
				case "backup_identity":
					_, err = f.s.DB.Exec(`UPDATE `+f.backups+` SET sha256=? WHERE id=?`, Hash("replaced"), f.ids[0])
				case "remote_pending":
					remote := ID()
					_, err = f.s.DB.Exec(`INSERT INTO backup_remotes(id,name,base_url,username,password_cipher,path_prefix,enabled,created_at,updated_at)VALUES(?,?,'https://example.invalid/dav','test',?,'panel',1,?,?)`, remote, remote, []byte{1}, Now(), Now())
					if err != nil {
						t.Fatal(err)
					}
					if engine == "mariadb" {
						_, err = f.s.DB.Exec(`INSERT INTO mariadb_remote_copies(id,remote_id,artifact_id,bytes,sha256,state,created_at)VALUES(?,?,?,?,?,'pending',?)`, ID(), remote, f.ids[0], 100, Hash(f.ids[0]), Now())
					} else {
						kind := "database"
						if engine == "site" {
							kind = "site"
						}
						_, err = f.s.DB.Exec(`INSERT INTO backup_remote_copies(id,remote_id,artifact_kind,artifact_id,bytes,sha256,state,created_at)VALUES(?,?,?,?,?,?,'pending',?)`, ID(), remote, kind, f.ids[0], 100, Hash(f.ids[0]), Now())
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				ex := retentionExecutor(t, f, func(r *http.Request) error { return nil }, &calls)
				if err = f.cleanup(t.Context(), ex); err != nil || calls.Load() != 0 {
					t.Fatal("changed policy/identity or pending remote copy allowed deletion", err, calls.Load())
				}
				records, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
				if err != nil || records.Counts["held"] != 1 || records.Items[0].Attempts != 0 {
					t.Fatal(records, err)
				}
			})
		}
	}
}

func TestRetentionLegacyFailureRemainsByteExact(t *testing.T) {
	f := newRetentionFixture(t, "mysql", 3)
	v, err := f.s.claimScheduleCleanup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.DB.Exec(`UPDATE schedule_cleanup_jobs SET attempts=1043148,last_error='original private permissions refusal' WHERE artifact_id=?`, v.Backup.ID); err != nil {
		t.Fatal(err)
	}
	before, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	ex := retentionExecutor(t, f, func(r *http.Request) error { return nil }, &calls)
	for i := 0; i < 8; i++ {
		if err = f.cleanup(t.Context(), ex); err != nil {
			t.Fatal(err)
		}
	}
	after, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	if string(x) != string(y) || calls.Load() != 0 {
		t.Fatal("legacy failure was retried or rewritten")
	}
}

func TestRetentionConcurrentWorkersCannotShareDispatch(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 3)
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			finished := make(chan error, 1)
			ex := retentionExecutor(t, f, func(r *http.Request) error { close(entered); <-release; return nil }, &calls)
			go func() { finished <- f.cleanup(t.Context(), ex) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first worker did not reach executor")
			}
			second := f.cleanup(t.Context(), ex)
			close(release)
			if err := <-finished; err != nil || second != nil || calls.Load() != 1 {
				t.Fatal("parallel duplicate dispatch", err, second, calls.Load())
			}
		})
	}
}

func TestRetentionUnknownDispatchSurvivesDatabaseReopen(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "site"} {
		t.Run(engine, func(t *testing.T) {
			f := newRetentionFixture(t, engine, 3)
			var calls atomic.Int32
			ex := retentionExecutor(t, f, func(r *http.Request) error { return errors.New("reply unknown") }, &calls)
			if err := f.cleanup(t.Context(), ex); err == nil {
				t.Fatal("unknown reply accepted")
			}
			before, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil {
				t.Fatal(err)
			}
			var sequence int
			var name, path string
			if err = f.s.DB.QueryRow(`PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil || name != "main" || path == "" {
				t.Fatal(err, name, path)
			}
			if err = f.s.DB.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			f.s.DB = reopened.DB
			if err = f.cleanup(t.Context(), ex); err != nil {
				t.Fatal(err)
			}
			after, err := f.s.ScheduleRetentionRecords(t.Context(), 20, 0)
			if err != nil {
				t.Fatal(err)
			}
			x, _ := json.Marshal(before)
			y, _ := json.Marshal(after)
			if string(x) != string(y) || calls.Load() != 1 {
				t.Fatal("restart made the old unknown operation eligible")
			}
		})
	}
}

func TestRetentionReadOnlyRecordsHTTPPermissionsAndClosedPagination(t *testing.T) {
	f := newRetentionFixture(t, "mysql", 3)
	v, err := f.s.claimScheduleCleanup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.DB.Exec(`UPDATE schedule_cleanup_jobs SET attempts=1043148,last_error='original diagnostic' WHERE artifact_id=?`, v.Backup.ID); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"admin", "viewer", "operator"} {
		accessUser(t, f.s, role, role, nil)
	}
	accessUser(t, f.s, "no-menu", "admin", []string{"sites"})
	a, err := NewServer(f.s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	a.Executor = retentionExecutor(t, f, func(r *http.Request) error { return nil }, &calls)
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/schedules/retention", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, role := range []string{"viewer", "operator", "no-menu", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+role+`","password":"access-test-password-long"}`, nil)
		if login.Code != 200 {
			t.Fatal(role, login.Code)
		}
		cookie := login.Result().Cookies()[0]
		w := request("GET", "/api/schedules/retention?limit=1&offset=0", "", cookie)
		if role != "admin" {
			if w.Code != 403 {
				t.Fatal("cleanup record permission bypass", role, w.Code)
			}
			continue
		}
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var page ScheduleRetentionRecords
		if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || !page.ReadOnly || page.Items[0].Attempts != 1043148 || page.Counts["needs_attention"] != 1 {
			t.Fatal(page, err)
		}
		for _, query := range []string{"limit=0", "limit=101", "offset=-1", "offset=100001", "limit=1&limit=2", "offset=abc", "engine=mysql", "limit="} {
			if w = request("GET", "/api/schedules/retention?"+query, "", cookie); w.Code != 400 {
				t.Fatal("invalid paging accepted", query, w.Code)
			}
		}
		if w = request("GET", "/api/schedules/retention?limit=1&offset=1", "", cookie); w.Code != 200 {
			t.Fatal(w.Code)
		}
		if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 0 || page.HasMore || page.Total != 1 {
			t.Fatal(page, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("read-only listing contacted executor", calls.Load())
	}
	var attempts int64
	var diagnostic string
	if err = f.s.DB.QueryRow(`SELECT attempts,last_error FROM schedule_cleanup_jobs WHERE artifact_id=?`, v.Backup.ID).Scan(&attempts, &diagnostic); err != nil || attempts != 1043148 || diagnostic != "original diagnostic" {
		t.Fatal("read-only requests rewrote original failure", attempts, diagnostic, err)
	}
}
