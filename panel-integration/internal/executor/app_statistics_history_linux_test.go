//go:build linux

package executor

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// The killed subprocess holds an actual SQLite write transaction. This is
// process interruption, not a claimed VM power-cut or storage-controller test.
func TestStatisticsHistoryKilledWriter(t *testing.T) {
	if path := os.Getenv("PANEL_STATISTICS_KILL_FIXTURE"); path != "" {
		var config Config
		if json.Unmarshal([]byte(os.Getenv("PANEL_STATISTICS_KILL_CONFIG")), &config) != nil || !filepath.IsAbs(path) || !strings.HasPrefix(path, os.TempDir()+"/TestStatisticsHistoryKilledWriter") {
			t.Fatal("private child fixture identity")
		}
		s := New(config)
		db, err := s.openStatisticsHistory(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite") != path {
			t.Fatal("child fixture database mismatch")
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES('qa',0,'','/uncommitted',200,0,0,'{}')"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("UPDATE access_streams SET offset=offset+999 WHERE site=?", strings.Repeat("a", 32)); err != nil {
			t.Fatal(err)
		}
		fmt.Println("OWN_SQLITE_UNCOMMITTED_READY")
		for {
			time.Sleep(time.Second)
		}
	}
	s, db, id, path, now := statisticsHistoryFixture(t)
	line := statisticsTestLine(now, "/before-interruption")
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	statisticsTestIngest(t, s, db, id, now)
	var beforeOffset int64
	if err := db.QueryRow("SELECT offset FROM access_streams WHERE site=?", id).Scan(&beforeOffset); err != nil {
		t.Fatal(err)
	}
	// Config contains functions; serialize only fixed fixture paths instead.
	config, _ := json.Marshal(map[string]string{"SitesDir": s.Config.SitesDir, "SecurityDir": s.Config.SecurityDir, "SystemRoot": s.Config.SystemRoot})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStatisticsHistoryKilledWriter$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "PANEL_STATISTICS_KILL_FIXTURE="+filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite"), "PANEL_STATISTICS_KILL_CONFIG="+string(config))
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = child.Stdout
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.Process != nil {
			_ = child.Process.Kill()
		}
	}()
	scanner := bufio.NewScanner(output)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "OWN_SQLITE_UNCOMMITTED_READY" {
			ready = true
			break
		}
	}
	if !ready {
		_ = child.Wait()
		t.Fatal("child did not reach actual uncommitted SQLite transaction")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("writer was not killed")
	}
	db.Close()
	reopened, err := s.openStatisticsHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var afterOffset int64
	if err = reopened.QueryRow("SELECT offset FROM access_streams WHERE site=?", id).Scan(&afterOffset); err != nil || beforeOffset != afterOffset || statisticsTestCount(t, reopened) != 1 {
		t.Fatal("killed transaction advanced accepted history", afterOffset, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(line)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	state := statisticsTestIngest(t, s, reopened, id, now)
	if statisticsTestCount(t, reopened) != 2 || state.Backlog != 0 {
		t.Fatal("interruption recovery lost or duplicated rows", state)
	}
	t.Log("PASS actual SIGKILL of SQLite writer, hot-journal recovery, original row/cursor identity retained and exact subsequent continuation; not VM power-loss proof")
}

func makeStatisticsTestFIFO(path string) error { return syscall.Mkfifo(path, 0600) }

func statisticsHistoryFixture(t *testing.T) (*Service, *sql.DB, string, string, time.Time) {
	t.Helper()
	id := strings.Repeat("a", 32)
	base := t.TempDir()
	sites := filepath.Join(base, "sites")
	logs := filepath.Join(base, "system/var/log/nginx")
	security := filepath.Join(base, "security")
	for _, dir := range []string{filepath.Join(sites, id, "public"), logs, security} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(sites, id, ".panel-site.json"), []byte("{\"id\":\""+id+"\"}"), 0600); e != nil {
		t.Fatal(e)
	}
	s := New(Config{SitesDir: sites, SecurityDir: security, SystemRoot: filepath.Join(base, "system")})
	db, e := s.openStatisticsHistory(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return s, db, id, filepath.Join(logs, "panel-"+id+".access.log"), time.Now().UTC().Truncate(time.Second)
}
func statisticsTestLine(now time.Time, path string) string {
	b, _ := json.Marshal(analyticsAccess{Time: now.Format(time.RFC3339Nano), Remote: "192.0.2.1", Method: "GET", Path: path, Status: 503, Bytes: 17, Seconds: 2.5, Agent: "Mozilla Chrome/123 Mobile raw-ua-secret", Referer: "https://user:referer-secret@example.test/source?token=query-secret#fragment-secret"})
	return string(b) + "\n"
}
func statisticsTestCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if e := db.QueryRow("SELECT count(*) FROM access_rows").Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func statisticsTestIngest(t *testing.T, s *Service, db *sql.DB, id string, now time.Time) statisticsIngestion {
	t.Helper()
	state, e := s.ingestStatisticsHistory(context.Background(), db, id, now)
	if e != nil {
		t.Fatal(e)
	}
	return state
}

func TestStatisticsHistoryIncrementalPrivateRestartAndPartialLine(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	line := statisticsTestLine(now, "/page?password=path-secret#fragment-secret")
	if e := os.WriteFile(path, []byte(line+line[:17]), 0600); e != nil {
		t.Fatal(e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 1 || state.Backlog != 17 {
		t.Fatal(state)
	}
	restart := New(s.Config)
	other, e := restart.openStatisticsHistory(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	state = statisticsTestIngest(t, restart, other, id, now)
	if statisticsTestCount(t, other) != 1 || state.Backlog != 17 {
		t.Fatal("partial/restart duplicated rows", state)
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(line[17:])
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	state = statisticsTestIngest(t, restart, other, id, now)
	if statisticsTestCount(t, other) != 2 || state.Backlog != 0 || state.Blocked != 0 {
		t.Fatal(state)
	}
	var payload string
	if e = other.QueryRow("SELECT payload FROM access_rows LIMIT 1").Scan(&payload); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(payload, "secret") || strings.Contains(payload, "Mozilla") {
		t.Fatal("history persisted sensitive metadata", payload)
	}
	report, e := statisticsHistoryReport(context.Background(), other, core.AppModuleInput{SiteID: id}, state, now)
	if e != nil || report["requests"] != 2 || report["bytes"] != int64(34) || report["partial"] != false || report["history_persistent"] != true {
		t.Fatal(report, e)
	}
	if report["browsers"].(map[string]int)["Chrome"] != 2 || report["devices"].(map[string]int)["Mobile"] != 2 {
		t.Fatal(report)
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, e := os.Lstat(filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite") + suffix)
		if os.IsNotExist(e) && suffix != "" {
			continue
		}
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private database permissions", suffix, e)
		}
	}
	t.Log("PASS incremental complete-line cursor, actual SQLite restart replay, private classified metadata and real report")
}

func TestStatisticsHistoryLatencyUsesDurableRowsAndFilters(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	defer db.Close()
	var log strings.Builder
	for i, seconds := range []float64{0, .05, .1, .5, 1.2, 4} {
		var row analyticsAccess
		if err := json.Unmarshal([]byte(statisticsTestLine(now, fmt.Sprintf("/latency-%d?token=latency-secret", i))), &row); err != nil {
			t.Fatal(err)
		}
		row.Seconds = seconds
		// The shared fixture deliberately defaults to 503. Establish the
		// mixed-status source explicitly; otherwise all six rows are errors.
		row.Status = 200
		if i >= 4 {
			row.Status = 503
		}
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		log.Write(raw)
		log.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(log.String()), 0600); err != nil {
		t.Fatal(err)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	var actualErrors int
	if err := db.QueryRow("SELECT count(*) FROM access_rows WHERE site=? AND status=503", id).Scan(&actualErrors); err != nil || actualErrors != 2 {
		t.Fatal("independent fixture did not establish exactly two 503 rows", actualErrors, err)
	}
	for _, tc := range []struct {
		status, count int
		p50, p99      float64
	}{{0, 6, .1, 4}, {503, 2, 1.2, 4}} {
		out, err := statisticsHistoryReport(context.Background(), db, core.AppModuleInput{SiteID: id, StatusCode: tc.status, MinSeconds: 8}, state, now)
		if err != nil {
			t.Fatal(err)
		}
		r := out["latency"].(analyticsLatencyReport)
		if out["requests"] != tc.count || out["slow_count"] != 0 || r.Requests != tc.count || r.Samples != tc.count || !r.QuantilesAvailable || r.PopulationPartial || *r.P50 != tc.p50 || *r.P99 != tc.p99 {
			t.Fatal("durable SQL population differs from exact latency population", out)
		}
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "/latency-") {
			t.Fatal("latency aggregate leaked row metadata")
		}
	}
	if state.Backlog != 0 || statisticsTestCount(t, db) != 6 {
		t.Fatal("report mutated ingestion progress", state)
	}
}

func TestStatisticsHistoryRenameRotationRetainsUnreadAndAvoidsDuplicates(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	line := statisticsTestLine(now, "/old")
	if e := os.WriteFile(path, []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	statisticsTestIngest(t, s, db, id, now)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(line)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	archive := path + "." + now.Format("20060102-150405")
	if e = os.Rename(path, archive); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(statisticsTestLine(now, "/new")), 0600); e != nil {
		t.Fatal(e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 3 || state.Backlog != 0 || state.Sources != 2 {
		t.Fatal(state)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 3 || state.Blocked != 0 {
		t.Fatal("rotated inode replay duplicated data", state)
	}
	if e = os.Remove(archive); e != nil {
		t.Fatal(e)
	} // Fixture only: already completely consumed.
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 3 || state.Blocked != 0 {
		t.Fatal("removed consumed log erased history", state)
	}
	t.Log("PASS real rename rotation, unread old inode continuation, new inode, replay and retained history after fixture archive removal")
}

func TestStatisticsHistoryCheckpointConflictAndCompressedGapAreHonest(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	line := statisticsTestLine(now, "/original")
	if e := os.WriteFile(path, []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	statisticsTestIngest(t, s, db, id, now)
	if e := os.WriteFile(path, []byte(statisticsTestLine(now, "/changed")+line), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path+"."+now.Format("20060102-150405")+".gz", []byte("untrusted-compressed-input"), 0600); e != nil {
		t.Fatal(e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if state.Blocked != 1 || state.Compressed != 1 || statisticsTestCount(t, db) != 1 {
		t.Fatal("rewritten inode was silently reset", state)
	}
	report, e := statisticsHistoryReport(context.Background(), db, core.AppModuleInput{SiteID: id}, state, now)
	if e != nil || report["partial"] != true || report["requests"] != 1 {
		t.Fatal(report, e)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 1 || state.Blocked != 1 {
		t.Fatal("second retry reset a blocked cursor", state)
	}
	t.Log("PASS immutable checkpoint rejection and explicit compressed-source/partial warnings without duplicate import")
}

func TestStatisticsHistoryFailedBatchRollsBackRowsAndCheckpoint(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	if e := os.WriteFile(path, []byte(statisticsTestLine(now, "/one")+statisticsTestLine(now, "/fail")), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec("CREATE TRIGGER qa_fail BEFORE INSERT ON access_rows WHEN NEW.path='/fail' BEGIN SELECT RAISE(ABORT,'injected failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ingestStatisticsHistory(context.Background(), db, id, now); e == nil {
		t.Fatal("injected failed write succeeded")
	}
	var cursors int
	if e := db.QueryRow("SELECT count(*) FROM access_streams").Scan(&cursors); e != nil || cursors != 0 || statisticsTestCount(t, db) != 0 {
		t.Fatal("partial transaction committed", cursors, e)
	}
	if _, e := db.Exec("DROP TRIGGER qa_fail"); e != nil {
		t.Fatal(e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Backlog != 0 {
		t.Fatal("safe retry lost or duplicated rows", state)
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.ingestStatisticsHistory(c, db, id, now); e == nil {
		t.Fatal("cancelled batch succeeded")
	}
	if statisticsTestCount(t, db) != 2 {
		t.Fatal("cancelled transaction altered history")
	}
	t.Log("PASS actual SQLite row/offset transaction failure and cancellation rollback, successful retry exactly once")
}

func TestStatisticsHistoryMoreThanLegacyTailAndSQLFilters(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	// All rows are real JSON logs. The initial record falls outside the last
	// 16 MiB, and must remain queryable after bounded catch-up and a restart.
	n := 55000
	line := statisticsTestLine(now, "/"+strings.Repeat("x", 80))
	contents := statisticsTestLine(now, "/oldest") + strings.Repeat(line, n)
	if len(contents) <= 16<<20 {
		t.Fatal("fixture did not exceed old tail bound", len(contents))
	}
	if e := os.WriteFile(path, []byte(contents), 0600); e != nil {
		t.Fatal(e)
	}
	var state statisticsIngestion
	for i := 0; i < 30; i++ {
		state = statisticsTestIngest(t, s, db, id, now)
		if state.Backlog == 0 {
			break
		}
	}
	if state.Backlog != 0 || statisticsTestCount(t, db) != n+1 {
		t.Fatal(state, statisticsTestCount(t, db))
	}
	report, e := statisticsHistoryReport(context.Background(), db, core.AppModuleInput{SiteID: id}, state, now)
	if e != nil || report["requests"] != n+1 || report["partial"] != false {
		t.Fatal("history was silently tail-limited", report["requests"], e)
	}
	for _, in := range []core.AppModuleInput{{SiteID: id, Search: "/oldest"}, {SiteID: id, Search: "192.0.2.1", StatusCode: 503}, {SiteID: id, Search: "%' OR 1=1 --"}, {SiteID: strings.Repeat("b", 32)}} {
		report, e = statisticsHistoryReport(context.Background(), db, in, state, now)
		want := 0
		if in.Search == "/oldest" {
			want = 1
		}
		if in.StatusCode == 503 {
			want = n + 1
		}
		if e != nil || report["requests"] != want {
			t.Fatal("SQL filter/isolation mismatch", in, report["requests"], e)
		}
	}
	t.Logf("PASS %d actual log bytes / %d rows, bounded catch-up beyond 16 MiB, SQL parameter isolation and real filtered history", len(contents), n+1)
}

func TestStatisticsHistoryTimeValidationRetentionAndCapacity(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	contents := statisticsTestLine(now.AddDate(0, 0, -31), "/expired") + statisticsTestLine(now.Add(time.Second/2), "/fraction") + statisticsTestLine(now.Add(2*time.Minute), "/future") + "bad-json\n"
	if e := os.WriteFile(path, []byte(contents), 0600); e != nil {
		t.Fatal(e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 1 || state.Invalid != 2 {
		t.Fatal(state)
	}
	report, e := statisticsHistoryReport(context.Background(), db, core.AppModuleInput{SiteID: id, ToTime: now.Add(time.Second / 2).Format(time.RFC3339Nano)}, state, now)
	if e != nil || report["requests"] != 0 {
		t.Fatal("exclusive fractional to-time failed", report, e)
	}
	report, e = statisticsHistoryReport(context.Background(), db, core.AppModuleInput{SiteID: id, FromTime: now.AddDate(0, 0, -31).Format(time.RFC3339)}, state, now)
	if e != nil || report["history_before_retention"] != true || report["partial"] != true {
		t.Fatal(report, e)
	}
	// Derived QA rows exercise the REAL capacity policy, not a weakened limit.
	_, e = db.Exec("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) SELECT ?,?,'','/',200,0,0,'{}' FROM n", statisticsHistoryRows, id, now.Unix())
	if e != nil {
		t.Fatal(e)
	}
	statisticsTestIngest(t, s, db, id, now)
	var evicted int
	if e = db.QueryRow("SELECT evicted FROM access_retention WHERE site=?", id).Scan(&evicted); e != nil || evicted != 1 || statisticsTestCount(t, db) != statisticsHistoryRows {
		t.Fatal(evicted, e)
	}
	t.Log("PASS actual 250000-row retention boundary, explicit evictions, 30-day cutoff, future/invalid rejection and exclusive subsecond filters")
}

func TestStatisticsHistoryRejectsUnsafeLogsAndDatabaseWithoutOverwrite(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "writable", "fifo", "database-link", "database-permission"} {
		t.Run(kind, func(t *testing.T) {
			s, db, id, path, now := statisticsHistoryFixture(t)
			outside := filepath.Join(t.TempDir(), "protected")
			original := []byte(statisticsTestLine(now, "/protected"))
			if e := os.WriteFile(outside, original, 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "symlink":
				e = os.Symlink(outside, path)
			case "hardlink":
				e = os.Link(outside, path)
			case "writable":
				e = os.WriteFile(path, original, 0666)
				if e == nil {
					e = os.Chmod(path, 0666)
				}
			case "fifo":
				e = makeStatisticsTestFIFO(path)
			case "database-link", "database-permission":
				db.Close()
				target := filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
				if kind == "database-link" {
					e = os.Rename(target, target+".qa-preserved")
					if e == nil {
						e = os.Symlink(outside, target)
					}
				} else {
					e = os.Chmod(target, 0644)
				}
				if e != nil {
					t.Fatal(e)
				}
				if opened, err := s.openStatisticsHistory(context.Background()); err == nil {
					opened.Close()
					t.Fatal("unsafe database accepted")
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if !strings.HasPrefix(kind, "database-") {
				if _, e = s.ingestStatisticsHistory(context.Background(), db, id, now); e == nil {
					t.Fatal("unsafe log accepted", kind)
				}
			}
			after, e := os.ReadFile(outside)
			if e != nil || string(after) != string(original) {
				t.Fatal("outside file changed", e)
			}
		})
	}
	t.Log("PASS links, writable logs, FIFO and unsafe SQLite paths refused without original-file mutation")
}

func TestStatisticsHistoryStreamLimitDoesNotResetOrLoseData(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	if e := os.WriteFile(path, []byte(statisticsTestLine(now, "/new")), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := db.Exec("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO access_streams(site,identity,name,offset,anchor,size,seen) SELECT ?,CAST(i AS TEXT),'qa',0,?,0,? FROM n", statisticsHistoryStreams, id, fmt.Sprintf("%064d", 0), now.Unix())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ingestStatisticsHistory(context.Background(), db, id, now); e == nil {
		t.Fatal("stream budget silently widened")
	}
	var count int
	if e = db.QueryRow("SELECT count(*) FROM access_streams").Scan(&count); e != nil || count != statisticsHistoryStreams || statisticsTestCount(t, db) != 0 {
		t.Fatal("limit changed original history", count, e)
	}
}

func TestStatisticsHistoryBackgroundCollectionAndUninstallFence(t *testing.T) {
	s, db, _, path, now := statisticsHistoryFixture(t)
	manifest := filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json")
	if err := moduleWrite(manifest, map[string]any{"id": "website-statistics-v2", "version": "2.3.0"}); err != nil {
		t.Fatal(err)
	}
	line := statisticsTestLine(now, "/background-only")
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.runStatisticsHistoryWorker(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("background worker did not terminate")
		}
	}()
	deadline := time.Now().Add(25 * time.Second)
	for {
		if statisticsTestCount(t, db) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("production 15-second worker did not collect the real fixture log")
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.mu.Lock()
	var status struct {
		CheckedAt string `json:"checked_at"`
		Error     string `json:"error"`
		Healthy   bool   `json:"healthy"`
	}
	err := moduleRead(filepath.Join(s.moduleDir("website-statistics-v2"), "history-worker.json"), &status)
	if err == nil {
		err = os.Rename(manifest, manifest+".qa-preserved")
	}
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.WriteString(line)
			f.Close()
		}
	}
	s.mu.Unlock()
	stamp, parseErr := time.Parse(time.RFC3339, status.CheckedAt)
	if err != nil || parseErr != nil || !status.Healthy || status.Error != "" || time.Since(stamp) > 3*time.Second {
		t.Fatal("actual background worker status was not fresh/known", status, err)
	}
	// The real interval runs once more with the installation marker absent.
	// No manual API/read/ingest call can account for these accepted rows.
	select {
	case <-time.After(17 * time.Second):
	case <-done:
		t.Fatal("worker stopped before lifecycle fence could be checked")
	}
	if statisticsTestCount(t, db) != 1 {
		t.Fatal("uninstalled fixture was still automatically collected")
	}
	if err = os.Rename(manifest+".qa-preserved", manifest); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		if statisticsTestCount(t, db) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not resume exact progress after reinstall fixture marker")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("PASS actual production 15-second background loop without a browser/manual ingestion, fresh private status, uninstall mutex fence, and resumed exact SQLite cursor; temporary fixture marker only, not installed authenticated lifecycle")
}
