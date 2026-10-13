//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statisticsArchiveTestWrite(t *testing.T, p string, raw []byte, now time.Time) {
	t.Helper()
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chtimes(p, now.Add(-15*time.Second), now.Add(-15*time.Second)); e != nil {
		t.Fatal(e)
	}
}
func statisticsArchiveTestCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil {
		t.Fatal(e)
	}
	return count
}
func TestStatisticsArchiveRuntimeDedupPrivacyRestartAndRetirement(t *testing.T) {
	s, db, id, p, now := statisticsReceiptFixture(t)
	first := statisticsIDTestLine(now, "/first?token=archive-secret", "00000000000000000000000000000001")
	second := statisticsIDTestLine(now, "/second", "00000000000000000000000000000002")
	if e := os.WriteFile(p, []byte(first+second), 0600); e != nil {
		t.Fatal(e)
	}
	statisticsTestIngest(t, s, db, id, now)
	third := statisticsIDTestLine(now, "/third", "00000000000000000000000000000003")
	archive := p + "." + now.Format("20060102-150405") + ".gz"
	compressed := statisticsTestGzip(t, []byte(first+second+third))
	statisticsArchiveTestWrite(t, archive, compressed, now)
	before := sha256.Sum256(compressed)
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 3 || state.Duplicates != 2 || state.VerifiedArchives != 1 || state.Compressed != 0 || state.Backlog != 0 || !state.RequestIDsEnabled {
		t.Fatal("runtime gzip dedup", state)
	}
	var payloads string
	rows, e := db.Query("SELECT payload FROM access_rows")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var v string
		if e = rows.Scan(&v); e != nil {
			t.Fatal(e)
		}
		payloads += v
	}
	rows.Close()
	if strings.Contains(payloads, "secret") || strings.Contains(payloads, "Mozilla") {
		t.Fatal("private history retained raw secrets")
	}
	db.Close()
	restart := New(s.Config)
	other, e := restart.openStatisticsHistorySchema(context.Background(), 2)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	state = statisticsTestIngest(t, restart, other, id, now)
	raw, e := os.ReadFile(archive)
	if e != nil || sha256.Sum256(raw) != before || statisticsTestCount(t, other) != 3 || state.Duplicates != 0 || state.VerifiedArchives != 1 {
		t.Fatal("gzip restart recounted or changed original", state, e)
	}
	if e = os.Remove(archive); e != nil {
		t.Fatal(e)
	}
	state = statisticsTestIngest(t, restart, other, id, now.AddDate(0, 0, statisticsHistoryDays).Add(2*time.Minute))
	if state.ExpiredStreams != 1 || statisticsArchiveTestCount(t, other, "access_archives") != 0 {
		t.Fatal("consumed absent archive did not retire atomically", state)
	}
	if _, e = os.Stat(p); e != nil {
		t.Fatal("source log was removed", e)
	}
	t.Log("PASS real schema2 ingestion, private ID dedup across plain/gzip, restart, unchanged archive and FK cursor retirement; isolated prototype, not signed app delivery")
}
func TestStatisticsArchiveRuntimeBadCacheAllowsLaterSourceAndLegacyGap(t *testing.T) {
	s, db, id, p, now := statisticsReceiptFixture(t)
	first := statisticsIDTestLine(now, "/live", "00000000000000000000000000000001")
	if e := os.WriteFile(p, []byte(first), 0600); e != nil {
		t.Fatal(e)
	}
	bad := p + "." + now.Add(-time.Second).Format("20060102-150405") + ".gz"
	corrupt := statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/not-accepted", "00000000000000000000000000000002")))
	corrupt[len(corrupt)-8] ^= 1
	statisticsArchiveTestWrite(t, bad, corrupt, now)
	good := p + "." + now.Format("20060102-150405") + ".gz"
	statisticsArchiveTestWrite(t, good, statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/accepted", "00000000000000000000000000000003")+statisticsTestLine(now, "/no-proof-id"))), now)
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 1 || state.Blocked != 1 || state.Compressed != 2 {
		t.Fatal("CRC accepted tentative rows or lost live log", state)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Blocked != 1 || state.Invalid != 1 || state.VerifiedArchives != 1 || statisticsArchiveTestCount(t, db, "access_receipts") != 2 {
		t.Fatal("corrupt cached source starved later gzip or legacy ID was invented", state)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Invalid != 1 || state.Blocked != 1 {
		t.Fatal("replayed compressed legacy/corrupt source", state)
	}
}
func TestStatisticsArchiveRuntimeRewriteAndWriteFailureKeepOriginalProgress(t *testing.T) {
	s, db, id, p, now := statisticsReceiptFixture(t)
	archive := p + "." + now.Format("20060102-150405") + ".gz"
	original := statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/old", "00000000000000000000000000000001")))
	statisticsArchiveTestWrite(t, archive, original, now)
	statisticsTestIngest(t, s, db, id, now)
	var offset int64
	if e := db.QueryRow("SELECT offset FROM access_streams").Scan(&offset); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(archive)
	if e != nil {
		t.Fatal(e)
	}
	replacement := statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/new", "00000000000000000000000000000002")))
	statisticsArchiveTestWrite(t, archive, replacement, now)
	after, e := os.Stat(archive)
	if e != nil || !os.SameFile(info, after) {
		t.Fatal("same-inode fixture", e)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	var actual int64
	if e = db.QueryRow("SELECT offset FROM access_streams").Scan(&actual); e != nil || actual != offset || statisticsTestCount(t, db) != 1 || state.Blocked != 1 {
		t.Fatal("rewritten archive reset progress", state, e)
	}
	statisticsArchiveTestWrite(t, archive, original, now)
	state = statisticsTestIngest(t, s, db, id, now)
	if state.Blocked != 0 || statisticsTestCount(t, db) != 1 {
		t.Fatal("byte-exact restored archive cannot resume safely", state)
	}
	next := p + "." + now.Add(time.Second).Format("20060102-150405") + ".gz"
	statisticsArchiveTestWrite(t, next, statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/old", "00000000000000000000000000000001")+statisticsIDTestLine(now, "/new", "00000000000000000000000000000002"))), now)
	if _, e = db.Exec("CREATE TRIGGER owned_gzip_failure BEFORE INSERT ON access_rows WHEN NEW.path='/new' BEGIN SELECT RAISE(ABORT,'owned refusal'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ingestStatisticsHistory(context.Background(), db, id, now); e == nil {
		t.Fatal("gzip row failure accepted")
	}
	if statisticsTestCount(t, db) != 1 || statisticsArchiveTestCount(t, db, "access_receipts") != 1 || statisticsArchiveTestCount(t, db, "access_archives") != 1 {
		t.Fatal("failed transaction retained cursor, row or receipt")
	}
	if _, e = db.Exec("DROP TRIGGER owned_gzip_failure"); e != nil {
		t.Fatal(e)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Duplicates != 1 || state.Blocked != 0 {
		t.Fatal("post-failure continuation lost identity", state)
	}
}
func TestStatisticsArchiveRuntimeLegacySchemaAndUnsafePathsRemainClosed(t *testing.T) {
	s, db, id, p, now := statisticsHistoryFixture(t)
	archive := p + "." + now.Format("20060102-150405") + ".gz"
	statisticsArchiveTestWrite(t, archive, statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/legacy", "00000000000000000000000000000001"))), now)
	state := statisticsTestIngest(t, s, db, id, now)
	var count int
	if e := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='access_archives'").Scan(&count); e != nil || count != 0 || statisticsTestCount(t, db) != 0 || state.Compressed != 1 || state.RequestIDsEnabled {
		t.Fatal("old app implicitly migrated gzip", state, e)
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			service, current, site, log, stamp := statisticsReceiptFixture(t)
			target := log + "." + stamp.Format("20060102-150405") + ".gz"
			source := filepath.Join(filepath.Dir(log), "unrelated-source")
			if e := os.WriteFile(source, statisticsTestGzip(t, []byte(statisticsIDTestLine(stamp, "/unsafe", "00000000000000000000000000000001"))), 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "symlink":
				e = os.Symlink(source, target)
			case "hardlink":
				e = os.Link(source, target)
			case "fifo":
				e = makeStatisticsTestFIFO(target)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = service.ingestStatisticsHistory(context.Background(), current, site, stamp); e == nil || statisticsTestCount(t, current) != 0 || statisticsArchiveTestCount(t, current, "access_archives") != 0 {
				t.Fatal("unsafe gzip source adopted", kind, e)
			}
		})
	}
	if statisticsAddBacklog(1<<62, 1<<62) != int64(^uint64(0)>>1) {
		t.Fatal(fmt.Sprint("backlog overflow"))
	}
}

func TestStatisticsArchiveRuntimeEvidenceDriftRefusesBeforeSkipOrRetirement(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE access_streams SET offset=0 WHERE identity LIKE 'gzip:%'",
		"UPDATE access_streams SET seen=1 WHERE identity LIKE 'gzip:%'",
		"UPDATE access_streams SET invalid=1 WHERE identity LIKE 'gzip:%'",
		"UPDATE access_archives SET evidence_sha='0000000000000000000000000000000000000000000000000000000000000000'",
		"UPDATE access_archives SET metadata='1:1:1:1:1'",
	} {
		t.Run(mutation[:min(len(mutation), 40)], func(t *testing.T) {
			s, db, id, path, now := statisticsReceiptFixture(t)
			archive := path + "." + now.Format("20060102-150405") + ".gz"
			statisticsArchiveTestWrite(t, archive, statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/protected", "00000000000000000000000000000001"))), now)
			statisticsTestIngest(t, s, db, id, now)
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ingestStatisticsHistory(context.Background(), db, id, now); err == nil {
				t.Fatal("completed cache trusted changed evidence")
			}
			if err := os.Remove(archive); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ingestStatisticsHistory(context.Background(), db, id, now.AddDate(0, 0, statisticsHistoryDays).Add(2*time.Minute)); err == nil {
				t.Fatal("corrupt absent evidence retired")
			}
			if statisticsTestCount(t, db) != 1 || statisticsArchiveTestCount(t, db, "access_receipts") != 1 || statisticsArchiveTestCount(t, db, "access_archives") != 1 {
				t.Fatal("closed refusal modified original data or evidence")
			}
		})
	}
}

func TestStatisticsArchiveRuntimeConventionalNumericAndDateextRotation(t *testing.T) {
	s, db, id, path, now := statisticsReceiptFixture(t)
	first := statisticsIDTestLine(now, "/rename", "00000000000000000000000000000001")
	if err := os.WriteFile(path, []byte(first), 0600); err != nil {
		t.Fatal(err)
	}
	statisticsTestIngest(t, s, db, id, now)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(statisticsIDTestLine(now, "/new", "00000000000000000000000000000002")), 0600); err != nil {
		t.Fatal(err)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.UnsupportedRotations != 0 {
		t.Fatal("numeric rename lost/replayed old requests", state)
	}
	statisticsArchiveTestWrite(t, path+".2.gz", statisticsTestGzip(t, []byte(first)), now)
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Duplicates != 1 || state.Compressed != 0 {
		t.Fatal("numeric gzip did not deduplicate", state)
	}
	statisticsArchiveTestWrite(t, path+"-"+now.Format("20060102")+".gz", statisticsTestGzip(t, []byte(statisticsIDTestLine(now, "/dateext", "00000000000000000000000000000003"))), now)
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 3 || state.UnsupportedRotations != 0 {
		t.Fatal("dateext archive ignored", state)
	}
	if err := os.WriteFile(path+".backup", []byte(first), 0600); err != nil {
		t.Fatal(err)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if state.UnsupportedRotations != 1 || statisticsTestCount(t, db) != 3 {
		t.Fatal("unknown rotation silently treated as complete", state)
	}
}

func TestStatisticsArchiveRuntimeLegacyReportsNumericGapWithoutMigrating(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	statisticsArchiveTestWrite(t, path+".1.gz", statisticsTestGzip(t, []byte(statisticsTestLine(now, "/legacy-numeric"))), now)
	state := statisticsTestIngest(t, s, db, id, now)
	if state.UnsupportedRotations != 1 || statisticsTestCount(t, db) != 0 {
		t.Fatal("legacy format gap was silently ignored or counted", state)
	}
	var schema int
	if err := db.QueryRow("PRAGMA user_version").Scan(&schema); err != nil || schema != 1 {
		t.Fatal("conventional archive implicitly upgraded legacy schema", schema, err)
	}
}
