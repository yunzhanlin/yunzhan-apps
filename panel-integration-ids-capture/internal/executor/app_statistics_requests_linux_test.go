//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statisticsIDTestLine(now time.Time, path, requestID string) string {
	var row analyticsAccess
	if err := json.Unmarshal([]byte(statisticsTestLine(now, path)), &row); err != nil {
		panic(err)
	}
	row.RequestID = requestID
	raw, _ := json.Marshal(row)
	return string(raw) + "\n"
}

func statisticsReceiptFixture(t *testing.T) (*Service, *sql.DB, string, string, time.Time) {
	t.Helper()
	s, old, id, path, now := statisticsHistoryFixture(t)
	old.Close()
	db, err := s.openStatisticsHistorySchema(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return s, db, id, path, now
}

func TestStatisticsRequestReceiptsSeparateIdenticalRequestsAndCopiedLogs(t *testing.T) {
	s, db, id, path, now := statisticsReceiptFixture(t)
	first := statisticsIDTestLine(now, "/same", "00000000000000000000000000000001")
	second := statisticsIDTestLine(now, "/same", "00000000000000000000000000000002")
	if err := os.WriteFile(path, []byte(first+second), 0600); err != nil {
		t.Fatal(err)
	}
	state := statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Duplicates != 0 {
		t.Fatal("identical legitimate requests collapsed", state)
	}
	archive := path + "." + now.Format("20060102-150405")
	if err := os.WriteFile(archive, []byte(first+second), 0600); err != nil {
		t.Fatal(err)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 2 || state.Duplicates != 2 || state.Backlog != 0 {
		t.Fatal("copied records duplicated real requests", state)
	}
	// Capacity-retired report rows must not erase the independent request identity.
	if _, err := db.Exec("DELETE FROM access_rows WHERE site=?", id); err != nil {
		t.Fatal(err)
	}
	newer := path + "." + now.Add(time.Second).Format("20060102-150405")
	if err := os.WriteFile(newer, []byte(first+second), 0600); err != nil {
		t.Fatal(err)
	}
	state = statisticsTestIngest(t, s, db, id, now)
	if statisticsTestCount(t, db) != 0 || state.Duplicates != 2 {
		t.Fatal("capacity-retired IDs recounted through another archive", state)
	}
	var receipts int
	if err := db.QueryRow("SELECT count(*) FROM access_receipts").Scan(&receipts); err != nil || receipts != 2 {
		t.Fatal("independent receipts lost", receipts, err)
	}
	t.Log("PASS distinct native-format request IDs retain two identical requests; copied logs deduplicate even after report-row capacity retirement")
}

func TestStatisticsRequestReceiptConflictAndWriteFailureRollbackCursor(t *testing.T) {
	for _, kind := range []string{"conflict", "write-failure"} {
		t.Run(kind, func(t *testing.T) {
			s, db, id, path, now := statisticsReceiptFixture(t)
			old := statisticsIDTestLine(now, "/original", "00000000000000000000000000000001")
			if err := os.WriteFile(path, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			statisticsTestIngest(t, s, db, id, now)
			var oldOffset int64
			if err := db.QueryRow("SELECT offset FROM access_streams WHERE site=?", id).Scan(&oldOffset); err != nil {
				t.Fatal(err)
			}
			line := statisticsIDTestLine(now, "/new", "00000000000000000000000000000002")
			if kind == "conflict" {
				line += statisticsIDTestLine(now, "/conflicting", "00000000000000000000000000000001")
			} else {
				if _, err := db.Exec("CREATE TRIGGER owned_receipt_row_failure BEFORE INSERT ON access_rows WHEN NEW.path='/new' BEGIN SELECT RAISE(ABORT,'owned refusal'); END"); err != nil {
					t.Fatal(err)
				}
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
			if _, err = s.ingestStatisticsHistory(context.Background(), db, id, now); err == nil {
				t.Fatal("conflict or row failure accepted")
			}
			var offset int64
			var receipts int
			if err = db.QueryRow("SELECT offset FROM access_streams WHERE site=?", id).Scan(&offset); err != nil || offset != oldOffset {
				t.Fatal("failed transaction advanced cursor", offset, err)
			}
			if err = db.QueryRow("SELECT count(*) FROM access_receipts").Scan(&receipts); err != nil || receipts != 1 || statisticsTestCount(t, db) != 1 {
				t.Fatal("failed transaction retained tentative receipt or row", receipts, err)
			}
		})
	}
}

func TestStatisticsRequestReceiptCeilingAndPrivateSchemaMigration(t *testing.T) {
	// Construct an actual v1 store. Dropping only receipts from a v2 store
	// left its future archive table behind and mislabeled partial v2 as v1.
	// Such a store must be refused, not repaired by the production opener.
	s, db, id, _, now := statisticsHistoryFixture(t)
	legacy := statisticsTestLine(now, "/legacy")
	row, stamp, valid := statisticsPrivateRow([]byte(legacy), now)
	if !valid {
		t.Fatal("legacy fixture")
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	if duplicate, err := insertStatisticsRequest(context.Background(), tx, id, row, stamp, &count); err != nil || duplicate || count != 0 {
		t.Fatal("legacy row manufactured an ID", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = validateStatisticsSchemaObjects(context.Background(), db, 1); err != nil {
		t.Fatal(err)
	}
	db.Close()
	migrated, err := s.openStatisticsHistorySchema(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var version int
	if err = migrated.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 || statisticsTestCount(t, migrated) != 1 {
		t.Fatal("schema migration lost original history", version, err)
	}
	dbpath := filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
	st, err := os.Lstat(dbpath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("schema migration loosened privacy", err)
	}
	var current analyticsAccess
	if err = json.Unmarshal([]byte(statisticsIDTestLine(now, "/ceiling", "00000000000000000000000000000003")), &current); err != nil {
		t.Fatal(err)
	}
	current, stamp, valid = statisticsPrivateRow(mustJSONStatisticsRow(t, current), now)
	if !valid {
		t.Fatal("identity fixture")
	}
	tx, err = migrated.Begin()
	if err != nil {
		t.Fatal(err)
	}
	count = statisticsHistoryReceipts
	if _, err = insertStatisticsRequest(context.Background(), tx, id, current, stamp, &count); err == nil {
		t.Fatal("receipt ceiling silently deleted dedup evidence")
	}
	_ = tx.Rollback()
	if statisticsTestCount(t, migrated) != 1 {
		t.Fatal("ceiling mutated original rows")
	}
	t.Log("PASS actual v1→v2 private SQLite migration preserves legacy rows; exact closed identity ceiling refuses without deleting evidence (not one-million-row load acceptance)")
}

func mustJSONStatisticsRow(t *testing.T, row analyticsAccess) []byte {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStatisticsRequestIdentityValidationAndFutureRetentionMargin(t *testing.T) {
	for _, value := range []string{"", "123", strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("0", 33), strings.Repeat("0", 31)} {
		if statisticsRequestID(value) {
			t.Fatal("invalid request identity accepted", fmt.Sprintf("%q", value))
		}
	}
	s, db, id, path, now := statisticsReceiptFixture(t)
	future := now.Add(time.Minute)
	line := statisticsIDTestLine(future, "/future", "00000000000000000000000000000004")
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	statisticsTestIngest(t, s, db, id, now)
	payload := statisticsTestLine(now, "/invalid")
	var row analyticsAccess
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		t.Fatal(err)
	}
	row.RequestID = strings.Repeat("X", 32)
	if _, _, valid := statisticsPrivateRow(mustJSONStatisticsRow(t, row), now); valid {
		t.Fatal("malformed source identity accepted as legacy")
	}
	// With the report row retired, the receipt still protects the accepted future
	// minute until that minute itself is outside the full retention boundary.
	before := now.AddDate(0, 0, statisticsHistoryDays).Add(time.Minute)
	statisticsTestIngest(t, s, db, id, before)
	var receipts int
	if err := db.QueryRow("SELECT count(*) FROM access_receipts").Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("future margin retired receipt early", receipts, err)
	}
	after := before.Add(time.Minute + time.Second)
	statisticsTestIngest(t, s, db, id, after)
	if err := db.QueryRow("SELECT count(*) FROM access_receipts").Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("expired receipts never retired", receipts, err)
	}
}

func TestStatisticsRequestProgramUpgradeDoesNotAdvanceLegacyApplicationSchema(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json"), map[string]any{
		"id": "website-statistics-v2", "version": "2.4.1", "settings": map[string]any{}, "installed_at": now.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(statisticsTestLine(now, "/preserved")), 0600); err != nil {
		t.Fatal(err)
	}
	statisticsTestIngest(t, s, db, id, now)
	db.Close()
	legacy, err := s.openStatisticsHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var version, receipts int
	if err = legacy.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("program upgrade silently migrated installed2.4.1", version, err)
	}
	if err = legacy.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='access_receipts'").Scan(&receipts); err != nil || receipts != 0 || statisticsTestCount(t, legacy) != 1 {
		t.Fatal("legacy application acquired the new receipt schema", receipts, err)
	}
	legacy.Close()
	newer, err := s.openStatisticsHistorySchema(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	newer.Close()
	dbpath := filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
	before, err := os.ReadFile(dbpath)
	if err != nil {
		t.Fatal(err)
	}
	if wronglyOpened, err := s.openStatisticsHistory(context.Background()); err == nil {
		wronglyOpened.Close()
		t.Fatal("legacy application accepted or downgraded a future history schema")
	}
	after, err := os.ReadFile(dbpath)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("legacy refusal changed future history database", err)
	}
	t.Log("PASS installed2.4.1 remains schema1 under new binaries; future schema is refused without downgrade or byte mutation")
}

func TestStatisticsRequestSelectedInstallVersionAndConfigureKeepLegacySchema(t *testing.T) {
	s, db, id, path, now := statisticsHistoryFixture(t)
	s.Config.NginxConf = filepath.Join(filepath.Dir(path), "owned-nginx.conf")
	if err := os.WriteFile(s.Config.NginxConf, statisticsNginxTestConfig(statisticsNginxLegacyFormat), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", map[string]any{}, "2.6.0", func(string) {}); err == nil {
		t.Fatal("future handler install accepted")
	}
	manifestPath := filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json")
	if _, err := os.Lstat(manifestPath); !os.IsNotExist(err) {
		t.Fatal("future install wrote a record", err)
	}
	if err := s.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", map[string]any{}, "2.4.0", func(string) {}); err != nil {
		t.Fatal(err)
	}
	before, err := s.moduleInstalledRecord("website-statistics-v2")
	if err != nil || before["version"] != "2.4.0" {
		t.Fatal("selected old package became current handler", before, err)
	}
	if err = s.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", map[string]any{}, "2.4.1", func(string) {}); err == nil {
		t.Fatal("install overwrote existing application")
	}
	if err = s.appModuleLifecycle(context.Background(), "website-statistics-v2", "configure", map[string]any{"custom": "kept"}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	after, err := s.moduleInstalledRecord("website-statistics-v2")
	if err != nil || after["version"] != "2.4.0" || after["installed_at"] != before["installed_at"] {
		t.Fatal("configuration rewrote installed identity", after, err)
	}
	if err = os.WriteFile(path, []byte(statisticsTestLine(now, "/old-schema")), 0600); err != nil {
		t.Fatal(err)
	}
	statisticsTestIngest(t, s, db, id, now)
	db.Close()
	old, err := s.openStatisticsHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var schema int
	if err = old.QueryRow("PRAGMA user_version").Scan(&schema); err != nil || schema != 1 || statisticsTestCount(t, old) != 1 {
		t.Fatal("selected legacy install/config migrated original history", schema, err)
	}
}
