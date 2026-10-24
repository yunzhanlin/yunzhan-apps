//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func statisticsPublishedOpenFixture(t *testing.T, version int) (*Service, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires actual Linux Root and private trusted filesystem fixtures")
	}
	if err := threatIDSTrustedParents("/var/lib/panel-executor", true); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/var/lib/panel-executor", "statistics-open-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(base) != "/var/lib/panel-executor" || !strings.HasPrefix(filepath.Base(base), "statistics-open-fixture-") {
			t.Error("refuse broad fixture cleanup")
			return
		}
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	s := New(Config{SecurityDir: filepath.Join(base, "security"), StateDir: filepath.Join(base, "state"), SystemRoot: filepath.Join(base, "system")})
	db, err := s.openStatisticsHistorySchema(context.Background(), version)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return s, filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
}

// A report/QA snapshot must not make opening an ALREADY published schema
// request a write lock. This calls the real production opener, not copied SQL.
func TestStatisticsPublishedHistoryOpenPreservesOriginalBytesWithActiveReader(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			s, path := statisticsPublishedOpenFixture(t, version)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=query_only(1)"}
			reader, err := sql.Open("sqlite", u.String())
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var count int
			if err := tx.QueryRow("SELECT count(*) FROM access_streams").Scan(&count); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			opened, err := s.openStatisticsHistorySchema(ctx, version)
			if err != nil {
				t.Fatal("already-published schema opening requires a write lock while a legitimate reader is active", err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || core.Hash(string(before)) != core.Hash(string(after)) {
				t.Fatal("reopening current schema rewrote the original database", err)
			}
		})
	}
}

func TestStatisticsPublishedHistoryUnsafeSchemaNotAdoptedOrRepaired(t *testing.T) {
	for _, scenario := range []string{"missing-index", "foreign-index", "foreign-table", "foreign-trigger", "foreign-view", "zero-nonempty", "partial-future-schema"} {
		t.Run(scenario, func(t *testing.T) {
			s, path := statisticsPublishedOpenFixture(t, 1)
			writer, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			query := map[string]string{
				"missing-index":         "DROP INDEX access_time",
				"foreign-index":         "CREATE INDEX foreign_index ON access_rows(path)",
				"foreign-table":         "CREATE TABLE unrelated(value TEXT)",
				"foreign-trigger":       "CREATE TRIGGER unrelated AFTER INSERT ON access_rows BEGIN SELECT 1; END",
				"foreign-view":          "CREATE VIEW unrelated AS SELECT seq FROM access_rows",
				"zero-nonempty":         "PRAGMA user_version=0",
				"partial-future-schema": "CREATE TABLE access_receipts(site TEXT)",
			}[scenario]
			if _, err := writer.Exec(query); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []int{1, 2} {
				if opened, err := s.openStatisticsHistorySchema(context.Background(), target); err == nil {
					opened.Close()
					t.Fatal("changed original schema adopted or repaired", target)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || core.Hash(string(before)) != core.Hash(string(after)) {
				t.Fatal("refusal changed original schema/data", err)
			}
		})
	}
}

func TestStatisticsPublishedHistoryExplicitUpgradePreservesOriginalRows(t *testing.T) {
	s, path := statisticsPublishedOpenFixture(t, 1)
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`INSERT INTO access_rows VALUES(1,?,1792310400,'','/original',200,0,0,'original-private-fixture')`, strings.Repeat("a", 32)); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := s.openStatisticsHistorySchema(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var version, count int
	var payload string
	if upgraded.QueryRow("PRAGMA user_version").Scan(&version) != nil || version != 2 || upgraded.QueryRow("SELECT count(*) FROM access_rows").Scan(&count) != nil || count != 1 || upgraded.QueryRow("SELECT payload FROM access_rows WHERE seq=1").Scan(&payload) != nil || payload != "original-private-fixture" {
		t.Fatal("explicit upgrade lost original rows or version")
	}
	if err := validateStatisticsSchemaObjects(context.Background(), upgraded, 2); err != nil {
		t.Fatal(err)
	}
	if opened, err := s.openStatisticsHistorySchema(context.Background(), 1); err == nil {
		opened.Close()
		t.Fatal("newer installed schema silently downgraded")
	}
}

func TestStatisticsPublishedHistoryObservationContentionKeepsDeadlineAndSafetyFences(t *testing.T) {
	for _, scenario := range []string{"released", "deadline", "pending-transaction", "unsafe-lock", "cancelled-before-open", "nil-context"} {
		t.Run(scenario, func(t *testing.T) {
			s, path := statisticsPublishedOpenFixture(t, 1)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			switch scenario {
			case "nil-context":
				ctx = nil
			case "cancelled-before-open":
				cancel()
			case "released", "deadline":
				writer, err := s.statisticsLogTransactionService().lockWAFConfiguration()
				if err != nil {
					t.Fatal(err)
				}
				if lock, err := s.statisticsLogReadLock(); !errors.Is(err, errWAFConfigurationBusy) {
					if lock != nil {
						lock.Close()
					}
					writer.Close()
					t.Fatal("fixture did not hold an actual incompatible flock", err)
				}
				if scenario == "released" {
					done := make(chan error, 1)
					go func() { time.Sleep(70 * time.Millisecond); done <- writer.Close() }()
					t.Cleanup(func() {
						if err := <-done; err != nil {
							t.Error(err)
						}
					})
				} else {
					defer writer.Close()
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(context.Background(), 30*time.Millisecond)
					defer stop()
				}
			case "pending-transaction":
				pending := s.statisticsLogTransactionService().wafPendingPath()
				if err := os.MkdirAll(filepath.Dir(pending), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pending, []byte("unresolved private fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-lock":
				lock, err := s.statisticsLogReadLock()
				if err != nil {
					t.Fatal(err)
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			lock, err := s.statisticsLogReadLockContext(ctx)
			if scenario == "released" {
				if err != nil || lock == nil {
					t.Fatal("bounded read observation did not wait for the actual exclusive owner", err)
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if lock != nil {
					lock.Close()
					t.Fatal("unsafe, canceled or unresolved observation was granted")
				}
				if err == nil {
					t.Fatal("missing failure")
				}
				if scenario == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("original wait deadline was lost", err)
				}
				if scenario == "pending-transaction" || scenario == "unsafe-lock" {
					if errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("non-contention safety refusal was retried", err)
					}
				}
				if scenario == "nil-context" || scenario == "cancelled-before-open" {
					if _, err := os.Lstat(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")); !os.IsNotExist(err) {
						t.Fatal("invalid context created a lock", err)
					}
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || core.Hash(string(before)) != core.Hash(string(after)) {
				t.Fatal("lock observation changed original history", err)
			}
		})
	}
}
