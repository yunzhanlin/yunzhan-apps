//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestModuleWorkerSignalRollbackHelper(t *testing.T) {
	root := os.Getenv("PANEL_WORKER_SIGNAL_FIXTURE")
	if root == "" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	var g workerLifecycle
	g.start(ctx, nil, func(ctx context.Context) {
		db, err := sql.Open("sqlite", filepath.Join(root, "access.sqlite"))
		if err != nil {
			panic(err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if _, err = db.Exec("PRAGMA cache_size=1; PRAGMA cache_spill=ON"); err != nil {
			panic(err)
		}
		tx, err := db.Begin()
		if err != nil {
			panic(err)
		}
		defer tx.Rollback()
		// Spill real modified SQLite pages and leave an uncommitted journal.
		if _, err = tx.Exec("UPDATE kept SET value=?", strings.Repeat("uncommitted", 500)); err != nil {
			panic(err)
		}
		if err = os.WriteFile(filepath.Join(root, "ready"), []byte("transaction-open"), 0600); err != nil {
			panic(err)
		}
		<-ctx.Done()
	})
	<-ctx.Done()
	bounded, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := g.stop(bounded); err != nil {
		panic(err)
	}
}

// Actual child SIGTERM and SQLite spill, not mocked signal or SQL callbacks.
// This is isolated process evidence, not a physical power-loss acceptance.
func TestModuleWorkerRealSIGTERMPreservesCommittedSQLiteAndClosesJournal(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "access.sqlite")
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE kept(id INTEGER PRIMARY KEY,value TEXT NOT NULL); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50) INSERT INTO kept SELECT x,'committed-'||x FROM n"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	commandContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(commandContext, os.Args[0], "-test.run=^TestModuleWorkerSignalRollbackHelper$", "-test.count=1")
	child.Env = append(os.Environ(), "PANEL_WORKER_SIGNAL_FIXTURE="+root)
	var output strings.Builder
	child.Stdout, child.Stderr = &output, &output
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = os.Lstat(filepath.Join(root, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatal("child did not reach actual SQLite transaction", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	journal, err := os.Lstat(file + "-journal")
	if err != nil || journal.Size() <= 512 {
		t.Fatal("fixture did not create actual SQLite rollback records", err)
	}
	if err = child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err != nil {
		t.Fatal("SIGTERM was not drained", err, output.String())
	}
	if _, err = os.Lstat(file + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hot journal survived orderly stop", err)
	}
	db, err = sql.Open("sqlite", "file:"+file+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var check string
	var count int
	if err = db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		t.Fatal("read-only reopen required recovery or found corruption", check, err)
	}
	if err = db.QueryRow("SELECT count(*) FROM kept WHERE value='committed-'||id").Scan(&count); err != nil || count != 50 {
		t.Fatal("committed rows lost or uncommitted values published", count, err)
	}
}

func TestModuleWorkersCanceledStartupDoesNotCreateOrRestart(t *testing.T) {
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "absent"), SitesDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.StartAppModuleWorkerContext(ctx)
	if err := s.StopAppModuleWorker(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.StartAppModuleWorkerContext(context.Background())
	if _, err := os.Lstat(s.Config.SecurityDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late worker admission changed absent application state", err)
	}
}
