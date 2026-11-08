package core

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
	"modernc.org/sqlite"
)

// Only a private fixture driver delays the return from a successful job write.
// This deterministically models slow SQL crossing a UTC second, without a
// production clock override or any rewrite of original audit/job evidence.
type runtimeStampBoundaryDriver struct {
	base driver.Driver
	hits atomic.Int64
}

func (d *runtimeStampBoundaryDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &runtimeStampBoundaryConn{Conn: c, owner: d}, nil
}

type runtimeStampBoundaryConn struct {
	driver.Conn
	owner *runtimeStampBoundaryDriver
}

func (c *runtimeStampBoundaryConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}

func (c *runtimeStampBoundaryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *runtimeStampBoundaryConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err != nil || !(strings.HasPrefix(query, "INSERT INTO runtime_jobs(") && strings.Contains(query, "'install_runtime'") || strings.HasPrefix(query, "UPDATE runtime_jobs SET state=")) {
		return result, err
	}
	if len(args) < 4 {
		return nil, fmt.Errorf("timestamp fixture did not match job arguments")
	}
	raw, ok := args[3].Value.(string)
	stamp, parseErr := time.Parse(time.RFC3339, raw)
	if !ok || parseErr != nil {
		return nil, fmt.Errorf("timestamp fixture received a noncanonical stamp")
	}
	c.owner.hits.Add(1)
	if delay := time.Until(stamp.Add(time.Second).Add(2 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return result, nil
}

func runtimeStampBoundaryStore(t *testing.T) (*Store, *runtimeStampBoundaryDriver) {
	t.Helper()
	s := testStore(t)
	var seq int
	var schema, filename string
	if err := s.DB.QueryRow("PRAGMA database_list").Scan(&seq, &schema, &filename); err != nil || schema != "main" || filename == "" {
		t.Fatal("private fixture database unavailable", err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	d := &runtimeStampBoundaryDriver{base: &sqlite.Driver{}}
	name := "runtime_stamp_boundary_" + ID()
	sql.Register(name, d)
	db, err := sql.Open(name, filename+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s.DB = db
	return s, d
}

func assertRuntimeAuditStamp(t *testing.T, s *Store, id, release string) (string, string) {
	t.Helper()
	var created, updated, queuedStamp, resultStamp string
	if err := s.DB.QueryRow("SELECT created_at,updated_at FROM runtime_jobs WHERE id=?", id).Scan(&created, &updated); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT created_at FROM audit_logs WHERE action='runtime.install' AND target=?", release).Scan(&queuedStamp); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT created_at FROM audit_logs WHERE action='install_runtime' AND target=?", release).Scan(&resultStamp); err != nil {
		t.Fatal(err)
	}
	if queuedStamp != created {
		t.Errorf("one queue transaction split job/audit timestamps: %s != %s", created, queuedStamp)
	}
	if resultStamp != updated {
		t.Errorf("one terminal transaction split job/audit timestamps: %s != %s", updated, resultStamp)
	}
	return created, updated
}

func finishBoundaryRuntimeFailure(t *testing.T, s *Store, id, release string) {
	t.Helper()
	in := RuntimeFailedInstallEvidence{JobID: id, ReleaseID: release, Error: "private slow SQL fixture", Steps: []Step{{Time: Now(), Message: "private slow SQL fixture"}}}
	if err := s.FinishRuntime(Job{ID: id, TargetID: release, Kind: "install_runtime"}, in.Error, in.Steps); err != nil {
		t.Fatal(err)
	}
	if digest, err := s.ValidateRuntimeFailedInstall(t.Context(), in); err != nil || len(digest) != 64 {
		t.Error("original failure must remain valid across slow SQL writes", digest, err)
	}
}

func TestRuntimeAuditTimestampSurvivesSQLSecondBoundary(t *testing.T) {
	s, boundary := runtimeStampBoundaryStore(t)
	release := runtimecatalog.Nginx[0].ID
	id, err := s.QueueInstall(release, ID(), "private-fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	finishBoundaryRuntimeFailure(t, s, id, release)
	assertRuntimeAuditStamp(t, s, id, release)
	if boundary.hits.Load() != 2 {
		t.Fatal("both real producer write paths were not delayed", boundary.hits.Load())
	}
}

func TestRuntimeBundleAuditTimestampSurvivesSQLSecondBoundary(t *testing.T) {
	s, boundary := runtimeStampBoundaryStore(t)
	releases := []string{runtimecatalog.Nginx[0].ID, runtimecatalog.PHPSecurity20261021[0].ID}
	key := ID()
	out, err := s.QueueInstallBundle(releases, key, "private-fixture-admin")
	if err != nil || len(out.JobIDs) != 2 {
		t.Fatal(out, err)
	}
	var bundleStamp string
	if err := s.DB.QueryRow("SELECT created_at FROM runtime_install_bundles WHERE idempotency_key=?", key).Scan(&bundleStamp); err != nil {
		t.Fatal(err)
	}
	for i, id := range out.JobIDs {
		finishBoundaryRuntimeFailure(t, s, id, releases[i])
		created, _ := assertRuntimeAuditStamp(t, s, id, releases[i])
		if created != bundleStamp {
			t.Errorf("atomic bundle split its own creation timestamps: %s != %s", created, bundleStamp)
		}
	}
	if boundary.hits.Load() != 4 {
		t.Fatal("all bundle queue/terminal writes were not delayed", boundary.hits.Load())
	}
}
