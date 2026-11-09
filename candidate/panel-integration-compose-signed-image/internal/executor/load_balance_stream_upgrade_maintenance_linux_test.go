//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

// A programme upgrade must repeat the complete SELECT-only inventory AFTER it
// sets its maintenance marker and stops Core. That marker must still deny
// every live installation/control/completion grant on this SAME held reader.
func TestLoadBalanceStreamUpgradeSnapshotsDuringMaintenanceKeepMutationFence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires the original Root-owned Core filesystem fixture")
	}
	for _, wal := range []bool{false, true} {
		name := "stopped-Core"
		if wal {
			name = "live-WAL"
		}
		t.Run(name, func(t *testing.T) {
			base, _, _ := memcachedCoreAuthorityFixture(t, wal)
			ctx := context.Background()
			reader, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			calls := 0
			reader.blocked = func() bool { calls++; return true }
			core := &loadBalanceStreamCoreAuthority{source: reader}
			before, err := os.ReadFile(filepath.Join(base, "panel.db"))
			if err != nil {
				t.Fatal(err)
			}
			jobs, err := core.upgradeJobs(ctx, nil)
			if err != nil || len(jobs) != 0 {
				t.Fatal("maintenance blocked the complete read-only install inventory", err)
			}
			history, err := core.controlUpgradeHistory(ctx, nil)
			if err != nil || len(history) != 0 {
				t.Fatal("maintenance blocked the complete read-only control history", err)
			}
			if calls != 0 {
				t.Fatal("inventory borrowed the live mutation-admission predicate")
			}
			if _, err := reader.db.ExecContext(ctx, `INSERT INTO schema_migrations VALUES(999999,'forbidden-write')`); err == nil {
				t.Fatal("read-only inventory gained SQL write access")
			}
			operation := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind,
				RequestID: strings.Repeat("b", 32), ActorID: strings.Repeat("c", 32),
				Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "maintenance.example",
					Policy: &loadbalancestream.Policy{Protocol: "tcp", Port: 42000,
						Nodes:  []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41001", Weight: 1}},
						Method: "round-robin", ConnectMilliseconds: 1000, SessionSeconds: 30, MaxSessions: 16}}}
			if _, err := loadbalancestream.OperationBytes(operation); err != nil {
				t.Fatal(err)
			}
			if _, err := core.installAuthority(ctx, strings.Repeat("a", 32)); err == nil || calls != 1 {
				t.Fatal("maintenance no longer denies live installation authority", err, calls)
			}
			if _, err := core.controlAuthority(ctx, operation); err == nil || calls != 2 {
				t.Fatal("maintenance no longer denies live control authority", err, calls)
			}
			if _, err := core.controlCompletion(ctx, operation); err == nil || calls != 3 {
				t.Fatal("maintenance no longer denies live completion authority", err, calls)
			}
			after, err := os.ReadFile(filepath.Join(base, "panel.db"))
			if err != nil || sha256.Sum256(before) != sha256.Sum256(after) || !reader.current() {
				t.Fatal("read-only inventory changed the original held database", err)
			}
		})
	}
}

func TestLoadBalanceStreamUpgradeSnapshotsDuringMaintenanceRejectUnknownOrChangedInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires the original Root-owned Core filesystem fixture")
	}
	for _, tc := range []struct {
		name    string
		change  string
		history bool
	}{
		{"unfinished-selected-job", `INSERT INTO runtime_jobs(id,target_id,kind,state,error,steps,idempotency_key,created_at,updated_at,payload) VALUES('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','load-balance','software_install','queued','','[]','maintenance-unbound-job','2026-10-27T00:00:00Z','2026-10-27T00:00:00Z','{"settings":{},"version":"1.9.0"}')`, false},
		{"changed-install-schema", `ALTER TABLE load_balance_stream_install_requests ADD COLUMN invented TEXT`, false},
		{"changed-control-schema", `ALTER TABLE load_balance_stream_controls ADD COLUMN invented TEXT`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, writer, _ := memcachedCoreAuthorityFixture(t, true)
			ctx := context.Background()
			reader, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			calls := 0
			reader.blocked = func() bool { calls++; return true }
			if _, err := writer.DB.Exec(tc.change); err != nil {
				t.Fatal(err)
			}
			core := &loadBalanceStreamCoreAuthority{source: reader}
			if _, err := core.upgradeJobs(ctx, nil); err == nil {
				t.Fatal("maintenance admitted unknown work or a changed schema")
			}
			if tc.history {
				if _, err := core.controlUpgradeHistory(ctx, nil); err == nil {
					t.Fatal("maintenance admitted a changed control-history schema")
				}
			}
			if calls != 0 {
				t.Fatal("negative inventory was rejected only by the unrelated mutation fence")
			}
			reader.blocked = nil
			if _, err := core.upgradeJobs(ctx, nil); err == nil {
				t.Fatal("an incomplete reader became an upgrade inventory")
			}
			if _, err := core.controlUpgradeHistory(ctx, nil); err == nil {
				t.Fatal("an incomplete reader became control history")
			}
		})
	}
}
