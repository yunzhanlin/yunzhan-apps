//go:build linux

package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// These are isolated real SQLite fixtures, never installed host state. Closed
// SELECT-only history must remain readable without changing blocked() or
// allowing a programme reader to become a native configuration writer.
func TestLoadBalanceStreamUpgradeCompletionDuringMaintenanceIsExactReadOnlyHistory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Root-owned SQLite fixture")
	}
	for _, wal := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped-Core", true: "live-WAL"}[wal], func(t *testing.T) {
			base, writer, _ := memcachedCoreAuthorityFixture(t, true)
			row := streamUpgradeControlRecordFixture()
			op := row.Operation
			operation, err := loadbalancestream.OperationBytes(op)
			if err != nil {
				t.Fatal(err)
			}
			digest := loadbalancestream.OperationSHA256(op)
			now := core.Now()
			manifest := strings.Repeat("1", 64)
			result := `{"format":1,"request_id":"` + op.RequestID + `","operation_sha256":"` + digest + `","state":"committed","seed_sha256":"` + strings.Repeat("2", 64) + `","final_event_sha256":"` + strings.Repeat("3", 64) + `","configuration_sha256":"` + strings.Repeat("4", 64) + `","service_observation_sha256":"` + strings.Repeat("5", 64) + `"}`
			audit := `{"format":1,"operation_sha256":"` + digest + `","nonce":"` + core.ID() + `"}`
			if _, err = writer.DB.Exec(`INSERT INTO load_balance_stream_controls(request_id,actor_id,access_revision,operation,operation_sha256,manifest_sha256,state,result,created_at,updated_at)VALUES(?,?,1,?,?,?,'completed',?,?,?)`, op.RequestID, op.ActorID, string(operation), digest, manifest, result, now, now); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.control',?,?,?)`, op.ActorID, op.RequestID, audit, now); err != nil {
				t.Fatal(err)
			}
			if !wal {
				if _, err = writer.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
					t.Fatal(err)
				}
				if _, err = writer.DB.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
					t.Fatal(err)
				}
				if err = writer.DB.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			source, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			calls := 0
			source.blocked = func() bool { calls++; return true }
			authority := &loadBalanceStreamCoreAuthority{source: source}
			history, err := authority.controlUpgradeHistory(ctx, nil)
			if err != nil || len(history) != 1 {
				t.Fatal("real closed original fixture", err)
			}
			raw, _ := json.Marshal(history)
			w := &loadBalanceStreamTrafficUpgrade{source: authority, history: raw, closed: map[string]bool{op.RequestID: true}, namespaces: &programQueueReader{ctx: ctx, root: base}}
			actual, err := w.recordedCompletion(ctx, op)
			if err != nil || actual != history[0].Completion || actual.OriginalRequestSHA256 != core.Hash(audit) || calls != 0 {
				t.Fatal("closed original maintenance read", err, calls)
			}
			if _, err = authority.controlCompletion(ctx, op); err == nil || calls != 1 {
				t.Fatal("live completion fence weakened", err, calls)
			}
			if err = (&loadBalanceStreamConfigurationStore{upgrade: w}).beforeCurrent(ctx); err != loadbalancestream.ErrRuntime {
				t.Fatal("historical reader became a writer")
			}
			if _, err = streamGenerationRecordedCompletion(ctx, &loadBalanceStreamCoreAuthority{}, w, op); err == nil {
				t.Fatal("other Core source adopted inventory")
			}
			changed := op
			changed.ActorID = core.ID()
			if _, err = w.recordedCompletion(ctx, changed); err == nil {
				t.Fatal("same ID selected a different original actor")
			}
			if _, err = source.db.Exec("DELETE FROM load_balance_stream_controls"); err == nil {
				t.Fatal("historical reader gained SQL write access")
			}
			// Only now open the isolated fixture writer for negative mutations;
			// the stopped-Core positive above had no writer or WAL/SHM pair.
			if !wal {
				writer.DB, err = sql.Open("sqlite", filepath.Join(base, "panel.db"))
				if err != nil {
					t.Fatal(err)
				}
				writer.DB.SetMaxOpenConns(1)
			}
			changedAudit := `{"format":1,"operation_sha256":"` + digest + `","nonce":"` + core.ID() + `"}`
			if _, err = writer.DB.Exec(`UPDATE audit_logs SET result=? WHERE action='app.load-balance.stream.control'`, changedAudit); err != nil {
				t.Fatal(err)
			}
			if _, err = authority.controlUpgradeHistory(ctx, nil); err != nil {
				t.Fatal("changed nonce fixture must still be canonical", err)
			}
			if _, err = w.recordedCompletion(ctx, op); err == nil {
				t.Fatal("a rehashed different original request was adopted")
			}
			for _, change := range []string{
				`UPDATE audit_logs SET result=replace(result,'"nonce":"','"nonce":"0')WHERE action='app.load-balance.stream.control'`,
				`UPDATE load_balance_stream_controls SET state='unknown',result=''`,
			} {
				if _, err = writer.DB.Exec(`UPDATE audit_logs SET result=? WHERE action='app.load-balance.stream.control'`, audit); err != nil {
					t.Fatal(err)
				}
				if _, err = writer.DB.Exec(`UPDATE load_balance_stream_controls SET state='completed',result=?`, result); err != nil {
					t.Fatal(err)
				}
				tx, err := writer.DB.Begin()
				if err != nil {
					t.Fatal(err)
				}
				// Publish only within this isolated fixture, then retain the refusal.
				if _, err = tx.Exec(change); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if _, err = w.recordedCompletion(ctx, op); err == nil {
					t.Fatal("changed/unknown original history adopted")
				}
			}
		})
	}
}
