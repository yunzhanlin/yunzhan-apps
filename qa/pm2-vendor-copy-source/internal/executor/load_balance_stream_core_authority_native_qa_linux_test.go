//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Real private Root filesystem/SQLite models, never the actual panel database.
func streamAuthorityNativeAnchor(t *testing.T) string {
	t.Helper()
	anchor := os.Getenv("PANEL_LBSTREAM_AUTHORITY_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit isolated Root authority models only; no installation/controller acceptance")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/lbstream-authority-native24bmdd-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) || threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("closed private Root fixture required")
	}
	return anchor
}

func streamCoreAuthorityNativeFixture(t *testing.T, wal bool) (string, *core.Store, loadbalancestream.Operation, loadbalancestream.OperationBinding) {
	t.Helper()
	streamAuthorityNativeAnchor(t)
	base := filepath.Join(t.TempDir(), "core")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	writer, err := core.OpenStore(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.DB.Close() })
	writer.DB.SetMaxOpenConns(1)
	op := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: core.ID(), ActorID: core.ID(), Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "auth.lb.invalid", Policy: &loadbalancestream.Policy{Protocol: "tcp", Port: 42000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41002", Weight: 3}}, Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64}}}
	raw, err := loadbalancestream.OperationBytes(op)
	if err != nil {
		t.Fatal(err)
	}
	now := core.Now()
	for _, q := range []struct {
		text string
		args []any
	}{
		{`CREATE TABLE IF NOT EXISTS load_balance_stream_controls(request_id TEXT PRIMARY KEY NOT NULL,actor_id TEXT NOT NULL,access_revision INTEGER NOT NULL CHECK(access_revision>0),operation TEXT NOT NULL,operation_sha256 TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,scope TEXT NOT NULL DEFAULT 'host' CHECK(scope='host'),state TEXT NOT NULL CHECK(state IN ('reserved','issued','unknown','completed')),result TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,CHECK(length(request_id)=32 AND length(actor_id)=32 AND length(operation) BETWEEN 1 AND 17408 AND length(operation_sha256)=64 AND length(manifest_sha256)=64 AND length(result)<=2048))`, nil},
		{`CREATE UNIQUE INDEX IF NOT EXISTS one_active_load_balance_stream_control ON load_balance_stream_controls(scope) WHERE state<>'completed'`, nil},
		{`INSERT INTO users(id,username,password_hash,created_at)VALUES(?,'isolated-stream-authority',X'00',?)`, []any{op.ActorID, now}},
		{`INSERT INTO app_user_roles(user_id,role,site_ids)VALUES(?,'admin','[]')`, []any{op.ActorID}},
		{`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('load-balance','load-balance',?,?,'load-balance',?)`, []any{loadbalancestream.AppVersion, strings.Repeat("1", 64), now}},
		{`INSERT INTO load_balance_stream_controls(request_id,actor_id,access_revision,operation,operation_sha256,manifest_sha256,state,created_at,updated_at)VALUES(?,?,1,?,?,?,'issued',?,?)`, []any{op.RequestID, op.ActorID, string(raw), loadbalancestream.OperationSHA256(op), strings.Repeat("1", 64), now, now}},
	} {
		if _, err := writer.DB.Exec(q.text, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	mode := "DELETE"
	if wal {
		mode = "WAL"
	}
	var actual string
	if writer.DB.QueryRow("PRAGMA journal_mode="+mode).Scan(&actual) != nil || actual != strings.ToLower(mode) {
		t.Fatal("private fixture journal mode")
	}
	if wal {
		if _, err := writer.DB.Exec("UPDATE users SET username='isolated-stream-live-wal'"); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		name := filepath.Join(base, "panel.db"+suffix)
		if _, err := os.Lstat(name); os.IsNotExist(err) {
			continue
		}
		if err := os.Chmod(name, 0600); err != nil {
			t.Fatal(err)
		}
	}
	authority, err := writer.LoadBalanceStreamControlAuthority(context.Background(), op)
	if err != nil {
		t.Fatal("actual fixture authority", err)
	}
	expected := loadbalancestream.OperationBinding{Format: 1, AppID: "load-balance", AppVersion: loadbalancestream.AppVersion, OperationSHA256: authority.OperationSHA256, ManifestSHA256: authority.ManifestSHA256, InstalledSHA256: strings.Repeat("2", 64), ProgrammeInputs: strings.Repeat("3", 64), ActorObservationSHA: authority.ActorObservationSHA256, OriginalConfigSHA256: strings.Repeat("4", 64)}
	expected.OriginalRequestSHA256 = authority.OriginalRequestSHA256
	return base, writer, op, expected
}

func TestLoadBalanceStreamCoreAuthorityNativeSelectOnlyFreshWALAndBinding(t *testing.T) {
	base, writer, op, binding := streamCoreAuthorityNativeFixture(t, true)
	ctx := context.Background()
	source, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &loadBalanceStreamCoreAuthority{source: source}
	defer r.close()
	if err = r.check(ctx, op, binding); err != nil {
		t.Fatal("original current authority prerequisite", err)
	}
	if _, err = source.db.Exec("UPDATE load_balance_stream_controls SET state='completed'"); err == nil {
		t.Fatal("SELECT-only authority could write")
	}
	for _, field := range []string{"manifest", "actor", "version", "legacy-receipt", "request", "binding-hash", "nil-context", "canceled", "upgrade-blocked"} {
		t.Run(field, func(t *testing.T) {
			next, changed, check := binding, op, ctx
			blocked := source.blocked
			switch field {
			case "manifest":
				next.ManifestSHA256 = strings.Repeat("9", 64)
			case "actor":
				next.ActorObservationSHA = strings.Repeat("a", 64)
			case "version":
				next.AppVersion = "1.8.5"
			case "legacy-receipt":
				if _, err := writer.DB.Exec("UPDATE app_registry_receipts SET version='1.8.5' WHERE app_id='load-balance'"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := writer.DB.Exec("UPDATE app_registry_receipts SET version=? WHERE app_id='load-balance'", loadbalancestream.AppVersion); err != nil {
						t.Error(err)
					}
				}()
			case "request":
				changed.RequestID = core.ID()
			case "binding-hash":
				next.OperationSHA256 = strings.Repeat("b", 64)
			case "nil-context":
				check = nil
			case "canceled":
				var cancel context.CancelFunc
				check, cancel = context.WithCancel(ctx)
				cancel()
			case "upgrade-blocked":
				source.blocked = func() bool { return true }
			}
			err := r.check(check, changed, next)
			source.blocked = blocked
			if err == nil {
				t.Fatal("unbound/currently blocked prerequisite accepted", field)
			}
		})
	}
	if err = r.check(ctx, op, binding); err != nil {
		t.Fatal("independent restored synthetic fixture prerequisite", err)
	}
	if _, err = writer.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", op.ActorID); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("live WAL revocation ignored")
	}
	// Synthetic fixture reset, not restoration/reuse of a real production grant.
	if _, err = writer.DB.Exec("UPDATE app_user_roles SET role='admin'WHERE user_id=?", op.ActorID); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", op.ActorID); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("revoked menu ceiling inherited")
	}
	var state string
	if source.db.QueryRow("SELECT state FROM load_balance_stream_controls WHERE request_id=?", op.RequestID).Scan(&state) != nil || state != "issued" {
		t.Fatal("read-only refusal changed original reservation")
	}
}

func TestLoadBalanceStreamCoreAuthorityNativeOriginalFilesystemAndSchemaRefuse(t *testing.T) {
	base, writer, op, binding := streamCoreAuthorityNativeFixture(t, false)
	ctx := context.Background()
	source, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &loadBalanceStreamCoreAuthority{source: source}
	defer r.close()
	if r.check(ctx, op, binding) != nil {
		t.Fatal("complete private DELETE-mode fixture refused")
	}
	db := filepath.Join(base, "panel.db")
	if err = os.Chmod(db, 0666); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("publicly writable database accepted")
	}
	if err = os.Chmod(db, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(db, db+".linked"); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("hard-linked database accepted")
	}
	if err = os.Remove(db + ".linked"); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.DB.Exec("DROP INDEX one_active_load_balance_stream_control"); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("partial schema accepted or repaired")
	}
	if _, err = writer.DB.Exec("CREATE UNIQUE INDEX one_active_load_balance_stream_control ON load_balance_stream_controls(scope) WHERE state<>'completed'"); err != nil {
		t.Fatal(err)
	}
	if err = r.check(ctx, op, binding); err != nil {
		t.Fatal("independent restored synthetic shape", err)
	}
	if _, err = writer.DB.Exec("UPDATE load_balance_stream_controls SET state='unknown'"); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("unknown request became native authority")
	}
	if err = os.WriteFile(db+"-journal", []byte("foreign private test journal"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.check(ctx, op, binding) == nil {
		t.Fatal("ambiguous live journal accepted")
	}
	if other, err := openMemcachedUpdateCoreAuthorityAt(ctx, base, 0); err == nil {
		other.Close()
		t.Fatal("constructor adopted ambiguous journal")
	}
}
