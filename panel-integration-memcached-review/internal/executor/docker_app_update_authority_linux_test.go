//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// OpenStore is used ONLY to construct these separate trusted-root fixtures.
// The production reader must never migrate, initialize or repair the Core DB.
func memcachedCoreAuthorityFixture(t *testing.T, wal bool) (string, *core.Store, core.MemcachedUpdateRecord) {
	t.Helper()
	journal, seed := memcachedJournalFixture(t)
	base := filepath.Join(filepath.Dir(journal.base), "core")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := core.OpenStore(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	s.DB.SetMaxOpenConns(1)
	now := core.Now()
	for _, q := range []struct {
		text string
		args []any
	}{
		{`INSERT INTO users(id,username,password_hash,created_at) VALUES(?,'isolated-authority',X'00',?)`, []any{seed.Record.Dispatch.ActorID, now}},
		{`INSERT INTO app_user_roles(user_id,role,site_ids) VALUES(?,'admin','[]')`, []any{seed.Record.Dispatch.ActorID}},
		{`INSERT INTO memcached_update_requests(request_id,job_id,actor_id,project_id,dispatch_sha256,seed_record,chain,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'','reserved',?,?)`, []any{seed.Record.Dispatch.RequestID, seed.Record.Dispatch.JobID, seed.Record.Dispatch.ActorID, seed.Record.Dispatch.ProjectID, seed.Record.DispatchSHA256, mustMemcachedAuthorityJSON(t, seed.Record), now, now}},
		{`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.update.reserve',?,?,?)`, []any{seed.Record.Dispatch.ActorID, seed.Record.Dispatch.JobID, seed.Record.RecordSHA256, now}},
	} {
		if _, err := s.DB.Exec(q.text, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if wal {
		// A live writer keeps the legitimate existing WAL/SHM pair present.
		var mode string
		if s.DB.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode) != nil || mode != "wal" {
			t.Fatal("fixture WAL mode")
		}
		if _, err := s.DB.Exec(`UPDATE users SET username='isolated-live-wal'`); err != nil {
			t.Fatal(err)
		}
	} else {
		var mode string
		if s.DB.QueryRow(`PRAGMA journal_mode=DELETE`).Scan(&mode) != nil || mode != "delete" {
			t.Fatal("fixture DELETE mode")
		}
		if err := s.DB.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := filepath.Join(base, "panel.db"+suffix)
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			continue
		}
		if err := os.Chmod(p, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return base, s, seed.Record
}

func mustMemcachedAuthorityJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMemcachedCoreAuthoritySelectOnlyAndFreshWALRevocation(t *testing.T) {
	for _, wal := range []bool{false, true} {
		name := "closed-delete"
		if wal {
			name = "live-wal"
		}
		t.Run(name, func(t *testing.T) {
			base, writer, seed := memcachedCoreAuthorityFixture(t, wal)
			r, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
			if err != nil {
				t.Fatal("trusted original fixture not readable", err)
			}
			defer r.Close()
			if err := r.check(context.Background(), seed); err != nil {
				t.Fatal("original full administrator/reservation", err)
			}
			var count, after int
			if r.db.QueryRow(`SELECT count(*) FROM memcached_update_requests`).Scan(&count) != nil || count != 1 {
				t.Fatal("original request missing")
			}
			if _, err := r.db.Exec(`DELETE FROM memcached_update_requests`); err == nil {
				t.Fatal("native reader could mutate original SQL")
			}
			if r.db.QueryRow(`SELECT count(*) FROM memcached_update_requests`).Scan(&after) != nil || after != count {
				t.Fatal("SELECT-only check changed original requests")
			}
			changed := seed
			changed.Dispatch.ActorID = strings.Repeat("f", 32)
			changed.DispatchSHA256 = core.MemcachedUpdateDispatchSHA(changed.Dispatch)
			changed, err = core.SealMemcachedUpdateRecord(changed)
			if err != nil || r.check(context.Background(), changed) == nil {
				t.Fatal("different actor adopted the original request")
			}
			if !wal {
				return
			}
			// The original reader is kept open. A role change in CURRENT WAL
			// must be seen, not an immutable/cached main-file authorization.
			if _, err := writer.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+strings.Repeat("b", 32)+`"]`, seed.Dispatch.ActorID); err != nil {
				t.Fatal(err)
			}
			if r.check(context.Background(), seed) == nil {
				t.Fatal("site-restricted administrator retained host-wide authority")
			}
			if _, err := writer.DB.Exec(`UPDATE app_user_roles SET site_ids='[]' WHERE user_id=?`, seed.Dispatch.ActorID); err != nil {
				t.Fatal(err)
			}
			if err := r.check(context.Background(), seed); err != nil {
				t.Fatal("unchanged full administrator at original revision", err)
			}
			if _, err := writer.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'[]',2)`, seed.Dispatch.ActorID); err != nil {
				t.Fatal(err)
			}
			if r.check(context.Background(), seed) == nil {
				t.Fatal("current WAL menu revocation ignored")
			}
		})
	}
}

func TestMemcachedCoreAuthorityUnsafeFilesNeverRepaired(t *testing.T) {
	for _, scenario := range []string{"missing-db", "public-db", "group-write-db", "foreign-db", "hardlink", "symlink", "fifo", "short-db", "journal", "unsafe-parent", "foreign-parent", "symlink-parent", "wal-missing-shm", "wal-symlink", "wal-foreign", "wal-hardlink", "wal-public"} {
		t.Run(scenario, func(t *testing.T) {
			wal := strings.HasPrefix(scenario, "wal-")
			base, writer, _ := memcachedCoreAuthorityFixture(t, wal)
			if wal {
				// Closing would remove the pair; pin a separate connection until cleanup.
				_ = writer
			}
			file := filepath.Join(base, "panel.db")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "missing-db":
				must(os.Remove(file))
			case "public-db":
				must(os.Chmod(file, 0644))
			case "group-write-db":
				must(os.Chmod(file, 0620))
			case "foreign-db":
				must(os.Chown(file, 65534, 65534))
			case "hardlink":
				must(os.Link(file, file+".alias"))
			case "symlink", "fifo":
				must(os.Rename(file, file+".original"))
				if scenario == "symlink" {
					must(os.Symlink("panel.db.original", file))
				} else {
					must(unix.Mkfifo(file, 0600))
				}
			case "short-db":
				must(os.Truncate(file, 16))
			case "journal":
				must(os.WriteFile(file+"-journal", []byte("unrecovered fixture"), 0600))
			case "unsafe-parent":
				must(os.Chmod(base, 0770))
			case "foreign-parent":
				must(os.Chown(base, 65534, 65534))
			case "symlink-parent":
				must(os.Rename(base, base+".original"))
				must(os.Symlink(filepath.Base(base)+".original", base))
			case "wal-missing-shm":
				must(os.Rename(file+"-shm", file+"-shm.original"))
			case "wal-symlink":
				must(os.Rename(file+"-wal", file+"-wal.original"))
				must(os.Symlink("panel.db-wal.original", file+"-wal"))
			case "wal-foreign":
				must(os.Chown(file+"-wal", 65534, 65534))
			case "wal-hardlink":
				must(os.Link(file+"-wal", file+"-wal.alias"))
			case "wal-public":
				must(os.Chmod(file+"-shm", 0644))
			}
			before, err := os.Lstat(file)
			if err != nil && scenario != "missing-db" {
				t.Fatal(err)
			}
			if r, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0); err == nil {
				r.Close()
				t.Fatal("unsafe filesystem adopted", scenario)
			}
			after, err := os.Lstat(file)
			if scenario == "missing-db" {
				if !os.IsNotExist(err) {
					t.Fatal("missing database was created")
				}
			} else if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("refused source repaired or replaced", err)
			}
		})
	}
}

func TestMemcachedCoreAuthorityRechecksNamedInodesContextAndUpgradeFence(t *testing.T) {
	for _, scenario := range []string{"replaced-db", "detached-parent", "changed-mode", "changed-owner", "new-journal", "blocked", "nil-context", "cancelled", "closed", "missing-index", "orphan-audit"} {
		t.Run(scenario, func(t *testing.T) {
			base, _, seed := memcachedCoreAuthorityFixture(t, false)
			r, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(base, "panel.db")
			switch scenario {
			case "replaced-db":
				body, err := os.ReadFile(file)
				must(err)
				must(os.Rename(file, file+".original"))
				must(os.WriteFile(file, body, 0600))
			case "detached-parent":
				must(os.Rename(base, base+".original"))
				must(os.Mkdir(base, 0700))
			case "changed-mode":
				must(os.Chmod(file, 0644))
			case "changed-owner":
				must(os.Chown(file, 65534, 65534))
			case "new-journal":
				must(os.WriteFile(file+"-journal", []byte("unrecovered fixture"), 0600))
			case "blocked":
				r.blocked = func() bool { return true }
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				r.Close()
			case "missing-index", "orphan-audit":
				// Separate fixture-only writer, never the protected production DB.
				s, err := core.OpenStore(file)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "missing-index" {
					_, err = s.DB.Exec(`DROP INDEX one_active_memcached_update_project`)
				} else {
					_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('fixture','app.memcached.update.reserve','unrelated','unresolved',?)`, core.Now())
				}
				must(err)
				must(s.DB.Close())
			}
			if r.check(ctx, seed) == nil {
				t.Fatal("changed current precondition authorized", scenario)
			}
		})
	}
	var nilReader *memcachedUpdateCoreAuthority
	if nilReader.check(context.Background(), core.MemcachedUpdateRecord{}) == nil {
		t.Fatal("nil reader authorized")
	}
	nilReader.Close()
}

var memcachedCoreNativeAuthority = flag.Bool("memcached-core-native-authority", false, "explicit owned-QA only: SELECT-only fixed Core authority reader; never migrate or update apps")

func TestMemcachedCoreAuthorityNativeFixedAccountAndDatabaseReadOnly(t *testing.T) {
	if !*memcachedCoreNativeAuthority {
		t.Skip("requires explicit owned Linux Root QA with existing panel Core DB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native QA must use actual Linux Root")
	}
	r, err := openMemcachedUpdateCoreAuthority(context.Background())
	if err != nil {
		t.Fatal("fixed protected existing Core reader", err)
	}
	defer r.Close()
	if r.base != "/var/lib/panel" || r.owner == 0 {
		t.Fatal("native fixed path/account changed")
	}
	var queryOnly, before, after int
	if r.db.QueryRow(`PRAGMA query_only`).Scan(&queryOnly) != nil || queryOnly != 1 || r.db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&before) != nil {
		t.Fatal("native readonly schema observation")
	}
	if r.check(context.Background(), core.MemcachedUpdateRecord{}) == nil {
		t.Fatal("unreserved invalid seed authorized")
	}
	if r.db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&after) != nil || before != after || !r.current() {
		t.Fatal("native SELECT-only observation altered schema/paths")
	}
}
