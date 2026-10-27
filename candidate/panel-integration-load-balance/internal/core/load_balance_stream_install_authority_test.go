package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/loadbalancestream"
)

// Actual existing registry binders and SQLite transactions, but no HTTP/native
// installer. Native availability stays disabled; this fixture does not invoke
// the dedicated original installer or prove native application acceptance.
func streamInstallFixture(t *testing.T, action string, issue bool) (*Store, identity, string, string) {
	t.Helper()
	s := testStore(t)
	s.DB.SetMaxOpenConns(1)
	if err := s.migrateLoadBalanceStreamInstallRequests(); err != nil {
		t.Fatal(err)
	}
	u := accessUser(t, s, "stream-install-owner", "admin", nil)
	job, key := ID(), ID()
	payload := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
	if action == "update" {
		payload = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	now := Now()
	if _, err = tx.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance',?,'queued',?,?,?,?)", job, "software_"+action, payload, key, now, now); err != nil {
		t.Fatal(err)
	}
	item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Version: loadbalancestream.AppVersion, SHA256: strings.Repeat("1", 64), Provider: "panel-module"}
	bind := s.bindRegistryUpdate(item, item.Target, key, u.ID)
	if action == "install" {
		bind = s.bindRegistryInstall(item, item.Target, key, u.ID, registryInstallInput{Settings: map[string]any{}, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
	}
	if err = bind(tx, job, false); err != nil {
		t.Fatal("original registry transaction", err)
	}
	if issue {
		if err = s.bindLoadBalanceStreamInstallRequest(u.ID, key)(tx, job, false); err != nil {
			t.Fatal("original full-administrator grant", err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if issue {
		if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='running',updated_at=? WHERE id=?", Now(), job); err != nil {
			t.Fatal(err)
		}
	}
	return s, u, job, key
}

func streamInstallSnapshot(t *testing.T, s *Store) string {
	t.Helper()
	queries := []string{"SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"}
	for _, n := range []string{"runtime_jobs", "app_registry_install_requests", "app_registry_update_requests", "app_registry_pending", "app_registry_request_closures", "load_balance_stream_install_requests", "audit_logs", "users", "app_user_roles", "app_user_menus"} {
		queries = append(queries, "SELECT *FROM "+n+" ORDER BY 1")
	}
	var snapshot [][][]any
	for _, q := range queries {
		rows, err := s.DB.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		data := [][]any{}
		for rows.Next() {
			v, dst := make([]any, len(cols)), make([]any, len(cols))
			for i := range v {
				dst[i] = &v[i]
			}
			if err = rows.Scan(dst...); err != nil {
				t.Fatal(err)
			}
			data = append(data, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, data)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestLoadBalanceStreamInstallAuthorityOriginalAtomicGrantSelectOnly(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, u, job, key := streamInstallFixture(t, action, true)
			before := streamInstallSnapshot(t, s)
			v, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job)
			if err != nil || v.Format != 1 || v.JobID != job || v.ActorID != u.ID || v.Action != action || v.AppVersion != "1.9.0" || v.AccessRevision != 1 || v.KeySHA256 != Hash(key) || !streamControlDigest(v.ActorObservationSHA256) || !streamControlDigest(v.OriginalRequestSHA256) {
				t.Fatal("original independently selected grant refused", v, err)
			}
			if _, err = s.DB.Exec("PRAGMA query_only=ON"); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				got, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job)
				if err != nil || !reflect.DeepEqual(got, v) {
					t.Fatal("SELECT-only original observation changed", err)
				}
			}
			if streamInstallSnapshot(t, s) != before {
				t.Fatal("observation changed schema, original job, authority or registry history")
			}
		})
	}
}

func TestLoadBalanceStreamInstallAuthorityOriginalDriftNeverRepaired(t *testing.T) {
	faults := []string{"unsigned", "queued", "failed", "succeeded", "unknown", "cancelled", "kind", "target", "payload", "oversized", "key", "legacy-version", "manifest", "actor", "provider", "scope", "request-clock", "future-clock", "missing-pending", "forked-pending", "original-grant-missing", "original-grant-changed", "viewer", "limited-admin", "site-scoped-admin", "restored-revision", "missing-user", "foreign-trigger", "competing-unknown-job", "closed-key", "wrong-original-payload"}
	for _, action := range []string{"install", "update"} {
		for _, fault := range faults {
			t.Run(action+"/"+fault, func(t *testing.T) {
				s, u, job, key := streamInstallFixture(t, action, true)
				if _, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job); err != nil {
					t.Fatal("invalid base before independent mutation", err)
				}
				table := "app_registry_" + action + "_requests"
				q, args := "", []any{}
				switch fault {
				case "unsigned":
					q = "DELETE FROM " + table
				case "queued", "failed", "succeeded", "unknown", "cancelled":
					q, args = "UPDATE runtime_jobs SET state=?", []any{fault}
				case "kind":
					q = "UPDATE runtime_jobs SET kind='software_configure'"
				case "target":
					q = "UPDATE runtime_jobs SET target_id='nginx-waf'"
				case "payload":
					q = "UPDATE runtime_jobs SET payload='{}'"
				case "oversized":
					q, args = "UPDATE runtime_jobs SET payload=?", []any{strings.Repeat("x", 1025)}
				case "key":
					q = "UPDATE runtime_jobs SET idempotency_key='other-original'"
				case "legacy-version":
					q = "UPDATE " + table + " SET version='1.8.5'"
				case "manifest":
					q, args = "UPDATE "+table+" SET sha256=?", []any{strings.Repeat("9", 64)}
				case "actor":
					q, args = "UPDATE "+table+" SET actor_id=?", []any{ID()}
				case "provider":
					q = "UPDATE " + table + " SET provider='runtime'"
				case "scope":
					q = "UPDATE " + table + " SET scope='other'"
				case "request-clock":
					q, args = "UPDATE "+table+" SET created_at=?", []any{time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)}
				case "future-clock":
					q, args = "UPDATE runtime_jobs SET updated_at=?", []any{time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}
				case "missing-pending":
					q = "DELETE FROM app_registry_pending"
				case "forked-pending":
					q, args = "UPDATE app_registry_pending SET sha256=?", []any{strings.Repeat("9", 64)}
				case "original-grant-missing":
					q = "DELETE FROM load_balance_stream_install_requests"
				case "original-grant-changed":
					q = "UPDATE load_balance_stream_install_requests SET access_revision=2"
				case "viewer":
					q = "UPDATE app_user_roles SET role='viewer'"
				case "limited-admin":
					q, args = "INSERT INTO app_user_menus VALUES(?,'[\"runtimes\"]',2)", []any{u.ID}
				case "site-scoped-admin":
					q, args = "UPDATE app_user_roles SET site_ids=?", []any{`["` + ID() + `"]`}
				case "restored-revision":
					menus, _ := normalizeMenuIDs("admin", nil)
					raw, _ := json.Marshal(menus)
					q, args = "INSERT INTO app_user_menus VALUES(?,?,3)", []any{u.ID, string(raw)}
				case "missing-user":
					q = "DELETE FROM users"
				case "foreign-trigger":
					q = "CREATE TRIGGER foreign_stream_install AFTER INSERT ON load_balance_stream_install_requests BEGIN SELECT 1;END"
				case "competing-unknown-job":
					q, args = "INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance','software_configure','needs_attention','{}',?,?,?)", []any{ID(), ID(), Now(), Now()}
				case "closed-key":
					q, args = "INSERT INTO app_registry_request_closures(idempotency_key,actor_id,app_id,action,version,sha256,created_at)VALUES(?,?,'load-balance',?,'1.9.0',?,?)", []any{key, u.ID, action, strings.Repeat("1", 64), Now()}
				case "wrong-original-payload":
					q, args = "UPDATE load_balance_stream_install_requests SET payload_sha256=?", []any{strings.Repeat("9", 64)}
				}
				if _, err := s.DB.Exec(q, args...); err != nil {
					t.Fatal("independent mutation", fault, err)
				}
				before := streamInstallSnapshot(t, s)
				if _, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job); err == nil {
					t.Fatal("drift authorized privileged installation", fault)
				}
				if streamInstallSnapshot(t, s) != before {
					t.Fatal("refusal repaired or overwrote original records", fault)
				}
			})
		}
	}
}

func TestLoadBalanceStreamInstallAuthorityAtomicBinderRefusesUnissuedOrRevoked(t *testing.T) {
	for _, fault := range []string{"unbound-existing", "viewer", "limited-admin", "wrong-actor", "wrong-key"} {
		t.Run(fault, func(t *testing.T) {
			s, u, job, key := streamInstallFixture(t, "install", false)
			actor, provided := u.ID, key
			switch fault {
			case "viewer":
				if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer'"); err != nil {
					t.Fatal(err)
				}
			case "limited-admin":
				if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[\"runtimes\"]',2)", u.ID); err != nil {
					t.Fatal(err)
				}
			case "wrong-actor":
				actor = ID()
			case "wrong-key":
				provided = ID()
			}
			before := streamInstallSnapshot(t, s)
			tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			err = s.bindLoadBalanceStreamInstallRequest(actor, provided)(tx, job, fault == "unbound-existing")
			tx.Rollback()
			if err == nil || streamInstallSnapshot(t, s) != before {
				t.Fatal("unissued/revoked original was adopted or changed", fault, err)
			}
		})
	}
}
