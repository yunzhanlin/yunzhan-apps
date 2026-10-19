package core

import (
	"context"
	"strings"
	"testing"
)

func TestMemcachedUpgradeEveryOriginalPhaseAndRevokedActorAreNotDrainProof(t *testing.T) {
	cases := []struct {
		name   string
		phases []string
		allow  bool
	}{
		{"reserved", nil, false}, {"unknown", nil, false},
		{"prepared", []string{}, false},
		{"pull_started", []string{"pull_started"}, false},
		{"image_verified", []string{"pull_started", "image_verified"}, false},
		{"apply_started", []string{"pull_started", "image_verified", "apply_started"}, false},
		{"applied", []string{"pull_started", "image_verified", "apply_started", "applied"}, false},
		{"rollback_started", []string{"pull_started", "image_verified", "apply_started", "rollback_started"}, false},
		{"needs_attention", []string{"needs_attention"}, false},
		{"failed_safe", []string{"failed_safe"}, true},
		{"rolled_back", []string{"pull_started", "image_verified", "apply_started", "rollback_started", "rolled_back"}, true},
		{"committed", []string{"pull_started", "image_verified", "apply_started", "applied", "committed"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			if c.name == "unknown" {
				if err := s.markMemcachedUpdateUnknown(context.Background(), actor.ID, seed.Dispatch.RequestID); err != nil {
					t.Fatal(err)
				}
			} else if c.name != "reserved" {
				if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, c.phases...)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); err != nil {
				t.Fatal(err)
			}
			before := memcachedStoreCounts(t, s)
			if err := s.CheckMemcachedUpdateUpgrade(context.Background()); (err == nil) != c.allow {
				t.Fatalf("phase %s allow=%v: %v", c.name, c.allow, err)
			}
			if memcachedStoreCounts(t, s) != before {
				t.Fatal("upgrade guard wrote state, audit, job or receipt")
			}
		})
	}
}

func TestMemcachedUpgradeMissingSchemaPairAndInvalidTerminalNeverRepair(t *testing.T) {
	for _, scenario := range []string{"empty", "older-absent", "missing-index", "changed-index", "bad-chain", "missing-audit", "missing-receipt", "conflicting-receipt", "wrong-target"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			if scenario == "older-absent" {
				if _, err := s.DB.Exec(`DROP TABLE memcached_update_requests`); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "missing-index" || scenario == "changed-index" {
				if _, err := s.DB.Exec(`DROP INDEX one_active_memcached_update_project`); err != nil {
					t.Fatal(err)
				}
				if scenario == "changed-index" {
					if _, err := s.DB.Exec(`CREATE INDEX one_active_memcached_update_project ON memcached_update_requests(project_id)`); err != nil {
						t.Fatal(err)
					}
				}
			} else if scenario != "empty" {
				memcachedStoreReserve(t, s, actor, seed)
				if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")); err != nil {
					t.Fatal(err)
				}
				queries := map[string]string{"bad-chain": `UPDATE memcached_update_requests SET chain='[]'`, "missing-audit": `DELETE FROM audit_logs WHERE action='app.memcached.update.observe'`, "missing-receipt": `DELETE FROM app_registry_receipts WHERE app_id='memcached'`, "conflicting-receipt": `UPDATE app_registry_receipts SET sha256='` + strings.Repeat("e", 64) + `' WHERE app_id='memcached'`, "wrong-target": `UPDATE app_registry_receipts SET target='other' WHERE app_id='memcached'`}
				if _, err := s.DB.Exec(queries[scenario]); err != nil {
					t.Fatal(err)
				}
			}
			var before, after string
			projection := `SELECT coalesce(group_concat(type||':'||name||':'||sql,'|'),'') FROM (SELECT type,name,sql FROM sqlite_master ORDER BY type,name)`
			if err := s.DB.QueryRow(projection).Scan(&before); err != nil {
				t.Fatal(err)
			}
			allow := scenario == "empty" || scenario == "older-absent"
			if err := s.CheckMemcachedUpdateUpgrade(context.Background()); (err == nil) != allow {
				t.Fatalf("allow=%v: %v", allow, err)
			}
			if err := s.DB.QueryRow(projection).Scan(&after); err != nil || after != before {
				t.Fatal("guard migrated or repaired original schema", err)
			}
		})
	}
}

// A missing Core row is not proof that its already-audited delivery never
// happened. Do not silently admit another job or call that an empty queue.
func TestMemcachedUpgradeOrphanedAuditCannotBecomeEmptyOrFreshAdmission(t *testing.T) {
	for _, action := range []string{"app.memcached.update.reserve", "app.memcached.update.observe", "app.memcached.update.unrecognized"} {
		t.Run(action, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			target := ID()
			if action == "app.memcached.update.observe" {
				target += ":0"
			}
			if _, err := s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, actor.ID, action, target, strings.Repeat("a", 64), Now()); err != nil {
				t.Fatal(err)
			}
			before := memcachedStoreCounts(t, s)
			if s.CheckMemcachedUpdateUpgrade(context.Background()) == nil {
				t.Fatal("orphan or unknown original audit was treated as an empty queue")
			}
			if _, fresh, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed); err == nil || fresh {
				t.Fatal("unreconciled original audit allowed a fresh native admission")
			}
			if memcachedStoreCounts(t, s) != before {
				t.Fatal("guard repaired/deleted evidence or reserved a replacement task")
			}
		})
	}
}
