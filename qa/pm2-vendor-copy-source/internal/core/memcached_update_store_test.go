package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// These are isolated SQLite/authority fixtures, not signed application delivery
// or live Docker progress. Only the real Core/Root adapter may supply a trusted
// independently verified original chain to the private reconcile method.
func memcachedStoreFixture(t *testing.T) (*Store, identity, MemcachedUpdateRecord) {
	t.Helper()
	s := testStore(t)
	actor := accessUser(t, s, "memcached-owner", "admin", nil)
	seed := memcachedTransactionFixture(t)
	seed.Dispatch.ActorID = actor.ID
	seed.DispatchSHA256 = MemcachedUpdateDispatchSHA(seed.Dispatch)
	var err error
	seed, err = SealMemcachedUpdateRecord(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('memcached',?,'1.6.45-compat1',?,'memcached-cache',?)`, seed.Dispatch.ProjectID, strings.Repeat("9", 64), Now()); err != nil {
		t.Fatal(err)
	}
	return s, actor, seed
}

func memcachedStoreCounts(t *testing.T, s *Store) [5]int {
	t.Helper()
	var out [5]int
	if err := s.DB.QueryRow(`SELECT (SELECT count(*) FROM memcached_update_requests),(SELECT count(*) FROM audit_logs WHERE action LIKE 'app.memcached.update.%'),(SELECT count(*) FROM app_registry_receipts),(SELECT count(*) FROM app_registry_pending),(SELECT count(*) FROM runtime_jobs)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4]); err != nil {
		t.Fatal(err)
	}
	return out
}

func memcachedStoreReceipt(t *testing.T, s *Store, project string) [4]string {
	t.Helper()
	var out [4]string
	if err := s.DB.QueryRow(`SELECT version,sha256,target,updated_at FROM app_registry_receipts WHERE app_id='memcached' AND scope=?`, project).Scan(&out[0], &out[1], &out[2], &out[3]); err != nil {
		t.Fatal(err)
	}
	return out
}

func memcachedStoreChain(t *testing.T, seed MemcachedUpdateRecord, phases ...string) []MemcachedUpdateRecord {
	t.Helper()
	chain := []MemcachedUpdateRecord{seed}
	for _, phase := range phases {
		chain = append(chain, memcachedTransactionNext(t, chain[len(chain)-1], phase))
	}
	return chain
}

func memcachedStoreReserve(t *testing.T, s *Store, actor identity, seed MemcachedUpdateRecord) memcachedUpdateReservation {
	t.Helper()
	row, fresh, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed)
	if err != nil || !fresh || row.Seed != seed || row.State != "reserved" || len(row.Chain) != 0 {
		t.Fatal("isolated initial reservation", row.State, fresh, err)
	}
	return row
}

func TestMemcachedStoreAtomicReservationAndReplayNeverDispatchOrAdvanceVersion(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	oldReceipt := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
	original := memcachedStoreReserve(t, s, actor, seed)
	counts := memcachedStoreCounts(t, s)
	if counts != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("reservation queued a different runtime/app operation", counts)
	}
	for range 3 {
		prior, fresh, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed)
		if err != nil || fresh || !reflect.DeepEqual(prior, original) || memcachedStoreCounts(t, s) != counts || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != oldReceipt {
			t.Fatal("replay changed original identity, audits, state or version", err)
		}
	}
	other := accessUser(t, s, "another-admin", "admin", nil)
	if _, _, err := s.memcachedUpdateForActor(context.Background(), other.ID, seed.Dispatch.RequestID); err == nil {
		t.Fatal("another administrator adopted private original request")
	}
	changed := seed
	changed.Dispatch.JobID, changed.Dispatch.RequestID = ID(), ID()
	changed.DispatchSHA256 = MemcachedUpdateDispatchSHA(changed.Dispatch)
	changed, _ = SealMemcachedUpdateRecord(changed)
	if _, _, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, changed); err == nil || memcachedStoreCounts(t, s) != counts {
		t.Fatal("new key bypassed the uncertain same-project reservation")
	}
	changed = seed
	changed.Dispatch.ActorID = other.ID
	changed.DispatchSHA256 = MemcachedUpdateDispatchSHA(changed.Dispatch)
	changed, _ = SealMemcachedUpdateRecord(changed)
	if _, _, err := s.reserveMemcachedUpdate(context.Background(), other.ID, changed); err == nil {
		t.Fatal("same key/job rebound to another actor")
	}
}

func TestMemcachedStoreOriginalReservationSurvivesDatabaseReopenWithoutResubmit(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	original := memcachedStoreReserve(t, s, actor, seed)
	var seq int
	var name, filename string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &filename); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.DB.Close() })
	prior, fresh, err := reopened.reserveMemcachedUpdate(context.Background(), actor.ID, seed)
	if err != nil || fresh || !reflect.DeepEqual(prior, original) || memcachedStoreCounts(t, reopened) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("restart resubmitted or discarded original request", err)
	}
}

func TestMemcachedStoreCurrentAuthorityAndRevisionCannotBeRevivedByRestoringMenus(t *testing.T) {
	for _, scenario := range []string{"viewer", "operator", "limited-admin", "site-scoped-admin", "revoked-menus", "restored-revision", "malformed-menus", "duplicate-menus", "deleted-owner"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			if err := s.CheckMemcachedUpdateMutation(context.Background(), seed); err != nil {
				t.Fatal("initial original mutation permission", err)
			}
			var err error
			switch scenario {
			case "viewer", "operator":
				_, err = s.DB.Exec(`UPDATE app_user_roles SET role=? WHERE user_id=?`, scenario, actor.ID)
			case "limited-admin":
				_, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'["runtimes","system-tools"]',2)`, actor.ID)
			case "site-scoped-admin":
				_, err = s.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+strings.Repeat("7", 32)+`"]`, actor.ID)
			case "revoked-menus":
				_, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'[]',2)`, actor.ID)
			case "restored-revision":
				menus, _ := normalizeMenuIDs("admin", nil)
				raw, _ := json.Marshal(menus)
				_, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'[]',2)`, actor.ID)
				if err == nil {
					_, err = s.DB.Exec(`UPDATE app_user_menus SET menu_ids=?,revision=3 WHERE user_id=?`, string(raw), actor.ID)
				}
			case "malformed-menus":
				_, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'{',2)`, actor.ID)
			case "duplicate-menus":
				_, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'["runtimes","runtimes"]',2)`, actor.ID)
			case "deleted-owner":
				_, err = s.DB.Exec(`DELETE FROM users WHERE id=?`, actor.ID)
			}
			if err != nil {
				t.Fatal("isolated permission fixture", err)
			}
			before := memcachedStoreCounts(t, s)
			if s.CheckMemcachedUpdateMutation(context.Background(), seed) == nil {
				t.Fatal("revoked/restored original grant authorized a mutation")
			}
			if _, _, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed); err == nil {
				t.Fatal("revoked/restored grant reacquired dispatch eligibility")
			}
			_, found, readErr := s.memcachedUpdateForActor(context.Background(), actor.ID, seed.Dispatch.RequestID)
			if scenario == "restored-revision" {
				if readErr != nil || !found {
					t.Fatal("read-only original evidence should survive restored current admin access", readErr)
				}
			} else if readErr == nil {
				t.Fatal("current revoked reader permission inherited from stale session")
			}
			if memcachedStoreCounts(t, s) != before {
				t.Fatal("authority check mutated request, receipt or audit")
			}
		})
	}
}

func TestMemcachedStoreNativeAuthorityRechecksClosedSchemaAndAllOriginalIntents(t *testing.T) {
	for _, scenario := range []string{"missing-index", "changed-index", "extra-index", "extra-trigger", "orphan-reserve", "orphan-observe", "unknown-audit", "unrelated-corrupt-reservation", "nil-context", "nil-store", "nil-database"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			var err error
			switch scenario {
			case "missing-index", "changed-index":
				_, err = s.DB.Exec(`DROP INDEX one_active_memcached_update_project`)
				if err == nil && scenario == "changed-index" {
					_, err = s.DB.Exec(`CREATE INDEX one_active_memcached_update_project ON memcached_update_requests(project_id)`)
				}
			case "extra-index":
				_, err = s.DB.Exec(`CREATE INDEX unknown_update_index ON memcached_update_requests(actor_id)`)
			case "extra-trigger":
				_, err = s.DB.Exec(`CREATE TRIGGER unknown_update_trigger AFTER INSERT ON memcached_update_requests BEGIN SELECT 1; END`)
			case "orphan-reserve", "orphan-observe", "unknown-audit":
				action := map[string]string{"orphan-reserve": "app.memcached.update.reserve", "orphan-observe": "app.memcached.update.observe", "unknown-audit": "app.memcached.update.unrecognized"}[scenario]
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, actor.ID, action, strings.Repeat("5", 32), strings.Repeat("6", 64), Now())
			case "unrelated-corrupt-reservation":
				other := seed
				other.Dispatch.RequestID, other.Dispatch.JobID, other.Dispatch.ProjectID = ID(), ID(), ID()
				other.DispatchSHA256 = MemcachedUpdateDispatchSHA(other.Dispatch)
				other.Plan.ProjectID = other.Dispatch.ProjectID
				other.Plan.ProjectSHA256, err = memcachedPlanIdentity(other.Plan)
				other.Dispatch.Input.ExpectedProjectSHA256 = other.Plan.ProjectSHA256
				other.DispatchSHA256 = MemcachedUpdateDispatchSHA(other.Dispatch)
				other, err = SealMemcachedUpdateRecord(other)
				if err == nil {
					_, _, err = s.reserveMemcachedUpdate(context.Background(), actor.ID, other)
				}
				if err == nil {
					_, err = s.DB.Exec(`UPDATE memcached_update_requests SET chain='null',state='prepared' WHERE request_id=?`, other.Dispatch.RequestID)
				}
			}
			if err != nil {
				t.Fatal("isolated negative fixture", err)
			}
			counts := memcachedStoreCounts(t, s)
			reader, ctx := s, context.Background()
			if scenario == "nil-context" {
				ctx = nil
			} else if scenario == "nil-store" {
				reader = nil
			} else if scenario == "nil-database" {
				reader = &Store{}
			}
			if reader.CheckMemcachedUpdateMutation(ctx, seed) == nil || memcachedStoreCounts(t, s) != counts {
				t.Fatal("stale or globally ambiguous native authority admitted or repaired")
			}
			if scenario == "missing-index" {
				var count int
				if s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='one_active_memcached_update_project'`).Scan(&count) != nil || count != 0 {
					t.Fatal("native readonly check recreated a missing fence")
				}
			}
		})
	}
}

func TestMemcachedStoreReadOnlyNativeDatabaseGuardDoesNotRunMigrationsOrWrites(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	memcachedStoreReserve(t, s, actor, seed)
	var seq int
	var name, filename string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &filename); err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "file", Path: filename, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	reader := &Store{DB: db}
	before := memcachedStoreCounts(t, s)
	if err := reader.CheckMemcachedUpdateMutation(context.Background(), seed); err != nil {
		t.Fatal("genuine read-only connection refused", err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'[]',2)`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := reader.CheckMemcachedUpdateMutation(context.Background(), seed); err == nil || memcachedStoreCounts(t, s) != before {
		t.Fatal("read-only native guard ignored new revocation or wrote state")
	}
}

func TestMemcachedStoreUnknownAndPartialPollNeverReleaseProjectOrPrematurelyAdvanceReceipt(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	ctx := context.Background()
	memcachedStoreReserve(t, s, actor, seed)
	oldReceipt := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
	if err := s.markMemcachedUpdateUnknown(ctx, actor.ID, seed.Dispatch.RequestID); err != nil {
		t.Fatal(err)
	}
	unknown, found, err := s.memcachedUpdateForActor(ctx, actor.ID, seed.Dispatch.RequestID)
	if err != nil || !found || unknown.State != "unknown" || len(unknown.Chain) != 0 {
		t.Fatal("timeout became absence or failure", err)
	}
	chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
	partial, err := s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, chain[:5])
	if err != nil || partial.State != "applied" || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != oldReceipt {
		t.Fatal("partial health/application phase advanced the app receipt", err)
	}
	counts := memcachedStoreCounts(t, s)
	stale, err := s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, chain[:2])
	if err != nil || !reflect.DeepEqual(stale, partial) || memcachedStoreCounts(t, s) != counts {
		t.Fatal("stale observation regressed or duplicated evidence", err)
	}
	if err := s.markMemcachedUpdateUnknown(ctx, actor.ID, seed.Dispatch.RequestID); err != nil {
		t.Fatal(err)
	}
	afterUnknown, _, _ := s.memcachedUpdateForActor(ctx, actor.ID, seed.Dispatch.RequestID)
	if !reflect.DeepEqual(afterUnknown, partial) {
		t.Fatal("later network failure erased previous actual observation")
	}
	complete, err := s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, chain)
	if err != nil || complete.State != "committed" {
		t.Fatal("complete original chain did not reconcile", err)
	}
	receipt := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
	if receipt[0] != seed.Dispatch.Input.ExpectedVersion || receipt[1] != seed.Dispatch.Input.ExpectedSHA256 || receipt[2] != "memcached-cache" || memcachedStoreCounts(t, s) != [5]int{1, 7, 1, 0, 0} {
		t.Fatal("committed receipt/audit not bound exactly once")
	}
	if err := s.CheckMemcachedUpdateMutation(ctx, seed); err == nil {
		t.Fatal("completed command was authorized for another effect")
	}
	counts = memcachedStoreCounts(t, s)
	_, err = s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, chain)
	if err != nil || memcachedStoreCounts(t, s) != counts || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != receipt {
		t.Fatal("repeated completed observation rewrote receipt or audits", err)
	}
	chain[0].RecordSHA256 = strings.Repeat("0", 64)
	retained, _, _ := s.memcachedUpdateForActor(ctx, actor.ID, seed.Dispatch.RequestID)
	if retained.Chain[0] != seed {
		t.Fatal("stored evidence shared a caller-owned chain buffer")
	}
}

func TestMemcachedStoreFailureRollbackAndAttentionPreserveOldVersion(t *testing.T) {
	for _, outcome := range []string{"failed_safe", "rolled_back", "needs_attention"} {
		t.Run(outcome, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			old := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			var chain []MemcachedUpdateRecord
			switch outcome {
			case "failed_safe":
				chain = memcachedStoreChain(t, seed, "pull_started", "failed_safe")
			case "rolled_back":
				chain = memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "rollback_started", "rolled_back")
			case "needs_attention":
				chain = memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "needs_attention")
			}
			row, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain)
			if err != nil || row.State != outcome || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != old || s.CheckMemcachedUpdateMutation(context.Background(), seed) == nil {
				t.Fatal("failure/rollback/unknown changed installed version or granted replay", err)
			}
			if outcome == "needs_attention" {
				changed := seed
				changed.Dispatch.JobID, changed.Dispatch.RequestID = ID(), ID()
				changed.DispatchSHA256 = MemcachedUpdateDispatchSHA(changed.Dispatch)
				changed, _ = SealMemcachedUpdateRecord(changed)
				if _, _, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, changed); err == nil {
					t.Fatal("new key bypassed original unknown outcome")
				}
			}
		})
	}
}

func TestMemcachedStoreOriginalChainCannotForkSkipOrFabricateHealthyCommit(t *testing.T) {
	for _, scenario := range []string{"missing-seed", "gap", "unhealthy", "fork-known-prefix", "different-actor", "wrong-rollback-image"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
			switch scenario {
			case "missing-seed":
				chain = chain[1:]
			case "gap":
				chain = []MemcachedUpdateRecord{chain[0], chain[5]}
			case "unhealthy":
				chain[5].Observation.Health = "unhealthy"
				chain[5].RecordSHA256 = memcachedRecordSHA(chain[5])
			case "fork-known-prefix":
				if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain[:5]); err != nil {
					t.Fatal(err)
				}
				chain[4].Observation.ContainerID = strings.Repeat("f", 64)
				chain[4], _ = SealMemcachedUpdateRecord(chain[4])
				chain[5] = memcachedTransactionNext(t, chain[4], "committed")
			case "different-actor":
				chain[0].Dispatch.ActorID = ID()
				chain[0].DispatchSHA256 = MemcachedUpdateDispatchSHA(chain[0].Dispatch)
				chain[0], _ = SealMemcachedUpdateRecord(chain[0])
			case "wrong-rollback-image":
				chain = memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "rollback_started", "rolled_back")
				chain[5].Observation.ImageID = chain[5].TargetImageID
				chain[5].RecordSHA256 = memcachedRecordSHA(chain[5])
			}
			before := memcachedStoreCounts(t, s)
			old := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain); err == nil || memcachedStoreCounts(t, s) != before || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != old {
				t.Fatal("unbound/forked chain rewrote original audit or version")
			}
		})
	}
}

func TestMemcachedStoreConflictingReceiptRollsBackEntireReconciliation(t *testing.T) {
	for _, scenario := range []string{"same-version-other-sha", "future-version", "malformed-version", "different-target", "malformed-sha"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			var err error
			switch scenario {
			case "same-version-other-sha":
				_, err = s.DB.Exec(`UPDATE app_registry_receipts SET version=? WHERE app_id='memcached'`, seed.Dispatch.Input.ExpectedVersion)
			case "future-version":
				_, err = s.DB.Exec(`UPDATE app_registry_receipts SET version='1.6.45-compat3' WHERE app_id='memcached'`)
			case "malformed-version":
				_, err = s.DB.Exec(`UPDATE app_registry_receipts SET version='unverifiable' WHERE app_id='memcached'`)
			case "different-target":
				_, err = s.DB.Exec(`UPDATE app_registry_receipts SET target='mongodb' WHERE app_id='memcached'`)
			case "malformed-sha":
				_, err = s.DB.Exec(`UPDATE app_registry_receipts SET sha256='unknown' WHERE app_id='memcached'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			counts, old := memcachedStoreCounts(t, s), memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
			if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain); err == nil || memcachedStoreCounts(t, s) != counts || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != old {
				t.Fatal("conflicting receipt partially updated request/audits/version")
			}
		})
	}
}

func TestMemcachedStoreReservationAndObservationRacesHaveOneWinner(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	var wg sync.WaitGroup
	fresh := make(chan bool, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			_, created, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed)
			fresh <- created
			errs <- err
		})
	}
	wg.Wait()
	close(fresh)
	close(errs)
	winners := 0
	for made := range fresh {
		if made {
			winners++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 || memcachedStoreCounts(t, s) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("concurrent requests had more than one dispatch winner", winners)
	}
	chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
	errs = make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if memcachedStoreCounts(t, s) != [5]int{1, 7, 1, 0, 0} {
		t.Fatal("parallel observations duplicated original progress or receipt")
	}
}

func TestMemcachedStoreSchemaPairIsExactAndNeverRepairsPartialOrAlteredState(t *testing.T) {
	for _, scenario := range []string{"idempotent", "missing-index", "different-index"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			if scenario != "idempotent" {
				if _, err := s.DB.Exec(`DROP INDEX one_active_memcached_update_project`); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "different-index" {
				if _, err := s.DB.Exec(`CREATE INDEX one_active_memcached_update_project ON memcached_update_requests(project_id)`); err != nil {
					t.Fatal(err)
				}
			}
			before := memcachedStoreCounts(t, s)
			err := s.migrateMemcachedUpdates()
			if (err == nil) != (scenario == "idempotent") || memcachedStoreCounts(t, s) != before {
				t.Fatal("schema accepted/repaired partial or altered existing identity", err)
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='one_active_memcached_update_project'`).Scan(&count) != nil || scenario == "missing-index" && count != 0 {
				t.Fatal("missing index was silently recreated")
			}
		})
	}
}

func TestMemcachedStoreMalformedOriginalRowsAndAuditNeverBecomeFreshRequests(t *testing.T) {
	for _, scenario := range []string{"actor-column", "dispatch-column", "empty-chain-phase", "bad-chain", "old-time", "missing-reserve-audit", "duplicate-reserve-audit", "wrong-reserve-audit", "unexpected-observation-audit"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			var err error
			switch scenario {
			case "actor-column":
				_, err = s.DB.Exec(`UPDATE memcached_update_requests SET actor_id=?`, ID())
			case "dispatch-column":
				_, err = s.DB.Exec(`UPDATE memcached_update_requests SET dispatch_sha256=?`, strings.Repeat("a", 64))
			case "empty-chain-phase":
				_, err = s.DB.Exec(`UPDATE memcached_update_requests SET state='prepared'`)
			case "bad-chain":
				_, err = s.DB.Exec(`UPDATE memcached_update_requests SET chain='null',state='prepared'`)
			case "old-time":
				_, err = s.DB.Exec(`UPDATE memcached_update_requests SET updated_at='2025-01-01T00:00:00Z'`)
			case "missing-reserve-audit":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE action='app.memcached.update.reserve'`)
			case "duplicate-reserve-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='app.memcached.update.reserve'`)
			case "wrong-reserve-audit":
				_, err = s.DB.Exec(`UPDATE audit_logs SET result='wrong' WHERE action='app.memcached.update.reserve'`)
			case "unexpected-observation-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.update.observe',?,'wrong',?)`, actor.ID, seed.Dispatch.JobID+":0", Now())
			}
			if err != nil {
				t.Fatal(err)
			}
			before := memcachedStoreCounts(t, s)
			if s.CheckMemcachedUpdateMutation(context.Background(), seed) == nil {
				t.Fatal("malformed original authorized native mutation")
			}
			if _, _, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, seed); err == nil || memcachedStoreCounts(t, s) != before {
				t.Fatal("malformed original became a fresh/rewritten request")
			}
		})
	}
}

func TestMemcachedStoreCapacityRetainsEveryOriginalWithoutPruning(t *testing.T) {
	s, actor, template := memcachedStoreFixture(t)
	_, legacy, _ := memcachedPlanFixture(t)
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 1; i <= memcachedUpdateRequestLimit; i++ {
		seed := template
		seed.Dispatch.JobID = fmt.Sprintf("%032x", i)
		seed.Dispatch.RequestID = fmt.Sprintf("%032x", i+1000)
		seed.Dispatch.ProjectID = fmt.Sprintf("%032x", i+2000)
		seed.Plan, err = MemcachedComposeUpdatePlan(seed.Dispatch.ProjectID, template.Plan.MetadataSHA256, legacy, template.Plan.HostPort, template.Plan.ContainerID, template.Plan.RuntimeImageID, template.Plan.RuntimeConfigSHA256)
		if err != nil {
			t.Fatal(err)
		}
		seed.Dispatch.Input.ExpectedProjectSHA256 = seed.Plan.ProjectSHA256
		seed.DispatchSHA256 = MemcachedUpdateDispatchSHA(seed.Dispatch)
		seed, err = SealMemcachedUpdateRecord(seed)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(seed)
		if _, err := tx.Exec(`INSERT INTO memcached_update_requests VALUES(?,?,?,?,?,?,'','reserved',?,?)`, seed.Dispatch.RequestID, seed.Dispatch.JobID, actor.ID, seed.Dispatch.ProjectID, seed.DispatchSHA256, string(raw), Now(), Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.update.reserve',?,?,?)`, actor.ID, seed.Dispatch.JobID, seed.RecordSHA256, Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before := memcachedStoreCounts(t, s)
	if before[0] != 128 || before[1] != 128 {
		t.Fatal("isolated capacity fixture not complete", before)
	}
	reader, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inventory, inventoryErr := memcachedUpdateInventory(context.Background(), reader)
	reader.Rollback()
	if inventoryErr != nil || len(inventory) != 128 {
		t.Fatal("entire capacity fixture must first independently validate", inventoryErr)
	}
	if _, _, err := s.reserveMemcachedUpdate(context.Background(), actor.ID, template); err == nil || !strings.Contains(err.Error(), "128") || memcachedStoreCounts(t, s) != before {
		t.Fatal("capacity silently discarded/reused retained identities")
	}
}

func TestMemcachedStoreEmptySQLProjectionDoesNotAcceptActualNullLengthOrOversizeBytes(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	memcachedStoreReserve(t, s, actor, seed)
	query := "SELECT " + strings.Replace(memcachedUpdateColumns, "length(CAST(chain AS BLOB))", "NULL", 1) + " FROM memcached_update_requests WHERE request_id=?"
	if _, err := scanMemcachedUpdateReservation(s.DB.QueryRow(query, seed.Dispatch.RequestID)); err == nil {
		t.Fatal("coalesced empty projection concealed an actually NULL source length")
	}
	if _, err := s.DB.Exec(`UPDATE memcached_update_requests SET chain=?`, strings.Repeat("界", 100000)); err != nil {
		t.Fatal("synthetic character-count-valid but byte-over-budget row", err)
	}
	if _, _, err := s.memcachedUpdateForActor(context.Background(), actor.ID, seed.Dispatch.RequestID); err == nil {
		t.Fatal("SQLite character length bypassed strict byte budget")
	}
}
