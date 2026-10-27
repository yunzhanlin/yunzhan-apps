package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Isolated real SQLite/role/receipt fixtures; no HTTP, systemd, account or Nginx.
func streamControlFixture(t *testing.T) (*Store, identity, loadbalancestream.Operation) {
	t.Helper()
	s := testStore(t)
	if err := s.migrateLoadBalanceStreamControls(); err != nil {
		t.Fatal(err)
	}
	actor := accessUser(t, s, "stream-control-owner", "admin", nil)
	if _, err := s.DB.Exec("INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('load-balance','load-balance',?,?,'load-balance',?)", loadBalanceStreamControlVersion, strings.Repeat("1", 64), Now()); err != nil {
		t.Fatal(err)
	}
	op := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: ID(), ActorID: actor.ID, Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "sql.lb.invalid", Policy: &loadbalancestream.Policy{Protocol: "tcp", Port: 42000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41002", Weight: 3}}, Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64}}}
	if _, err := loadbalancestream.OperationBytes(op); err != nil {
		t.Fatal(err)
	}
	return s, actor, op
}

func streamControlCounts(t *testing.T, s *Store) [3]int {
	t.Helper()
	var out [3]int
	if err := s.DB.QueryRow("SELECT(SELECT count(*)FROM load_balance_stream_controls),(SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.control'),(SELECT count(*)FROM runtime_jobs)").Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}

func streamControlReserve(t *testing.T, s *Store, op loadbalancestream.Operation) loadBalanceStreamControlRow {
	t.Helper()
	row, fresh, err := s.reserveLoadBalanceStreamControl(context.Background(), op)
	if err != nil || !fresh || row.State != "reserved" || row.AccessRevision != 1 {
		t.Fatal("original reservation", row, fresh, err)
	}
	return row
}

func streamControlModelChain(t *testing.T, s *Store, op loadbalancestream.Operation) ([]byte, [][]byte) {
	t.Helper()
	validation := loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: 64 << 20}
	facts := loadbalancestream.ServiceFacts{Validation: validation, AvailableMemoryBytes: 4 << 30, HardOpenFiles: loadbalancestream.RuntimeOpenFiles, UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: 991, AccountGID: 991, AccountRecordSHA256: strings.Repeat("a", 64), NginxVersion: "1.30.6", NginxSHA256: strings.Repeat("b", 64)}
	before, err := loadbalancestream.RenderRuntime([]loadbalancestream.Entry{}, loadbalancestream.ServiceRuntimePrefix, validation)
	if err != nil {
		t.Fatal(err)
	}
	binding := loadbalancestream.OperationBinding{Format: 1, AppID: "load-balance", AppVersion: loadBalanceStreamControlVersion, OperationSHA256: loadbalancestream.OperationSHA256(op), ManifestSHA256: strings.Repeat("1", 64), InstalledSHA256: strings.Repeat("2", 64), ProgrammeInputs: strings.Repeat("3", 64), ActorObservationSHA: strings.Repeat("4", 64), OriginalConfigSHA256: before.SHA256}
	row, found, err := readStreamControl(context.Background(), s.DB, op.RequestID)
	if err != nil || !found {
		t.Fatal("model lacks real original reservation", err)
	}
	binding.OriginalRequestSHA256, err = streamControlOriginalRequestSHA(context.Background(), s.DB, row)
	if err != nil {
		t.Fatal(err)
	}
	access, err := readUserAccessContext(context.Background(), s.DB, op.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	actorRaw, _ := json.Marshal(struct {
		ActorID string     `json:"actor_id"`
		Access  UserAccess `json:"access"`
	}{op.ActorID, access})
	binding.ActorObservationSHA = Hash(string(actorRaw))
	seed, _, err := loadbalancestream.PrepareControlSeed(op, binding, []loadbalancestream.Entry{}, 43000, strings.Repeat("6", 64), facts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := loadbalancestream.ControlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for i := 0; i < 12; i++ {
		e := loadbalancestream.ControlAdvanceEvidence{}
		if i == 2 {
			e.AccountReceiptSHA256 = strings.Repeat("7", 64)
		}
		if i == 10 {
			e.ServiceObservationSHA = strings.Repeat("8", 64)
		}
		next, err := loadbalancestream.NextControlEvent(raw, records, e)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, next)
	}
	return raw, records
}

func TestLoadBalanceStreamControlActualSQLReservationAndSingleIssuedCAS(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	original := streamControlReserve(t, s, op)
	counts := streamControlCounts(t, s)
	if counts[0] != 1 || counts[1] != 1 {
		t.Fatal("missing original request/audit", counts)
	}
	if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
		t.Fatal("undispatched reservation became native authority")
	}
	for range 3 {
		row, fresh, err := s.reserveLoadBalanceStreamControl(ctx, op)
		if err != nil || fresh || !reflect.DeepEqual(row, original) || streamControlCounts(t, s) != counts {
			t.Fatal("retry changed original", fresh, err)
		}
	}
	fresh, err := s.issueLoadBalanceStreamControl(ctx, op)
	if err != nil || !fresh || s.CheckLoadBalanceStreamControl(ctx, op) != nil {
		t.Fatal("original issue", fresh, err)
	}
	for range 3 {
		fresh, err = s.issueLoadBalanceStreamControl(ctx, op)
		if err != nil || fresh {
			t.Fatal("issued request dispatched again", fresh, err)
		}
	}
	row, found, err := s.loadBalanceStreamControlForActor(ctx, actor.ID, op.RequestID)
	if err != nil || !found || row.State != "issued" || streamControlCounts(t, s) != counts {
		t.Fatal("read changed original", row, found, err)
	}
	other := op
	other.RequestID = ID()
	if _, _, err = s.reserveLoadBalanceStreamControl(ctx, other); err == nil {
		t.Fatal("new key bypassed original host fence")
	}
}

func TestLoadBalanceStreamControlUnknownIsTerminalNeverReissuedOrPromoted(t *testing.T) {
	s, _, op := streamControlFixture(t)
	ctx := context.Background()
	streamControlReserve(t, s, op)
	if s.markLoadBalanceStreamControlUnknown(ctx, op) == nil {
		t.Fatal("unissued request pretended to have a transport outcome")
	}
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.markLoadBalanceStreamControlUnknown(ctx, op); err != nil {
			t.Fatal(err)
		}
	}
	if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
		t.Fatal("unknown became native effect permission")
	}
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || fresh {
		t.Fatal("unknown redispatched", err)
	}
	seed, records := streamControlModelChain(t, s, op)
	if s.finishLoadBalanceStreamControl(ctx, op, seed, records) == nil {
		t.Fatal("unknown original retroactively changed into success")
	}
	row, fresh, err := s.reserveLoadBalanceStreamControl(ctx, op)
	if err != nil || fresh || row.State != "unknown" || row.Result != nil {
		t.Fatal("original unknown erased", row, err)
	}
	other := op
	other.RequestID = ID()
	if _, _, err = s.reserveLoadBalanceStreamControl(ctx, other); err == nil {
		t.Fatal("unknown lost original host fence")
	}
}

func TestLoadBalanceStreamControlCompleteExactOriginalChainOnly(t *testing.T) {
	for _, fault := range []string{"partial", "missing-seed", "foreign-request", "forked-manifest", "missing-observation", "duplicate-phase", "foreign-version", "trailing-seed", "duplicate-seed-field", "valid"} {
		t.Run(fault, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
				t.Fatal(err)
			}
			seed, records := streamControlModelChain(t, s, op)
			changed := op
			switch fault {
			case "partial":
				records = records[:11]
			case "missing-seed":
				seed = nil
			case "foreign-request":
				changed.RequestID = ID()
			case "forked-manifest":
				seed = []byte(strings.Replace(string(seed), strings.Repeat("1", 64), strings.Repeat("9", 64), 1))
			case "missing-observation":
				records[10] = []byte(strings.Replace(string(records[10]), strings.Repeat("8", 64), "", 1))
			case "duplicate-phase":
				records[11] = records[10]
			case "foreign-version":
				seed = []byte(strings.Replace(string(seed), `"app_version":"`+loadBalanceStreamControlVersion+`"`, `"app_version":"1.8.5"`, 1))
			case "trailing-seed":
				seed = append(seed, '\n')
			case "duplicate-seed-field":
				seed = append([]byte("{\"format\":1,"), seed[1:]...)
			}
			before := streamControlCounts(t, s)
			err := s.finishLoadBalanceStreamControl(ctx, changed, seed, records)
			if fault != "valid" {
				if err == nil {
					t.Fatal("invalid result committed", fault)
				}
				row, found, e := readStreamControl(ctx, s.DB, op.RequestID)
				if e != nil || !found || row.State != "issued" || row.Result != nil || streamControlCounts(t, s) != before {
					t.Fatal("failed validation changed original", e)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			row, found, err := readStreamControl(ctx, s.DB, op.RequestID)
			if err != nil || !found || row.State != "completed" || row.Result == nil || row.Result.State != "committed" {
				t.Fatal(row, err)
			}
			if err = s.finishLoadBalanceStreamControl(ctx, op, seed, records); err != nil {
				t.Fatal("same exact original outcome not readable", err)
			}
			if s.markLoadBalanceStreamControlUnknown(ctx, op) == nil || s.CheckLoadBalanceStreamControl(ctx, op) == nil {
				t.Fatal("completed result became unfinished authority")
			}
			if fresh, e := s.issueLoadBalanceStreamControl(ctx, op); e != nil || fresh {
				t.Fatal("completed request reissued", e)
			}
			other := op
			other.RequestID = ID()
			if _, fresh, e := s.reserveLoadBalanceStreamControl(ctx, other); e != nil || !fresh {
				t.Fatal("true completed host remained fenced", e)
			}
		})
	}
}

func TestLoadBalanceStreamControlFreshGrantsAndExactModuleBinding(t *testing.T) {
	for _, fault := range []string{"viewer", "operator", "limited-admin", "site-scoped-admin", "deleted-owner", "revoked-menus", "restored-revision", "malformed-menus", "duplicate-menus", "changed-manifest", "old-version", "pending-update", "deleted-receipt"} {
		t.Run(fault, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
				t.Fatal(err)
			}
			var err error
			switch fault {
			case "viewer", "operator":
				_, err = s.DB.Exec("UPDATE app_user_roles SET role=? WHERE user_id=?", fault, actor.ID)
			case "limited-admin":
				_, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[\"system-tools\"]',2)", actor.ID)
			case "site-scoped-admin":
				_, err = s.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id=?", `["`+strings.Repeat("7", 32)+`"]`, actor.ID)
			case "deleted-owner":
				_, err = s.DB.Exec("DELETE FROM users WHERE id=?", actor.ID)
			case "revoked-menus":
				_, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", actor.ID)
			case "restored-revision":
				menus, _ := normalizeMenuIDs("admin", nil)
				raw, _ := json.Marshal(menus)
				_, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,?,3)", actor.ID, string(raw))
			case "malformed-menus":
				_, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'{',2)", actor.ID)
			case "duplicate-menus":
				_, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[\"system-tools\",\"system-tools\"]',2)", actor.ID)
			case "changed-manifest":
				_, err = s.DB.Exec("UPDATE app_registry_receipts SET sha256=? WHERE app_id='load-balance'", strings.Repeat("9", 64))
			case "old-version":
				_, err = s.DB.Exec("UPDATE app_registry_receipts SET version='1.8.4' WHERE app_id='load-balance'")
			case "pending-update":
				_, err = s.DB.Exec("INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at)VALUES(?,'load-balance','load-balance',?,?,'load-balance','panel-module',?)", ID(), loadBalanceStreamControlVersion, strings.Repeat("1", 64), Now())
			case "deleted-receipt":
				_, err = s.DB.Exec("DELETE FROM app_registry_receipts WHERE app_id='load-balance'")
			}
			if err != nil {
				t.Fatal(err)
			}
			before := streamControlCounts(t, s)
			if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
				t.Fatal("stale grant/module authorized native control", fault)
			}
			if _, _, err = s.reserveLoadBalanceStreamControl(ctx, op); err == nil {
				t.Fatal("stale original reacquired eligibility", fault)
			}
			if fault == "restored-revision" {
				row, found, e := s.loadBalanceStreamControlForActor(ctx, actor.ID, op.RequestID)
				if e != nil || !found || row.State != "issued" {
					t.Fatal("read-only history should remain", e)
				}
			}
			if streamControlCounts(t, s) != before {
				t.Fatal("authority observation changed original")
			}
		})
	}
}

func TestLoadBalanceStreamControlMalformedOriginalAndSchemaNeverRepaired(t *testing.T) {
	for _, fault := range []string{"missing-index", "foreign-trigger", "missing-table", "forked-actor", "changed-operation", "future-clock", "invalid-result", "noncanonical-result", "wrong-scope"} {
		t.Run(fault, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
				t.Fatal(err)
			}
			var err error
			switch fault {
			case "missing-index":
				_, err = s.DB.Exec("DROP INDEX one_active_load_balance_stream_control")
			case "foreign-trigger":
				_, err = s.DB.Exec("CREATE TRIGGER foreign_stream AFTER UPDATE ON load_balance_stream_controls BEGIN SELECT 1; END")
			case "missing-table":
				_, err = s.DB.Exec("DROP TABLE load_balance_stream_controls")
			case "forked-actor":
				_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET actor_id=?", ID())
			case "changed-operation":
				_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET operation=operation||' '")
			case "future-clock":
				_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET updated_at=?", time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
			case "invalid-result":
				_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result='{}'")
			case "noncanonical-result":
				_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result='null'")
			case "wrong-scope":
				_, err = s.DB.Exec("PRAGMA ignore_check_constraints=ON")
				if err == nil {
					_, err = s.DB.Exec("UPDATE load_balance_stream_controls SET scope='foreign'")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
				t.Fatal("malformed current authority accepted", fault)
			}
			if fault == "missing-index" || fault == "foreign-trigger" || fault == "missing-table" {
				if s.migrateLoadBalanceStreamControls() == nil {
					t.Fatal("partial/activated namespace repaired", fault)
				}
			}
		})
	}
}

func TestLoadBalanceStreamControlOtherActorAndCancelledCannotMutate(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	streamControlReserve(t, s, op)
	other := accessUser(t, s, "other-stream-admin", "admin", nil)
	before := streamControlCounts(t, s)
	if _, _, err := s.loadBalanceStreamControlForActor(ctx, other.ID, op.RequestID); err == nil {
		t.Fatal("other current admin adopted original private request")
	}
	changed := op
	changed.ActorID = other.ID
	if _, _, err := s.reserveLoadBalanceStreamControl(ctx, changed); err == nil {
		t.Fatal("other actor rebound original key")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	seed, records := streamControlModelChain(t, s, op)
	for _, c := range []context.Context{nil, cancelled} {
		if _, _, err := s.reserveLoadBalanceStreamControl(c, op); err == nil {
			t.Fatal("invalid reservation context")
		}
		if fresh, err := s.issueLoadBalanceStreamControl(c, op); err == nil || fresh {
			t.Fatal("invalid issue context")
		}
		if s.markLoadBalanceStreamControlUnknown(c, op) == nil || s.finishLoadBalanceStreamControl(c, op, seed, records) == nil || s.CheckLoadBalanceStreamControl(c, op) == nil {
			t.Fatal("invalid context accepted")
		}
		if _, _, err := s.loadBalanceStreamControlForActor(c, actor.ID, op.RequestID); err == nil {
			t.Fatal("invalid read context")
		}
	}
	if streamControlCounts(t, s) != before {
		t.Fatal("invalid/other actor actions wrote")
	}
}

func TestLoadBalanceStreamControlConcurrentIssueHasOneFreshWinner(t *testing.T) {
	s, _, op := streamControlFixture(t)
	streamControlReserve(t, s, op)
	s.DB.SetMaxOpenConns(1)
	var wg sync.WaitGroup
	results := make(chan bool, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op)
			results <- fresh
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	winners := 0
	for v := range results {
		if v {
			winners++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent duplicate dispatch eligibility", winners)
	}
}

func TestLoadBalanceStreamControlUpgradeNeverDropsUnissuedRevokedOrUnknown(t *testing.T) {
	for _, phase := range []string{"reserved", "issued", "unknown", "revoked", "completed"} {
		t.Run(phase, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			if s.CheckLoadBalanceStreamControlUpgrade(ctx) != nil {
				t.Fatal("new empty valid store refused")
			}
			streamControlReserve(t, s, op)
			if phase != "reserved" {
				if fresh, e := s.issueLoadBalanceStreamControl(ctx, op); e != nil || !fresh {
					t.Fatal(e)
				}
			}
			if phase == "unknown" {
				if e := s.markLoadBalanceStreamControlUnknown(ctx, op); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "revoked" {
				if _, e := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "completed" {
				seed, records := streamControlModelChain(t, s, op)
				if e := s.finishLoadBalanceStreamControl(ctx, op, seed, records); e != nil {
					t.Fatal(e)
				}
			}
			if got := s.CheckLoadBalanceStreamControlUpgrade(ctx); (got == nil) != (phase == "completed") {
				t.Fatal("upgrade lost unfinished or malformed original", phase, got)
			}
		})
	}
	for _, kind := range []string{"unactivated-old-schema", "prior-audit", "activated-receipt"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			// Store.Open now creates the independent empty schema. Explicitly
			// construct the OLD missing-schema fixture before adding history;
			// the SELECT-only guard must still never recreate it.
			if _, err := s.DB.Exec("DROP TABLE load_balance_stream_controls"); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if kind == "prior-audit" {
				if _, e := s.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.control',?,?,?)", ID(), ID(), strings.Repeat("1", 64), Now()); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "activated-receipt" {
				if _, e := s.DB.Exec("INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('load-balance','load-balance',?,?,'load-balance',?)", loadBalanceStreamControlVersion, strings.Repeat("1", 64), Now()); e != nil {
					t.Fatal(e)
				}
			}
			if got := s.CheckLoadBalanceStreamControlUpgrade(ctx); (got == nil) != (kind == "unactivated-old-schema") {
				t.Fatal("old/missing schema ambiguity accepted", kind, got)
			}
			var count int
			if e := s.DB.QueryRow("SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_controls'").Scan(&count); e != nil || count != 0 {
				t.Fatal("read-only guard created or repaired schema", count, e)
			}
			if kind != "unactivated-old-schema" && s.migrateLoadBalanceStreamControls() == nil {
				t.Fatal("uncertain activated namespace recreated")
			}
		})
	}
}

func TestLoadBalanceStreamControlCompleteCapacityCensusInspectsLastRowAndNeverTruncates(t *testing.T) {
	s, _, op := streamControlFixture(t)
	ctx := context.Background()
	s.DB.SetMaxOpenConns(1)
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare("INSERT INTO load_balance_stream_controls(request_id,actor_id,access_revision,operation,operation_sha256,manifest_sha256,state,result,created_at,updated_at)VALUES(?,?,1,?,?,?,'completed',?,?,?)")
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var last string
	stamp := Now()
	for i := 1; i <= loadBalanceStreamControlLimit; i++ {
		v := op
		v.RequestID = fmt.Sprintf("%032x", i)
		raw, e := loadbalancestream.OperationBytes(v)
		if e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		result := loadBalanceStreamControlResult{Format: 1, RequestID: v.RequestID, OperationSHA256: loadbalancestream.OperationSHA256(v), State: "refused-before-issue"}
		b, _ := json.Marshal(result)
		if _, e = statement.Exec(v.RequestID, v.ActorID, string(raw), result.OperationSHA256, strings.Repeat("1", 64), string(b), stamp, stamp); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		last = v.RequestID
	}
	statement.Close()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = s.CheckLoadBalanceStreamControlUpgrade(ctx); err != nil {
		t.Fatal("complete4096-row census", err)
	}
	t.Log("ordinary local capacity observation, not native whole-guard acceptance", time.Since(started))
	if _, fresh, e := s.reserveLoadBalanceStreamControl(ctx, op); e == nil || fresh {
		t.Fatal("full history capacity silently exceeded")
	}
	var original string
	if e := s.DB.QueryRow("SELECT result FROM load_balance_stream_controls WHERE request_id=?", last).Scan(&original); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("UPDATE load_balance_stream_controls SET state='unknown',result='' WHERE request_id=?", last); e != nil {
		t.Fatal(e)
	}
	if s.CheckLoadBalanceStreamControlUpgrade(ctx) == nil {
		t.Fatal("complete census skipped the final original unknown")
	}
	if _, e := s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result=? WHERE request_id=?", original, last); e != nil {
		t.Fatal(e)
	}
	v := op
	v.RequestID = fmt.Sprintf("%032x", loadBalanceStreamControlLimit+1)
	raw, _ := loadbalancestream.OperationBytes(v)
	result := loadBalanceStreamControlResult{Format: 1, RequestID: v.RequestID, OperationSHA256: loadbalancestream.OperationSHA256(v), State: "refused-before-issue"}
	b, _ := json.Marshal(result)
	if _, e := s.DB.Exec("INSERT INTO load_balance_stream_controls(request_id,actor_id,access_revision,operation,operation_sha256,manifest_sha256,state,result,created_at,updated_at)VALUES(?,?,1,?,?,?,'completed',?,?,?)", v.RequestID, v.ActorID, string(raw), result.OperationSHA256, strings.Repeat("1", 64), string(b), stamp, stamp); e != nil {
		t.Fatal(e)
	}
	if s.CheckLoadBalanceStreamControlUpgrade(ctx) == nil {
		t.Fatal("4097 records accepted by truncating history")
	}
}

func TestLoadBalanceStreamControlOnlyOriginalUnissuedOwnerCanExplicitlyCancel(t *testing.T) {
	for _, phase := range []string{"reserved", "issued", "unknown", "committed", "other-owner", "viewer", "restored-owner"} {
		t.Run(phase, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			who := actor.ID
			if phase == "issued" || phase == "unknown" || phase == "committed" {
				if fresh, e := s.issueLoadBalanceStreamControl(ctx, op); e != nil || !fresh {
					t.Fatal(e)
				}
			}
			if phase == "unknown" {
				if e := s.markLoadBalanceStreamControlUnknown(ctx, op); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "committed" {
				seed, records := streamControlModelChain(t, s, op)
				if e := s.finishLoadBalanceStreamControl(ctx, op, seed, records); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "other-owner" {
				who = accessUser(t, s, "cancel-other-admin", "admin", nil).ID
			}
			if phase == "viewer" {
				if _, e := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "restored-owner" {
				menus, _ := normalizeMenuIDs("admin", nil)
				raw, _ := json.Marshal(menus)
				if _, e := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,?,3)", actor.ID, string(raw)); e != nil {
					t.Fatal(e)
				}
			}
			before, found, e := readStreamControl(ctx, s.DB, op.RequestID)
			if e != nil || !found {
				t.Fatal(e)
			}
			fresh, err := s.cancelUndispatchedLoadBalanceStreamControl(ctx, who, op.RequestID)
			want := phase == "reserved" || phase == "restored-owner"
			if !want {
				if err == nil || fresh {
					t.Fatal("issued/foreign/unknown work canceled", phase)
				}
				after, found, e := readStreamControl(ctx, s.DB, op.RequestID)
				if e != nil || !found || !reflect.DeepEqual(before, after) {
					t.Fatal("refused cancellation changed original", phase, e)
				}
				return
			}
			if err != nil || !fresh {
				t.Fatal("explicit original unissued cancellation refused", err)
			}
			for range 3 {
				if again, e := s.cancelUndispatchedLoadBalanceStreamControl(ctx, who, op.RequestID); e != nil || again {
					t.Fatal("original cancellation replayed", e)
				}
			}
			row, found, e := readStreamControl(ctx, s.DB, op.RequestID)
			if e != nil || !found || row.State != "completed" || row.Result == nil || row.Result.State != "refused-before-issue" {
				t.Fatal(row, e)
			}
			var audits int
			if e := s.DB.QueryRow("SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.cancel-before-issue'AND target=?", op.RequestID).Scan(&audits); e != nil || audits != 1 {
				t.Fatal("cancellation audit missing or duplicated", audits, e)
			}
			if s.CheckLoadBalanceStreamControl(ctx, op) == nil || s.CheckLoadBalanceStreamControlUpgrade(ctx) != nil {
				t.Fatal("canceled unissued request became native authority or remained pending")
			}
		})
	}
}

func TestLoadBalanceStreamControlCancellationAndIssueRaceHasOneOriginalOutcome(t *testing.T) {
	for range 12 {
		s, actor, op := streamControlFixture(t)
		streamControlReserve(t, s, op)
		s.DB.SetMaxOpenConns(1)
		start := make(chan struct{})
		out := make(chan bool, 2)
		errs := make(chan error, 2)
		go func() {
			<-start
			fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op)
			out <- fresh
			errs <- err
		}()
		go func() {
			<-start
			fresh, err := s.cancelUndispatchedLoadBalanceStreamControl(context.Background(), actor.ID, op.RequestID)
			out <- fresh
			errs <- err
		}()
		close(start)
		winners := 0
		for range 2 {
			if <-out {
				winners++
			}
			<-errs
		}
		if winners != 1 {
			t.Fatal("cancel and issue both gained fresh authority", winners)
		}
		row, found, err := readStreamControl(context.Background(), s.DB, op.RequestID)
		if err != nil || !found || row.State != "issued" && row.State != "completed" {
			t.Fatal("race lost original", row, err)
		}
		if row.State == "completed" && (row.Result == nil || row.Result.State != "refused-before-issue") {
			t.Fatal("cancellation forged committed effect")
		}
	}
}

func TestLoadBalanceStreamControlReadOnlyAuthorityIsExactOriginalAndRevocationAware(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	streamControlReserve(t, s, op)
	if _, e := s.LoadBalanceStreamControlAuthority(ctx, op); e == nil {
		t.Fatal("unissued control gained authority data")
	}
	if fresh, e := s.issueLoadBalanceStreamControl(ctx, op); e != nil || !fresh {
		t.Fatal(e)
	}
	before := streamControlCounts(t, s)
	access, err := s.UserAccess(actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(struct {
		ActorID string     `json:"actor_id"`
		Access  UserAccess `json:"access"`
	}{actor.ID, access})
	value, err := s.LoadBalanceStreamControlAuthority(ctx, op)
	row, found, rowErr := readStreamControl(ctx, s.DB, op.RequestID)
	if rowErr != nil || !found {
		t.Fatal(rowErr)
	}
	originalSHA, rowErr := streamControlOriginalRequestSHA(ctx, s.DB, row)
	if rowErr != nil {
		t.Fatal(rowErr)
	}
	want := LoadBalanceStreamAuthority{OriginalRequestSHA256: originalSHA, Format: 1, RequestID: op.RequestID, ActorID: actor.ID, OperationSHA256: loadbalancestream.OperationSHA256(op), AppID: "load-balance", AppVersion: loadBalanceStreamControlVersion, ManifestSHA256: strings.Repeat("1", 64), AccessRevision: 1, ActorObservationSHA256: Hash(string(raw))}
	if err != nil || value != want {
		t.Fatal("actual original authority", value, err)
	}
	for range 3 {
		v, e := s.LoadBalanceStreamControlAuthority(ctx, op)
		if e != nil || v != want || streamControlCounts(t, s) != before {
			t.Fatal("read-only authority mutated or changed", e)
		}
	}
	foreign := op
	foreign.ActorID = accessUser(t, s, "authority-other-admin", "admin", nil).ID
	if _, e := s.LoadBalanceStreamControlAuthority(ctx, foreign); e == nil {
		t.Fatal("other administrator borrowed original")
	}
	if _, e := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.LoadBalanceStreamControlAuthority(ctx, op); e == nil {
		t.Fatal("old identity digest revived revoked live grant")
	}
}
