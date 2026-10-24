package core

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func memcachedUnixControlFixture(t *testing.T) (*Store, identity, MemcachedUnixControlOperation) {
	t.Helper()
	s, actor, original, item := memcachedUnixStoreFixture(t)
	if _, err := s.DB.Exec("INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('memcached',?,?,?,?,?)", original.ProjectID, item.Version, item.SHA256, item.Target, Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM app_registry_pending WHERE job_id=?", original.JobID); err != nil {
		t.Fatal(err)
	}
	return s, actor, MemcachedUnixControlOperation{Format: 1, RequestID: ID(), ProjectID: original.ProjectID, ActorID: actor.ID, Input: MemcachedUnixControlInput{Action: "stop", ExpectedRuntimeSHA256: strings.Repeat("a", 64), AcknowledgeCacheLoss: true}}
}
func TestMemcachedUnixControlSeparateCanonicalABIAndExplicitVolatileLoss(t *testing.T) {
	_, _, op := memcachedUnixControlFixture(t)
	raw, _ := json.Marshal(op)
	if got, err := DecodeMemcachedUnixControlOperation(raw); err != nil || got != op {
		t.Fatal("canonical control", err)
	}
	for _, kind := range []string{"duplicate", "alias", "path", "trailing", "missing-ack", "wrong-action", "numeric-hash", "wrong-actor"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(raw)
			changed := op
			switch kind {
			case "duplicate":
				b = append([]byte("{\"format\":1,"), b[1:]...)
			case "alias":
				b = bytes.Replace(b, []byte("\"actor_id\""), []byte("\"Actor_ID\""), 1)
			case "path":
				b = append([]byte("{\"path\":\"/tmp/fake\","), b[1:]...)
			case "trailing":
				b = append(b, '\n')
			case "missing-ack":
				changed.Input.AcknowledgeCacheLoss = false
				b, _ = json.Marshal(changed)
			case "wrong-action":
				changed.Input.Action = "update"
				b, _ = json.Marshal(changed)
			case "numeric-hash":
				changed.Input.ExpectedRuntimeSHA256 = "42"
				b, _ = json.Marshal(changed)
			case "wrong-actor":
				changed.ActorID = "root"
				b, _ = json.Marshal(changed)
			}
			if _, err := DecodeMemcachedUnixControlOperation(b); err == nil {
				t.Fatal("foreign/replayed ABI accepted", kind)
			}
		})
	}
}
func TestMemcachedUnixControlOriginalUnknownNeverRedispatchesOrDisappearsAfterRevoke(t *testing.T) {
	s, actor, op := memcachedUnixControlFixture(t)
	ctx := context.Background()
	row, fresh, err := s.reserveMemcachedUnixControl(ctx, op)
	checkErr := s.CheckMemcachedUnixControl(ctx, op)
	if err != nil || !fresh || row.Operation != op || checkErr != nil {
		reread, found, readErr := readMemcachedUnixControl(ctx, s.DB, op.RequestID)
		t.Fatal("actual SQL reservation", err, "fresh", fresh, "same", row.Operation == op, "check", checkErr, "read", reread, found, readErr)
	}
	if s.CheckMemcachedUnixControlUpgrade(ctx) == nil {
		t.Fatal("undelivered original queue lost")
	}
	if s.CheckMemcachedUnixOtherControls(ctx, op) != nil {
		t.Fatal("exact original census")
	}
	if err = s.finishMemcachedUnixControl(ctx, op, nil); err != nil {
		t.Fatal(err)
	}
	if s.CheckMemcachedUnixControl(ctx, op) == nil {
		t.Fatal("unknown outcome may be sent again")
	}
	row, fresh, err = s.reserveMemcachedUnixControl(ctx, op)
	if err != nil || fresh || row.State != "unknown" {
		t.Fatal("original replay requeued", err)
	}
	different := op
	different.RequestID = ID()
	if _, _, err = s.reserveMemcachedUnixControl(ctx, different); err == nil {
		t.Fatal("new id bypassed original unknown")
	}
	changed := op
	changed.Input.Action = "restart"
	if _, _, err = s.reserveMemcachedUnixControl(ctx, changed); err == nil {
		t.Fatal("original input overwritten")
	}
	if _, err = s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", actor.ID); err != nil {
		t.Fatal(err)
	}
	if s.CheckMemcachedUnixControlUpgrade(ctx) == nil {
		t.Fatal("revocation erased original queue")
	}
	if _, _, err = s.memcachedUnixControlForActor(ctx, actor.ID, op.RequestID); err == nil {
		t.Fatal("revoked actor read native result")
	}
	if _, err = s.DB.Exec("UPDATE app_user_roles SET role='admin' WHERE user_id=?", actor.ID); err != nil {
		t.Fatal(err)
	}
	result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "completed", FinalState: "stopped", RuntimeSHA256: strings.Repeat("b", 64)}
	if err = s.finishMemcachedUnixControl(ctx, op, &result); err != nil {
		t.Fatal("readonly native result reconciliation", err)
	}
	if s.CheckMemcachedUnixControlUpgrade(ctx) != nil {
		t.Fatal("true complete queue still pending")
	}
	row, fresh, err = s.reserveMemcachedUnixControl(ctx, op)
	if err != nil || fresh || row.Result == nil || *row.Result != result {
		t.Fatal("completed request rerun", err)
	}
	fork := result
	fork.RuntimeSHA256 = strings.Repeat("c", 64)
	if s.finishMemcachedUnixControl(ctx, op, &fork) == nil {
		t.Fatal("terminal result overwritten")
	}
}
func TestMemcachedUnixControlRejectsOtherActorAndPartialSchemaWithoutRepair(t *testing.T) {
	for _, kind := range []string{"other-actor", "missing-index", "added-trigger", "missing-table", "invalid-result", "forked-operation"} {
		t.Run(kind, func(t *testing.T) {
			s, actor, op := memcachedUnixControlFixture(t)
			ctx := context.Background()
			if _, _, err := s.reserveMemcachedUnixControl(ctx, op); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "other-actor":
				other := accessUser(t, s, "other-control-admin", "admin", nil)
				if _, _, err := s.memcachedUnixControlForActor(ctx, other.ID, op.RequestID); err == nil {
					t.Fatal("other actor adopted old operation")
				}
				if s.CheckMemcachedUnixControlUpgrade(ctx) == nil {
					t.Fatal("pending work lost")
				}
				return
			case "missing-index":
				s.DB.Exec("DROP INDEX one_active_memcached_unix_control")
			case "added-trigger":
				s.DB.Exec("CREATE TRIGGER foreign_control AFTER UPDATE ON memcached_unix_controls BEGIN SELECT 1; END")
			case "missing-table":
				s.DB.Exec("DROP TABLE memcached_unix_controls")
			case "invalid-result":
				s.DB.Exec("UPDATE memcached_unix_controls SET state='completed',result='{}'")
			case "forked-operation":
				s.DB.Exec("UPDATE memcached_unix_controls SET actor_id=?", strings.Repeat("f", 32))
			}
			if s.CheckMemcachedUnixControl(ctx, op) == nil {
				t.Fatal("changed native authority accepted", kind)
			}
			if kind != "invalid-result" && kind != "forked-operation" && s.CheckMemcachedUnixControlUpgrade(ctx) == nil {
				t.Fatal("changed queue interpreted as no work", kind)
			}
			if _, _, err := s.memcachedUnixControlForActor(ctx, actor.ID, op.RequestID); err == nil {
				t.Fatal("changed status accepted", kind)
			}
		})
	}
}
