package core

import (
	"context"
	"testing"
)

func TestLoadBalanceStreamRecreatedIdentifierCannotAdoptOldNativeCompletion(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	oldRow := streamControlReserve(t, s, op)
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	original, err := s.LoadBalanceStreamControlAuthority(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	oldSeed, oldRecords := streamControlModelChain(t, s, op)
	if s.finishLoadBalanceStreamControl(ctx, op, oldSeed, oldRecords) != nil {
		t.Fatal("original model failed")
	}
	// ISOLATED DB recovery model ONLY. No production records are deleted.
	// Simulate restoring a DB before the old reservation then recreating its
	// UUID with the SAME user, policy, role, manifest AND timestamp.
	if _, err := s.DB.Exec("DELETE FROM load_balance_stream_controls WHERE request_id=?", op.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM audit_logs WHERE action='app.load-balance.stream.control' AND target=?", op.RequestID); err != nil {
		t.Fatal(err)
	}
	streamControlReserve(t, s, op)
	if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET created_at=?,updated_at=? WHERE request_id=?", oldRow.CreatedAt, oldRow.CreatedAt, op.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE audit_logs SET created_at=? WHERE action='app.load-balance.stream.control' AND target=?", oldRow.CreatedAt, op.RequestID); err != nil {
		t.Fatal(err)
	}
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	current, err := s.LoadBalanceStreamControlAuthority(ctx, op)
	if err != nil || current.OriginalRequestSHA256 == original.OriginalRequestSHA256 ||
		current.ActorID != actor.ID || current.ActorObservationSHA256 != original.ActorObservationSHA256 {
		t.Fatal("recreated reservation did not retain a separate persistent identity", err)
	}
	if s.finishLoadBalanceStreamControl(ctx, op, oldSeed, oldRecords) == nil {
		t.Fatal("old native completion was adopted for a different reservation")
	}
	row, found, err := readStreamControl(ctx, s.DB, op.RequestID)
	if err != nil || !found || row.State != "issued" || row.Result != nil {
		t.Fatal("old proof changed the new original outcome", err)
	}
	newSeed, newRecords := streamControlModelChain(t, s, op)
	if err := s.finishLoadBalanceStreamControl(ctx, op, newSeed, newRecords); err != nil {
		t.Fatal("new independent model refused", err)
	}
	completion, err := s.LoadBalanceStreamControlCompletion(ctx, op)
	if err != nil || completion.OriginalRequestSHA256 != current.OriginalRequestSHA256 {
		t.Fatal("historical completion lost reservation binding", err)
	}
}

func TestLoadBalanceStreamMissingOrAmbiguousReservationAuditCannotIssue(t *testing.T) {
	for _, query := range []string{
		"DELETE FROM audit_logs WHERE action='app.load-balance.stream.control'",
		"UPDATE audit_logs SET result='claimed' WHERE action='app.load-balance.stream.control'",
		"INSERT INTO audit_logs(actor,action,target,result,created_at)SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='app.load-balance.stream.control'",
	} {
		s, _, op := streamControlFixture(t)
		streamControlReserve(t, s, op)
		if _, err := s.DB.Exec(query); err != nil {
			t.Fatal(err)
		}
		if fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op); err == nil || fresh {
			t.Fatal("malformed/missing/duplicate original audit issued an operation")
		}
	}
}
