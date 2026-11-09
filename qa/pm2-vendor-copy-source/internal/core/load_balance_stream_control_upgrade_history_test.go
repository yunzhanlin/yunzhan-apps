package core

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamControlUpgradeHistoryOnlyCompleteLiveOriginalMayRemainIssued(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	streamControlReserve(t, s, op)
	if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil); err == nil {
		t.Fatal("reserved request disappeared from admission")
	}
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	authority, err := s.LoadBalanceStreamControlAuthority(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	counts := streamControlCounts(t, s)
	if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil); err == nil {
		t.Fatal("issued request disappeared without an original witness")
	}
	history, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, &authority)
	if err != nil || len(history) != 1 || history[0].State != "issued" || history[0].ResultState != "" || history[0].Completion.Format != 0 || !reflect.DeepEqual(history[0].Operation, op) || streamControlCounts(t, s) != counts {
		t.Fatal("complete original read-only authority refused or changed data", err)
	}
	for _, field := range []string{"format", "request", "actor", "operation", "app", "version", "manifest", "revision", "actor-observation"} {
		changed := authority
		switch field {
		case "format":
			changed.Format++
		case "request":
			changed.RequestID = ID()
		case "actor":
			changed.ActorID = ID()
		case "operation":
			changed.OperationSHA256 = strings.Repeat("c", 64)
		case "app":
			changed.AppID = "nginx"
		case "version":
			changed.AppVersion = "2.0.0"
		case "manifest":
			changed.ManifestSHA256 = strings.Repeat("c", 64)
		case "revision":
			changed.AccessRevision++
		case "actor-observation":
			changed.ActorObservationSHA256 = strings.Repeat("c", 64)
		}
		if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, &changed); err == nil {
			t.Fatal("partial/changed current grant became a skip", field)
		}
	}
	if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, &authority); err == nil {
		t.Fatal("revoked original retained a live exemption")
	}
	if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil); err == nil {
		t.Fatal("revocation erased still issued original work")
	}
}

func TestLoadBalanceStreamControlUpgradeHistoryClosedOriginalsRemainVisibleAfterRevocation(t *testing.T) {
	for _, kind := range []string{"committed", "refused-before-issue"} {
		t.Run(kind, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if kind == "committed" {
				if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
					t.Fatal(err)
				}
				seed, records := streamControlModelChain(t, s, op)
				if err := s.finishLoadBalanceStreamControl(ctx, op, seed, records); err != nil {
					t.Fatal(err)
				}
			} else if fresh, err := s.cancelUndispatchedLoadBalanceStreamControl(ctx, actor.ID, op.RequestID); err != nil || !fresh {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); err != nil {
				t.Fatal(err)
			}
			counts := streamControlCounts(t, s)
			history, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil)
			if err != nil || len(history) != 1 || history[0].State != "completed" || history[0].ResultState != kind || streamControlCounts(t, s) != counts {
				t.Fatal("closed original was hidden/changed by revocation", err)
			}
			if (history[0].Completion.Format == 1) != (kind == "committed") {
				t.Fatal("safe pre-dispatch refusal became a committed generation")
			}
			if kind == "committed" && history[0].Completion.OperationSHA256 != loadbalancestream.OperationSHA256(op) {
				t.Fatal("original committed binding changed")
			}
			if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
				t.Fatal("closed history revived native effect authority")
			}
		})
	}
}

func TestLoadBalanceStreamControlUpgradeHistoryOrphanUnknownAndAuditDriftRefuse(t *testing.T) {
	for _, fault := range []string{"unknown", "deleted-row", "missing-audit", "duplicate-audit", "changed-audit-actor", "orphan-cancel-audit", "missing-schema"} {
		t.Run(fault, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
				t.Fatal(err)
			}
			authority, err := s.LoadBalanceStreamControlAuthority(ctx, op)
			if err != nil {
				t.Fatal(err)
			}
			var query string
			var args []any
			switch fault {
			case "unknown":
				query = "UPDATE load_balance_stream_controls SET state='unknown'"
			case "deleted-row":
				query = "DELETE FROM load_balance_stream_controls"
			case "missing-audit":
				query = "DELETE FROM audit_logs WHERE action='app.load-balance.stream.control'"
			case "duplicate-audit":
				query = "INSERT INTO audit_logs(actor,action,target,result,created_at)SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='app.load-balance.stream.control'"
			case "changed-audit-actor":
				query = "UPDATE audit_logs SET actor=? WHERE action='app.load-balance.stream.control'"
				args = []any{ID()}
			case "orphan-cancel-audit":
				query = "INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.cancel-before-issue',?,?,?)"
				args = []any{op.ActorID, ID(), loadbalancestream.OperationSHA256(op), Now()}
			case "missing-schema":
				query = "DROP TABLE load_balance_stream_controls"
			}
			if _, err := s.DB.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, &authority); err == nil {
				t.Fatal("orphan/unknown/drifted original admitted", fault)
			}
			if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil); err == nil {
				t.Fatal("lost original treated as empty/closed history", fault)
			}
		})
	}
}
