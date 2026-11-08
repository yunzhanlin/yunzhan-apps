package core

import (
	"context"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamHistoricalCompletionSelectOnlyIsNotLiveAuthority(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	streamControlReserve(t, s, op)
	if _, err := s.LoadBalanceStreamControlCompletion(ctx, op); err == nil {
		t.Fatal("reserved request became completed history")
	}
	if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	if _, err := s.LoadBalanceStreamControlCompletion(ctx, op); err == nil {
		t.Fatal("issued request became completed history")
	}
	seed, records := streamControlModelChain(t, s, op)
	if err := s.finishLoadBalanceStreamControl(ctx, op, seed, records); err != nil {
		t.Fatal(err)
	}
	counts := streamControlCounts(t, s)
	v, err := s.LoadBalanceStreamControlCompletion(ctx, op)
	if err != nil || v.Format != 1 || v.RequestID != op.RequestID || v.OperationSHA256 != loadbalancestream.OperationSHA256(op) || v.ManifestSHA256 != strings.Repeat("1", 64) || v.SeedSHA256 != Hash(string(seed)) || v.FinalEventSHA256 != Hash(string(records[11])) || v.ServiceObservationSHA256 != strings.Repeat("8", 64) {
		t.Fatal("full original historical binding refused", err)
	}
	if _, err = s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); err != nil {
		t.Fatal(err)
	}
	after, err := s.LoadBalanceStreamControlCompletion(ctx, op)
	if err != nil || after != v || streamControlCounts(t, s) != counts {
		t.Fatal("revoked actor erased or changed original completed metadata", err)
	}
	if s.CheckLoadBalanceStreamControl(ctx, op) == nil {
		t.Fatal("historical record revived live effect authority")
	}
	changed := op
	changed.ActorID = ID()
	if _, err = s.LoadBalanceStreamControlCompletion(ctx, changed); err == nil {
		t.Fatal("other original actor/request accepted as the old completed operation")
	}
}

func TestLoadBalanceStreamHistoricalCompletionDoesNotAdoptUnknownOrSafeRefusal(t *testing.T) {
	for _, state := range []string{"unknown", "refused-before-issue", "partial", "missing-schema"} {
		t.Run(state, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			if fresh, err := s.issueLoadBalanceStreamControl(ctx, op); err != nil || !fresh {
				t.Fatal(err)
			}
			switch state {
			case "unknown":
				if err := s.markLoadBalanceStreamControlUnknown(ctx, op); err != nil {
					t.Fatal(err)
				}
			case "refused-before-issue":
				raw := `{"format":1,"request_id":"` + op.RequestID + `","operation_sha256":"` + loadbalancestream.OperationSHA256(op) + `","state":"refused-before-issue"}`
				if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result=?", raw); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result='{}'"); err != nil {
					t.Fatal(err)
				}
			case "missing-schema":
				if _, err := s.DB.Exec("DROP TABLE load_balance_stream_controls"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.LoadBalanceStreamControlCompletion(ctx, op); err == nil {
				t.Fatal("noncommitted/lost original became runtime generation metadata", state)
			}
		})
	}
}
