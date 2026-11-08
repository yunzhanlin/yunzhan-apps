package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestLoadBalanceStreamControlHistoryHTTPHasNoExecutionAndClosedQuery(t *testing.T) {
	s, owner, op := streamControlFixture(t)
	other := accessUser(t, s, "history-http-other", "admin", nil)
	limited := accessUser(t, s, "history-http-limited", "admin", []string{"runtimes", "system-tools"})
	streamControlReserve(t, s, op)
	a, request, login := diskHostHTTPServer(t, s)
	nativeCalls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		nativeCalls++
		return nil, errors.New("readonly history must not contact the executor")
	})}}
	oc, csrf := login(owner.Username)
	xc, xcsrf := login(other.Username)
	lc, lcsrf := login(limited.Username)
	before := streamControlCounts(t, s)
	const path = "/api/app-registry/load-balance/stream/controls"
	for _, suffix := range []string{"", "?offset=0", "?offset=32", "?offset=4096"} {
		w := request("GET", path+suffix, "", oc, csrf)
		var page loadBalanceStreamControlHistory
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.ActorID != owner.ID || page.Total != 1 {
			t.Fatal("original authenticated no-store history", suffix, w.Code, w.Body.String())
		}
		if suffix == "" && (len(page.Rows) != 1 || page.Rows[0].Operation.RequestID != op.RequestID || page.Rows[0].State != "reserved") {
			t.Fatal("history did not preserve an undispatched original", page)
		}
	}
	for _, suffix := range []string{"?offset=1", "?offset=-32", "?offset=4097", "?offset=00", "?offset=+32", "?offset=%33%32", "?offset=32&offset=0", "?offset=0&", "?actor_id=" + owner.ID, "?dispatch=true", "?offset=0&limit=1", "?offset=0;dispatch=true", "?%6ffset=0"} {
		w := request("GET", path+suffix, "", oc, csrf)
		if w.Code != 400 {
			t.Fatal("noncanonical or effect-bearing query accepted", suffix, w.Code, w.Body.String())
		}
	}
	foreign := request("GET", path, "", xc, xcsrf)
	var page loadBalanceStreamControlHistory
	if foreign.Code != 200 || json.Unmarshal(foreign.Body.Bytes(), &page) != nil || page.ActorID != other.ID || page.Total != 0 || len(page.Rows) != 0 || strings.Contains(foreign.Body.String(), op.RequestID) {
		t.Fatal("other administrator could read private original", foreign.Code, foreign.Body.String())
	}
	if w := request("GET", path, "", lc, lcsrf); w.Code != 403 {
		t.Fatal("restricted administrator obtained host history", w.Code)
	}
	if w := request("GET", path, "", nil, ""); w.Code != 401 {
		t.Fatal("anonymous history", w.Code)
	}
	if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", owner.ID); err != nil {
		t.Fatal(err)
	}
	if w := request("GET", path, "", oc, csrf); w.Code != 403 {
		t.Fatal("old cookie bypassed current authority", w.Code)
	}
	if nativeCalls != 0 || streamControlCounts(t, s) != before {
		t.Fatal("history reads changed original state, jobs, audit, or Root", nativeCalls)
	}
}

func TestLoadBalanceStreamControlHistoryIsReadOnlyBoundedAndActorOwned(t *testing.T) {
	s, actor, op := streamControlFixture(t)
	ctx := context.Background()
	other := accessUser(t, s, "stream-history-other", "admin", nil)
	// Real SQL reservations and explicit never-issued closure; no Root effects.
	for i := 0; i < 34; i++ {
		op.RequestID = ID()
		op.ActorID = actor.ID
		if i == 1 {
			op.ActorID = other.ID
		}
		streamControlReserve(t, s, op)
		if _, err := s.cancelUndispatchedLoadBalanceStreamControl(ctx, op.ActorID, op.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	counts := streamControlCounts(t, s)
	first, err := s.loadBalanceStreamControlsForActor(ctx, actor.ID, 0)
	if err != nil || first.Format != 1 || first.ActorID != actor.ID || first.Total != 33 || len(first.Rows) != 32 || first.NextOffset == nil || *first.NextOffset != 32 {
		t.Fatal("first bounded original history", first, err)
	}
	seen := map[string]bool{}
	for _, row := range first.Rows {
		if row.Operation.ActorID != actor.ID || row.State != "completed" || row.Result == nil || row.Result.State != "refused-before-issue" || seen[row.Operation.RequestID] {
			t.Fatal("cross-actor, incomplete, or duplicate history", row)
		}
		seen[row.Operation.RequestID] = true
	}
	last, err := s.loadBalanceStreamControlsForActor(ctx, actor.ID, *first.NextOffset)
	if err != nil || len(last.Rows) != 1 || last.NextOffset != nil || seen[last.Rows[0].Operation.RequestID] {
		t.Fatal("last bounded original history", last, err)
	}
	foreign, err := s.loadBalanceStreamControlsForActor(ctx, other.ID, 0)
	if err != nil || foreign.Total != 1 || len(foreign.Rows) != 1 || foreign.Rows[0].Operation.ActorID != other.ID {
		t.Fatal("independent administrator privacy", foreign, err)
	}
	if streamControlCounts(t, s) != counts {
		t.Fatal("read-only history mutated jobs, controls, or audit")
	}
	for _, offset := range []int{-1, 1, 31, 33, 4097, 1 << 30} {
		if _, err := s.loadBalanceStreamControlsForActor(ctx, actor.ID, offset); err == nil {
			t.Fatal("unbounded page accepted", offset)
		}
	}
	empty, err := s.loadBalanceStreamControlsForActor(ctx, actor.ID, 4096)
	if err != nil || len(empty.Rows) != 0 || empty.NextOffset != nil {
		t.Fatal("bounded end page", empty, err)
	}
}

func TestLoadBalanceStreamControlHistoryRejectsCorruptionAndRevocation(t *testing.T) {
	for _, change := range []string{"corrupt-result", "foreign-operation", "viewer"} {
		t.Run(change, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			streamControlReserve(t, s, op)
			switch change {
			case "corrupt-result":
				if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET state='completed',result='{}'"); err != nil {
					t.Fatal(err)
				}
			case "foreign-operation":
				changed := op
				changed.ActorID = strings.Repeat("f", 32)
				raw, _ := json.Marshal(changed)
				if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET operation=?", string(raw)); err != nil {
					t.Fatal(err)
				}
			case "viewer":
				if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", actor.ID); err != nil {
					t.Fatal(err)
				}
			}
			counts := streamControlCounts(t, s)
			if _, err := s.loadBalanceStreamControlsForActor(ctx, actor.ID, 0); err == nil {
				t.Fatal("untrusted historical evidence or revoked role accepted")
			}
			if streamControlCounts(t, s) != counts {
				t.Fatal("failed readonly query performed work")
			}
		})
	}
}
