//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func analyticsHTMLNativeSnapshotTriplet(t *testing.T, s *Service) []fileBackup {
	t.Helper()
	txs := s.analyticsHTMLTransactionService()
	out := []fileBackup{}
	for _, path := range txs.analyticsHTMLConfigurationPaths() {
		b, err := txs.analyticsHTMLStableBackup(path)
		if err != nil || !b.existed || b.owner == nil {
			t.Fatal("actual configuration triplet snapshot", path, err)
		}
		out = append(out, b)
	}
	return out
}

func analyticsHTMLNativeMatchTriplet(t *testing.T, s *Service, want []fileBackup) {
	t.Helper()
	got := analyticsHTMLNativeSnapshotTriplet(t, s)
	if len(got) != len(want) {
		t.Fatal("triplet length changed")
	}
	for i := range want {
		if got[i].path != want[i].path || got[i].existed != want[i].existed || got[i].mode != want[i].mode || *got[i].owner != *want[i].owner || !bytes.Equal(got[i].data, want[i].data) {
			t.Fatal("actual triplet lost exact bytes/mode/uid/gid/existence", want[i].path)
		}
	}
}

func analyticsHTMLNativeActualHandover(t *testing.T, ctx context.Context, s *Service, site core.Site, firstID, nextID string, reloads *int, rejectNext *bool) {
	t.Helper()
	actualReceipts := map[string][]byte{}
	for _, id := range []string{firstID, nextID} {
		path := filepath.Join(analyticsHTMLBuilds, id+".json")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		actualReceipts[path] = b
	}
	active := s.systemPath("/etc/panel/analytics-html/active.json")
	readActive := func(id string) analyticsHTMLEngineIdentity {
		t.Helper()
		var identity analyticsHTMLEngineIdentity
		if err := readAnalyticsHTMLPrivateJSON(active, 64<<10, &identity); err != nil || identity.JobID != id || identity.State != "active" || identity.CompilerCollection != nativeCompilerCollectionContract {
			t.Fatal("actual current handover identity/collection", id, err)
		}
		if err := s.requireAnalyticsHTMLReady(ctx); err != nil {
			t.Fatal("new actual worker did not acknowledge exact current engine", err)
		}
		return identity
	}
	for _, id := range []string{nextID, firstID} {
		before := *reloads
		if err := s.activateAnalyticsHTML(ctx, id); err != nil || *reloads != before+1 {
			t.Fatal("successful genuine engine handover must reload exactly once", id, err, *reloads-before)
		}
		readActive(id)
		if err := s.activateAnalyticsHTML(ctx, id); err != nil || *reloads != before+1 {
			t.Fatal("current engine lost reply unexpectedly mutated/reloaded", err)
		}
	}
	current := readActive(firstID)
	currentBackup := analyticsHTMLNativeSnapshotTriplet(t, s)
	// Fault-inject ONLY this private active-record copy. The two real source
	// receipts remain current-v2 and byte-identical. This exercises the prior
	// empty-contract handover branch; it is NOT evidence of an actual historic
	// pre-v2 compilation or permission to promote a missing build receipt.
	for _, contract := range []string{"", "dedicated_cgroup_v2_pidfd_reaped_v1", "unknown-contract"} {
		changed := current
		changed.CompilerCollection = contract
		b, err := json.Marshal(changed)
		if err != nil || atomicWrite(active, append(b, '\n'), 0600) != nil {
			t.Fatal("private contract fault injection", err)
		}
		faultSnapshot := analyticsHTMLNativeSnapshotTriplet(t, s)
		before := *reloads
		if err := s.requireAnalyticsHTMLReady(ctx); err == nil {
			t.Fatal("missing/unknown active contract reported current ready", contract)
		}
		if err := s.activateAnalyticsHTML(ctx, firstID); err == nil || *reloads != before {
			t.Fatal("same-ID missing/unknown-contract replay was promoted", contract, err)
		}
		candidate := site
		candidate.Settings.AnalyticsInjectHTML = true
		candidate.Settings.AnalyticsEndpoint = "127.0.0.1:19100"
		candidate.Status = "running"
		data, _ := json.Marshal(candidate)
		r := httptest.NewRequest("POST", "/v1/sites/preview", bytes.NewReader(data)).WithContext(ctx)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "稳定进程完整回收契约") {
			t.Fatal("new actual preview bypassed closed missing-contract readiness", contract, w.Code, w.Body.String())
		}
		analyticsHTMLNativeMatchTriplet(t, s, faultSnapshot)
		if contract != "" {
			if err := s.activateAnalyticsHTML(ctx, nextID); err == nil || *reloads != before {
				t.Fatal("different current producer authorized an unknown prior contract", contract, err)
			}
			analyticsHTMLNativeMatchTriplet(t, s, faultSnapshot)
		} else {
			*rejectNext = true
			if err := s.activateAnalyticsHTML(ctx, nextID); err == nil {
				t.Fatal("empty-prior failed reload reported handover success")
			}
			analyticsHTMLNativeMatchTriplet(t, s, faultSnapshot)
			if err := s.probeAnalyticsHTMLLoaded(ctx, changed); err != nil {
				t.Fatal("empty-prior rollback lost real old worker", err)
			}
			if _, err := os.Lstat(s.analyticsHTMLTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("empty-prior confirmed recovery retained pending journal", err)
			}
			if err := s.activateAnalyticsHTML(ctx, nextID); err != nil {
				t.Fatal("different verified current-v2 producer could not replace exact empty-prior private identity", err)
			}
			readActive(nextID)
			if err := s.activateAnalyticsHTML(ctx, firstID); err != nil {
				t.Fatal("return to actual first current producer", err)
			}
			readActive(firstID)
		}
		// Explicit fixture restoration is not a product repair/migration. Only
		// the active metadata copy was fault-injected; never rewrite a build.
		if err := atomicWrite(active, currentBackup[2].data, currentBackup[2].mode); err != nil {
			t.Fatal(err)
		}
		analyticsHTMLNativeMatchTriplet(t, s, currentBackup)
		readActive(firstID)
	}
	for path, want := range actualReceipts {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("handover/fault test rewrote a genuine producer receipt", path, err)
		}
	}
	t.Log("PASS actual two-way current-v2 engine handover/replay; exact bytes/mode/uid/gid rollback; private simulated empty-prior identity refuses readiness/replay/new preview but permits only different verified producer handover; unknown/v1 prior contract refuses replacement; genuine producer receipt bytes unchanged, NOT historical source-build or app-install acceptance")
}
