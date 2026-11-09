//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/core"
)

func lbRoutingFixtureEntry() loadBalanceEntry {
	in := lbFixtureInput()
	on := true
	policy := lbHTTPPolicy()
	policy.AutoTraffic = &on
	return loadBalanceEntry{Format: 3, Revision: 1, Domain: in.Domain, Port: in.Port, Nodes: in.Nodes, HealthCheck: policy, Routing: &loadBalanceRouting{Down: []string{}}}
}

// These are isolated filesystem contract tests, not a native Nginx reload.
func lbRoutingTransactionFixture(t *testing.T, withTLS ...bool) (*Service, loadBalanceTransaction, loadBalanceEntry) {
	t.Helper()
	s := wafPolicyFixture(t)
	old := lbRoutingFixtureEntry()
	if len(withTLS) > 0 && withTLS[0] {
		_, ca := lbTLSCertificate(t, "backend.example.test", false)
		old.BackendTLS = &core.LoadBalanceBackendTLS{ServerName: "backend.example.test", CAPEM: ca}
		old.HealthCheck.CheckPort = 41003
		old.Nodes = append([]core.AppUpstream{}, old.Nodes...)
		old.Nodes[1].Address = "127.0.0.2:41002"
	}
	first := lbRoutingSample(old, nil, false)
	second := lbRoutingSample(old, &first, false)
	next, changed, err := loadBalanceRoutingNext(old, second)
	if err != nil || !changed {
		t.Fatal(next, changed, err)
	}
	second.Fingerprint = loadBalanceFingerprint(next)
	conf, meta := s.loadBalancePaths(old.Domain)
	health := s.loadBalanceHealthPath(old.Domain)
	changes := []wafConfigChange{}
	oldRender, err := s.renderLoadBalanceEntry(old)
	if err != nil {
		t.Fatal(err)
	}
	nextRender, err := s.renderLoadBalanceEntry(next)
	if err != nil {
		t.Fatal(err)
	}
	oldMeta, _ := json.Marshal(old)
	nextMeta, _ := json.Marshal(next)
	oldHealth, _ := json.Marshal(first)
	nextHealth, _ := json.Marshal(second)
	for _, v := range []struct {
		path          string
		before, after []byte
		mode          os.FileMode
	}{{conf, []byte(oldRender), []byte(nextRender), 0644}, {meta, oldMeta, nextMeta, 0600}, {health, oldHealth, nextHealth, 0600}} {
		if err = s.wafOwnedDirectory(filepath.Dir(v.path), true); err != nil {
			t.Fatal(err)
		}
		if err = atomicWrite(v.path, v.before, v.mode); err != nil {
			t.Fatal(err)
		}
		changes = append(changes, wafConfigChange{Path: v.path, OldExists: true, OldData: v.before, OldMode: v.mode, NextExists: true, NextData: v.after, NextMode: v.mode})
	}
	format := 3
	if old.BackendTLS != nil {
		path := s.loadBalanceCAPath(old.Domain)
		_, ca := loadBalanceCAState(old)
		if err = s.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		if err = atomicWrite(path, ca, 0600); err != nil {
			t.Fatal(err)
		}
		changes = append(changes, wafConfigChange{Path: path, OldExists: true, OldData: ca, OldMode: 0600, NextExists: true, NextData: ca, NextMode: 0600})
		format = 4
	}
	if err = s.wafOwnedDirectory(filepath.Dir(s.loadBalancePendingPath()), true); err != nil {
		t.Fatal(err)
	}
	tx := loadBalanceTransaction{Format: format, ID: core.ID(), Domain: old.Domain, State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
	for _, c := range changes {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
	}
	if err = s.loadBalanceTransactionContract(tx); err != nil {
		t.Fatal("valid active transaction rejected", err)
	}
	return s, tx, old
}

func TestLoadBalanceRoutingThreeFileRecoveryEveryPartialWriteAndUnknownPreservation(t *testing.T) {
	for stage := 0; stage <= 3; stage++ {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			s, tx, _ := lbRoutingTransactionFixture(t)
			if err := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < stage; i++ {
				if err := wafApplyChange(tx.Changes[i], true); err != nil {
					t.Fatal(err)
				}
			}
			fresh := New(s.Config)
			got, restored, err := fresh.restoreLoadBalanceTransaction()
			if err != nil || !restored || got.ID != tx.ID || got.State != "restored" {
				t.Fatal(got, restored, err)
			}
			for _, c := range tx.Changes {
				b, err := os.ReadFile(c.Path)
				if err != nil || !bytes.Equal(b, c.OldData) {
					t.Fatal("incomplete old set restore", c.Path, err)
				}
			}
			if _, err = os.Stat(s.loadBalancePendingPath()); err != nil {
				t.Fatal("native confirmation pending record lost", err)
			}
		})
	}
	s, tx, _ := lbRoutingTransactionFixture(t)
	if err := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); err != nil {
		t.Fatal(err)
	}
	for _, c := range tx.Changes[:2] {
		if err := wafApplyChange(c, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tx.Changes[2].Path, []byte("external-health-change"), 0600); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, c := range tx.Changes {
		before[c.Path], _ = os.ReadFile(c.Path)
	}
	if _, _, err := s.restoreLoadBalanceTransaction(); err == nil {
		t.Fatal("unknown health data overwritten")
	}
	for _, c := range tx.Changes {
		b, _ := os.ReadFile(c.Path)
		if !bytes.Equal(b, before[c.Path]) {
			t.Fatal("partial restore occurred before all-file check", c.Path)
		}
	}
}

func TestLoadBalanceRoutingTransactionRejectsPolicyAndCounterRewrites(t *testing.T) {
	s, tx, _ := lbRoutingTransactionFixture(t)
	for name, edit := range map[string]func(*loadBalanceTransaction){
		"wrong health path":  func(v *loadBalanceTransaction) { v.Changes[2].Path += ".foreign" },
		"public health mode": func(v *loadBalanceTransaction) { v.Changes[2].NextMode = 0644 },
		"omitted health":     func(v *loadBalanceTransaction) { v.Changes = v.Changes[:2] },
		"missing CA format":  func(v *loadBalanceTransaction) { v.Format = 4 },
		"rewritten policy revision": func(v *loadBalanceTransaction) {
			var e loadBalanceEntry
			json.Unmarshal(v.Changes[1].NextData, &e)
			e.Revision++
			v.Changes[1].NextData, _ = json.Marshal(e)
		},
		"rewritten threshold evidence": func(v *loadBalanceTransaction) {
			var e loadBalanceHTTPState
			json.Unmarshal(v.Changes[2].NextData, &e)
			e.Nodes[0].Failures = 1
			v.Changes[2].NextData, _ = json.Marshal(e)
		},
		"forgotten original transitions": func(v *loadBalanceTransaction) {
			var e loadBalanceHTTPState
			json.Unmarshal(v.Changes[2].NextData, &e)
			e.Transitions = []loadBalanceHTTPTransition{}
			v.Changes[2].NextData, _ = json.Marshal(e)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := tx
			bad.Changes = append([]wafConfigChange{}, tx.Changes...)
			edit(&bad)
			bad.Digests = map[string]string{}
			for _, c := range bad.Changes {
				bad.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
				bad.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
			}
			if s.loadBalanceTransactionContract(bad) == nil {
				t.Fatal("forged semantic recovery contract accepted")
			}
		})
	}
}

func lbRoutingSample(v loadBalanceEntry, old *loadBalanceHTTPState, success bool) loadBalanceHTTPState {
	now := time.Now().UTC()
	rows := []loadBalanceHTTPNode{}
	for _, n := range v.Nodes {
		sample := loadBalanceHTTPNode{Address: n.Address, State: "unknown", Reason: "status_mismatch", Status: 503, CheckedAt: now.Format(time.RFC3339Nano)}
		if success {
			sample.Reason, sample.Status, sample.LastSuccess = "ok", 200, true
		}
		rows = append(rows, sample)
	}
	return advanceLoadBalanceHTTPState(v, old, rows, now)
}

func TestLoadBalanceRoutingMetadataClosedNoImplicitAuthority(t *testing.T) {
	v := lbRoutingFixtureEntry()
	if err := validateLoadBalanceEntry(v); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*loadBalanceEntry){
		"implicit historical format": func(v *loadBalanceEntry) { v.Format = 1 },
		"missing explicit policy":    func(v *loadBalanceEntry) { p := *v.HealthCheck; p.AutoTraffic = nil; v.HealthCheck = &p },
		"explicitly off":             func(v *loadBalanceEntry) { p := *v.HealthCheck; off := false; p.AutoTraffic = &off; v.HealthCheck = &p },
		"missing runtime identity":   func(v *loadBalanceEntry) { v.Routing = nil },
		"missing complete down set":  func(v *loadBalanceEntry) { v.Routing = &loadBalanceRouting{} },
		"negative sequence":          func(v *loadBalanceEntry) { v.Routing = &loadBalanceRouting{Sequence: -1, Down: []string{}} },
		"sequence overflow":          func(v *loadBalanceEntry) { v.Routing = &loadBalanceRouting{Sequence: 1 << 60, Down: []string{}} },
		"foreign address":            func(v *loadBalanceEntry) { v.Routing = &loadBalanceRouting{Down: []string{"127.0.0.1:41003"}} },
		"duplicates": func(v *loadBalanceEntry) {
			v.Routing = &loadBalanceRouting{Down: []string{v.Nodes[0].Address, v.Nodes[0].Address}}
		},
		"unsorted": func(v *loadBalanceEntry) {
			v.Routing = &loadBalanceRouting{Down: []string{v.Nodes[1].Address, v.Nodes[0].Address}}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			bad := v
			edit(&bad)
			if validateLoadBalanceEntry(bad) == nil {
				t.Fatal("unsafe runtime routing accepted")
			}
		})
	}
	legacy := v
	legacy.Format = 1
	legacy.Routing = nil
	p := *legacy.HealthCheck
	p.AutoTraffic = nil
	legacy.HealthCheck = &p
	if validateLoadBalanceEntry(legacy) != nil || core.LoadBalanceAutomaticTraffic(legacy.HealthCheck) {
		t.Fatal("historical observation changed")
	}
}

func TestLoadBalanceRoutingThresholdsPreservePolicyAndNoImplicitFailOpen(t *testing.T) {
	v := lbRoutingFixtureEntry()
	original, _ := json.Marshal(v)
	first := lbRoutingSample(v, nil, false)
	if _, changed, err := loadBalanceRoutingNext(v, first); err != nil || changed {
		t.Fatal("first failure ejected", changed, err)
	}
	second := lbRoutingSample(v, &first, false)
	next, changed, err := loadBalanceRoutingNext(v, second)
	if err != nil || !changed || next.Revision != v.Revision || next.Routing.Sequence != 1 || len(next.Routing.Down) != 2 {
		t.Fatal(next, changed, err)
	}
	after, _ := json.Marshal(v)
	if string(after) != string(original) {
		t.Fatal("pure decision mutated original policy")
	}
	rendered, err := renderLoadBalanceEntry(next)
	if err != nil || strings.Count(rendered, " down;") != 2 {
		t.Fatal("all failures silently admitted", rendered, err)
	}
	second.Fingerprint = loadBalanceFingerprint(next)
	rise := lbRoutingSample(next, &second, true)
	if _, changed, err = loadBalanceRoutingNext(next, rise); err != nil || changed {
		t.Fatal("first success restored before threshold", changed, err)
	}
	recovered := lbRoutingSample(next, &rise, true)
	restored, changed, err := loadBalanceRoutingNext(next, recovered)
	if err != nil || !changed || restored.Revision != 1 || restored.Routing.Sequence != 2 || len(restored.Routing.Down) != 0 {
		t.Fatal(restored, changed, err)
	}
	rendered, err = renderLoadBalanceEntry(restored)
	if err != nil || strings.Contains(rendered, " down;") {
		t.Fatal(rendered, err)
	}
}

func TestLoadBalanceRoutingRejectsWrongIdentityTimeAndExhaustion(t *testing.T) {
	v := lbRoutingFixtureEntry()
	first := lbRoutingSample(v, nil, false)
	state := lbRoutingSample(v, &first, false)
	for name, edit := range map[string]func(*loadBalanceHTTPState){
		"revision":      func(s *loadBalanceHTTPState) { s.Revision++ },
		"fingerprint":   func(s *loadBalanceHTTPState) { s.Fingerprint = "wrong" },
		"partial nodes": func(s *loadBalanceHTTPState) { s.Nodes = s.Nodes[:1] },
		"future clock":  func(s *loadBalanceHTTPState) { s.CheckedAt = time.Now().Add(2 * time.Minute).Format(time.RFC3339Nano) },
		"wrong node": func(s *loadBalanceHTTPState) {
			s.Nodes = append([]loadBalanceHTTPNode{}, s.Nodes...)
			s.Nodes[0].Address = "127.0.0.1:41003"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := state
			edit(&bad)
			if _, _, err := loadBalanceRoutingNext(v, bad); err == nil {
				t.Fatal("unbound health decision accepted")
			}
		})
	}
	v.Routing = &loadBalanceRouting{Sequence: (1 << 60) - 1, Down: []string{}}
	state.Fingerprint = loadBalanceFingerprint(v)
	if _, _, err := loadBalanceRoutingNext(v, state); err == nil {
		t.Fatal("runtime sequence wrapped")
	}
}

func lbRoutingInstalled(t *testing.T, s *Service, version string) {
	t.Helper()
	if err := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{"id": "load-balance", "version": version, "installed_at": core.Now(), "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBalanceRoutingSaveRequiresCurrentVersionExactAuthorityAndPreservesDown(t *testing.T) {
	s := wafPolicyFixture(t)
	lbRoutingInstalled(t, s, "1.6.0")
	in := lbFixtureInput()
	lbSave(t, s, in)
	in.ExpectedRevision = 1
	in.HealthCheck = lbRoutingFixtureEntry().HealthCheck
	in.Confirm = "ENABLE HEALTH ROUTING " + in.Domain
	before := lbFiles(t, s, in.Domain)
	if _, err := s.moduleLoadBalance(context.Background(), "save", in); err == nil {
		t.Fatal("old version implicitly upgraded active authority")
	}
	lbAssertFiles(t, s, in.Domain, before)
	lbRoutingInstalled(t, s, "1.7.0")
	for _, confirm := range []string{"", "ENABLE HEALTH ROUTING other.example.test", in.Confirm + " "} {
		bad := in
		bad.Confirm = confirm
		if _, err := s.moduleLoadBalance(context.Background(), "save", bad); err == nil {
			t.Fatal("inexact active authority accepted", confirm)
		}
		lbAssertFiles(t, s, in.Domain, before)
	}
	lbSave(t, s, in)
	in.ExpectedRevision = 2
	v, _, err := s.readLoadBalanceEntry(in.Domain)
	if err != nil || v.Format != 3 || len(v.Routing.Down) != 0 {
		t.Fatal(v, err)
	}
	// This fixture emulates a fully bound committed exclusion, not Nginx proof.
	v.Routing = &loadBalanceRouting{Sequence: 1, Down: []string{v.Nodes[0].Address}}
	conf, meta := s.loadBalancePaths(in.Domain)
	rendered, err := s.renderLoadBalanceEntry(v)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	if err = atomicWrite(conf, []byte(rendered), 0644); err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(meta, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// A legacy client omitting the new boolean cannot silently switch it off.
	policy := *in.HealthCheck
	policy.AutoTraffic = nil
	in.HealthCheck = &policy
	in.Confirm = ""
	before = lbFiles(t, s, in.Domain)
	if _, err = s.moduleLoadBalance(context.Background(), "save", in); err == nil {
		t.Fatal("legacy omission silently altered authority")
	}
	lbAssertFiles(t, s, in.Domain, before)
	in.Confirm = "ENABLE HEALTH ROUTING " + in.Domain
	lbSave(t, s, in)
	in.ExpectedRevision = 3
	v, _, err = s.readLoadBalanceEntry(in.Domain)
	if err != nil || !core.LoadBalanceAutomaticTraffic(v.HealthCheck) || len(v.Routing.Down) != 1 || v.Routing.Sequence != 0 {
		t.Fatal("policy edit reopened excluded node", v, err)
	}
	state := lbRoutingSample(v, nil, true)
	if _, changed, err := loadBalanceRoutingNext(v, state); err != nil || changed {
		t.Fatal("unknown fresh counters reopened excluded node", changed, err)
	}
	off := false
	policy.AutoTraffic = &off
	in.Confirm = ""
	lbSave(t, s, in)
	v, _, err = s.readLoadBalanceEntry(in.Domain)
	if err != nil || v.Format != 1 || v.Routing != nil || core.LoadBalanceAutomaticTraffic(v.HealthCheck) {
		t.Fatal("explicit disable retained runtime", v, err)
	}
}

func TestLoadBalanceRoutingNoopBatchVersionDriftDropsAllResults(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var block atomic.Bool
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if block.Load() {
			started <- struct{}{}
			<-release
		}
		w.Write([]byte("READY"))
	})
	lbRoutingInstalled(t, s, "1.7.0")
	on := true
	in.HealthCheck.AutoTraffic = &on
	in.Confirm = "ENABLE HEALTH ROUTING " + in.Domain
	lbSave(t, s, in)
	in.ExpectedRevision = 2
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("no routing change must not reload Nginx")
		return "", errors.New("unexpected command")
	}
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	path := s.loadBalanceHealthPath(in.Domain)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block.Store(true)
	done := make(chan error, 1)
	go func() { _, err := s.checkLoadBalanceHTTP(context.Background(), in); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("probes never started")
	}
	lbRoutingInstalled(t, s, "1.6.0")
	close(release)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "安装身份") {
			t.Fatal("version drift committed result", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("batch never ended")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("stale no-op result overwritten", err)
	}
}

func TestLoadBalanceRoutingTLSFourFileRecoveryAllStagesAndCAIdentity(t *testing.T) {
	for stage := 0; stage <= 4; stage++ {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			s, tx, _ := lbRoutingTransactionFixture(t, true)
			if err := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); err != nil {
				t.Fatal(err)
			}
			for _, c := range tx.Changes[:stage] {
				if err := wafApplyChange(c, true); err != nil {
					t.Fatal(err)
				}
			}
			fresh := New(s.Config)
			if _, restored, err := fresh.restoreLoadBalanceTransaction(); err != nil || !restored {
				t.Fatal("complete TLS routing restore", restored, err)
			}
			for _, c := range tx.Changes {
				b, err := os.ReadFile(c.Path)
				if err != nil || !bytes.Equal(b, c.OldData) {
					t.Fatal("TLS old set incomplete", c.Path, err)
				}
			}
		})
	}
	s, tx, _ := lbRoutingTransactionFixture(t, true)
	_, ca := lbTLSCertificate(t, "foreign.example.test", false)
	tx.Changes[3].NextData = []byte(ca)
	tx.Digests[tx.Changes[3].Path+":next"] = core.Hash(ca)
	if s.loadBalanceTransactionContract(tx) == nil {
		t.Fatal("auto-routing changed TLS trust")
	}
}
