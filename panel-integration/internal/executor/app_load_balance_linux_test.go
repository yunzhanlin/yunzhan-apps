//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func lbFixtureInput() core.AppModuleInput {
	return core.AppModuleInput{Domain: "lb-fixture.example.test", Port: 42791, Nodes: []core.AppUpstream{{Address: "127.0.0.1:41001", Weight: 1}, {Address: "127.0.0.1:41002", Weight: 2}}}
}
func lbFiles(t *testing.T, s *Service, domain string) map[string][]byte {
	t.Helper()
	conf, meta := s.loadBalancePaths(domain)
	out := map[string][]byte{}
	for _, p := range []string{conf, meta} {
		b, e := os.ReadFile(p)
		if e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
		if e == nil {
			out[p] = b
		}
	}
	return out
}
func lbAssertFiles(t *testing.T, s *Service, domain string, want map[string][]byte) {
	t.Helper()
	got := lbFiles(t, s, domain)
	if len(got) != len(want) {
		t.Fatal("file presence changed")
	}
	for p, b := range want {
		if !bytes.Equal(b, got[p]) {
			t.Fatal("file changed", p)
		}
	}
}
func lbSave(t *testing.T, s *Service, in core.AppModuleInput) map[string]any {
	t.Helper()
	out, e := s.moduleLoadBalance(context.Background(), "save", in)
	if e != nil {
		t.Fatal(e)
	}
	return out.(map[string]any)
}
func TestLoadBalanceLifecycleRevisionTombstoneAndABA(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	if out, e := s.moduleLoadBalance(context.Background(), "run", core.AppModuleInput{}); e != nil || out.(map[string]any)["count"] != 0 {
		t.Fatal(out, e)
	}
	got := lbSave(t, s, in)
	if got["revision"] != int64(1) {
		t.Fatal(got)
	}
	conf, _ := s.loadBalancePaths(in.Domain)
	b, _ := os.ReadFile(conf)
	if !strings.Contains(string(b), "revision=1") || !strings.Contains(string(b), loadBalanceProbePath(in.Domain)) {
		t.Fatal("no committed identity")
	}
	before := lbFiles(t, s, in.Domain)
	in.Nodes[0].Weight = 7
	if _, e := s.moduleLoadBalance(context.Background(), "save", in); e == nil {
		t.Fatal("stale zero revision replaced entry")
	}
	lbAssertFiles(t, s, in.Domain, before)
	in.ExpectedRevision = 1
	got = lbSave(t, s, in)
	if got["revision"] != int64(2) {
		t.Fatal(got)
	}
	if _, e := s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: in.Domain, ExpectedRevision: 1}); e == nil {
		t.Fatal("stale remove accepted")
	}
	out, e := s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: in.Domain, ExpectedRevision: 2})
	if e != nil || out.(map[string]any)["revision"] != int64(3) {
		t.Fatal(out, e)
	}
	old, present, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil || !present || !old.Removed || old.Revision != 3 {
		t.Fatal(old, present, e)
	}
	if rows, e := s.loadBalanceEntries(); e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	in.ExpectedRevision = 0
	got = lbSave(t, s, in)
	if got["revision"] != int64(4) {
		t.Fatal("recreated revision reset", got)
	}
	in.ExpectedRevision = 1
	if _, e = s.moduleLoadBalance(context.Background(), "save", in); e == nil {
		t.Fatal("old live tab crossed delete/recreate ABA")
	}
}
func TestLoadBalanceClosedAddressAndRenderContract(t *testing.T) {
	in := lbFixtureInput()
	valid := loadBalanceEntry{Format: 1, Revision: 1, Domain: in.Domain, Port: in.Port, Nodes: in.Nodes}
	cases := []struct {
		name string
		edit func(*loadBalanceEntry)
	}{
		{"uppercase", func(v *loadBalanceEntry) { v.Domain = "LB.example.test" }},
		{"injection", func(v *loadBalanceEntry) { v.Domain = "bad';return 200 x;" }},
		{"format", func(v *loadBalanceEntry) { v.Format = 2 }},
		{"revision zero", func(v *loadBalanceEntry) { v.Revision = 0 }},
		{"revision max", func(v *loadBalanceEntry) { v.Revision = 1 << 60 }},
		{"small port", func(v *loadBalanceEntry) { v.Port = 19999 }},
		{"few nodes", func(v *loadBalanceEntry) { v.Nodes = v.Nodes[:1] }},
		{"DNS", func(v *loadBalanceEntry) { v.Nodes[0].Address = "example.test:80" }},
		{"port injection", func(v *loadBalanceEntry) { v.Nodes[0].Address = "127.0.0.1:80;return" }},
		{"mapped IPv6", func(v *loadBalanceEntry) { v.Nodes[0].Address = "[::ffff:127.0.0.1]:80" }},
		{"IPv6 zone", func(v *loadBalanceEntry) { v.Nodes[0].Address = "[fe80::1%lo]:80" }},
		{"metadata", func(v *loadBalanceEntry) { v.Nodes[0].Address = "169.254.169.254:80" }},
		{"multicast", func(v *loadBalanceEntry) { v.Nodes[0].Address = "224.0.0.1:80" }},
		{"unspecified", func(v *loadBalanceEntry) { v.Nodes[0].Address = "0.0.0.0:80" }},
		{"broadcast", func(v *loadBalanceEntry) { v.Nodes[0].Address = "255.255.255.255:80" }},
		{"port padding", func(v *loadBalanceEntry) { v.Nodes[0].Address = "127.0.0.1:080" }},
		{"weight zero", func(v *loadBalanceEntry) { v.Nodes[0].Weight = 0 }},
		{"weight large", func(v *loadBalanceEntry) { v.Nodes[0].Weight = 101 }},
		{"self loop", func(v *loadBalanceEntry) { v.Nodes[0].Address = "127.0.0.1:42791" }},
		{"panel control", func(v *loadBalanceEntry) { v.Nodes[0].Address = "[::1]:19100" }},
		{"duplicate", func(v *loadBalanceEntry) { v.Nodes[1].Address = v.Nodes[0].Address }},
		{"all backup", func(v *loadBalanceEntry) { v.Nodes[0].Backup = true; v.Nodes[1].Backup = true }},
		{"sticky backup", func(v *loadBalanceEntry) { v.Sticky = true; v.Nodes[1].Backup = true }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := valid
			v.Nodes = append([]core.AppUpstream{}, valid.Nodes...)
			tt.edit(&v)
			if e := validateLoadBalanceEntry(v); e == nil {
				t.Fatal("invalid entry accepted")
			}
			if _, e := renderLoadBalanceEntry(v); e == nil {
				t.Fatal("invalid entry rendered")
			}
		})
	}
	good := valid
	good.Nodes = append([]core.AppUpstream{}, valid.Nodes...)
	good.Nodes[0].Address = "[::1]:41001"
	if _, e := renderLoadBalanceEntry(good); e != nil {
		t.Fatal("valid IPv6 rejected", e)
	}
	legacy := valid
	legacy.Format = 0
	legacy.Revision = 0
	rendered, e := renderLoadBalanceEntry(legacy)
	if e != nil || strings.Contains(rendered, "__yunzhan_lb_health") || !strings.Contains(rendered, "proxy_next_upstream error timeout http_502 http_503 http_504") {
		t.Fatal(rendered, e)
	}
	for _, raw := range []string{"{\"format\":2}", "{\"domain\":\"x\",\"unknown\":true}", "{} {}", "[]", "null"} {
		if _, e := decodeLoadBalanceEntry([]byte(raw)); e == nil {
			t.Fatal("unknown/invalid manifest", raw)
		}
	}
}
func lbPendingFixture(t *testing.T) (*Service, core.AppModuleInput, loadBalanceTransaction, map[string][]byte) {
	t.Helper()
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	lbSave(t, s, in)
	before := lbFiles(t, s, in.Domain)
	conf, meta := s.loadBalancePaths(in.Domain)
	old, _, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil {
		t.Fatal(e)
	}
	next := old
	next.Revision++
	next.Nodes = append([]core.AppUpstream{}, old.Nodes...)
	next.Nodes[0].Weight++
	config, e := renderLoadBalanceEntry(next)
	if e != nil {
		t.Fatal(e)
	}
	metadata, _ := json.MarshalIndent(next, "", "  ")
	metadata = append(metadata, '\n')
	changes := []wafConfigChange{{Path: conf, OldData: before[conf], OldExists: true, OldMode: 0644, NextData: []byte(config), NextExists: true, NextMode: 0644}, {Path: meta, OldData: before[meta], OldExists: true, OldMode: 0600, NextData: metadata, NextExists: true, NextMode: 0600}}
	tx := loadBalanceTransaction{Format: 1, ID: core.ID(), Domain: in.Domain, State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
	for _, c := range changes {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
	}
	if e = s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
		t.Fatal(e)
	}
	return s, in, tx, before
}
func TestLoadBalanceDurablePartialWritesRestoredAndCommitted(t *testing.T) {
	for _, stage := range []int{0, 1, 2} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			s, in, tx, before := lbPendingFixture(t)
			for i := 0; i < stage; i++ {
				if e := wafApplyChange(tx.Changes[i], true); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := s.moduleLoadBalance(context.Background(), "save", in); e == nil {
				t.Fatal("pending replaced")
			}
			if unlock, e := s.lockWAFSiteMutation(); e == nil {
				unlock()
				t.Fatal("site mutation ignored pending entry")
			}
			if e := s.recoverLoadBalanceBeforeMutation(context.Background(), s.Config.NginxBin); e != nil {
				t.Fatal(e)
			}
			lbAssertFiles(t, s, in.Domain, before)
			if _, e := os.Lstat(s.loadBalancePendingPath()); !os.IsNotExist(e) {
				t.Fatal("pending not finished")
			}
			var saved loadBalanceTransaction
			if e := moduleRead(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), tx.ID+".json"), &saved); e != nil || saved.State != "recovered" {
				t.Fatal(saved, e)
			}
		})
	}
	t.Run("committed pending preserves new version", func(t *testing.T) {
		s, in, tx, _ := lbPendingFixture(t)
		for _, c := range tx.Changes {
			if e := wafApplyChange(c, true); e != nil {
				t.Fatal(e)
			}
		}
		tx.State = "committed"
		if e := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
			t.Fatal(e)
		}
		before := lbFiles(t, s, in.Domain)
		if e := s.recoverLoadBalanceBeforeMutation(context.Background(), s.Config.NginxBin); e != nil {
			t.Fatal(e)
		}
		lbAssertFiles(t, s, in.Domain, before)
	})
}
func TestLoadBalanceRecoveryRejectsExternalEditsBeforeAnyRestore(t *testing.T) {
	for _, index := range []int{0, 1} {
		t.Run(string(rune('0'+index)), func(t *testing.T) {
			s, in, tx, _ := lbPendingFixture(t)
			if e := wafApplyChange(tx.Changes[0], true); e != nil {
				t.Fatal(e)
			}
			c := tx.Changes[index]
			if e := os.WriteFile(c.Path, []byte("external edit\n"), c.OldMode); e != nil {
				t.Fatal(e)
			}
			before := lbFiles(t, s, in.Domain)
			pending, _ := os.ReadFile(s.loadBalancePendingPath())
			if e := s.recoverLoadBalanceBeforeMutation(context.Background(), s.Config.NginxBin); e == nil {
				t.Fatal("external edit overwritten")
			}
			lbAssertFiles(t, s, in.Domain, before)
			got, _ := os.ReadFile(s.loadBalancePendingPath())
			if !bytes.Equal(got, pending) {
				t.Fatal("unknown pending altered")
			}
		})
	}
}
func TestLoadBalanceRecoveryRejectsCorruptPrivateRecordAndForeignPaths(t *testing.T) {
	edits := []struct {
		name string
		edit func(*loadBalanceTransaction)
	}{
		{"digest", func(tx *loadBalanceTransaction) { tx.Digests[tx.Changes[0].Path+":old"] = strings.Repeat("0", 64) }},
		{"path", func(tx *loadBalanceTransaction) { tx.Changes[0].Path = "/etc/nginx/nginx.conf" }},
		{"state", func(tx *loadBalanceTransaction) { tx.State = "successful" }},
		{"mode", func(tx *loadBalanceTransaction) { tx.Changes[1].NextMode = 0644 }},
		{"domain", func(tx *loadBalanceTransaction) { tx.Domain = "other.example.test" }},
		{"missing", func(tx *loadBalanceTransaction) { tx.Changes = tx.Changes[:1] }},
		{"revision", func(tx *loadBalanceTransaction) {
			var v loadBalanceEntry
			json.Unmarshal(tx.Changes[1].NextData, &v)
			v.Revision = 8
			b, _ := json.Marshal(v)
			tx.Changes[1].NextData = b
			tx.Digests[tx.Changes[1].Path+":next"] = core.Hash(string(b))
		}},
	}
	for _, tt := range edits {
		t.Run(tt.name, func(t *testing.T) {
			s, in, tx, before := lbPendingFixture(t)
			tt.edit(&tx)
			if e := moduleWrite(s.loadBalancePendingPath(), tx); e != nil {
				t.Fatal(e)
			}
			pending, _ := os.ReadFile(s.loadBalancePendingPath())
			if _, _, e := s.restoreLoadBalanceTransaction(); e == nil {
				t.Fatal("corrupt recovery accepted")
			}
			lbAssertFiles(t, s, in.Domain, before)
			got, _ := os.ReadFile(s.loadBalancePendingPath())
			if !bytes.Equal(pending, got) {
				t.Fatal("corrupt evidence modified")
			}
		})
	}
	for _, kind := range []string{"symlink", "hardlink", "public mode"} {
		t.Run(kind, func(t *testing.T) {
			s, in, _, before := lbPendingFixture(t)
			p := s.loadBalancePendingPath()
			if kind == "symlink" {
				target := p + ".saved"
				os.Rename(p, target)
				os.Symlink(target, p)
			}
			if kind == "hardlink" {
				os.Link(p, p+".saved")
			}
			if kind == "public mode" {
				os.Chmod(p, 0644)
			}
			if _, _, e := s.restoreLoadBalanceTransaction(); e == nil {
				t.Fatal("untrusted recovery identity accepted")
			}
			lbAssertFiles(t, s, in.Domain, before)
		})
	}
}
func TestLoadBalanceLegacyExactMigrationAndManualDrift(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "external edit"}[drift], func(t *testing.T) {
			s := wafPolicyFixture(t)
			in := lbFixtureInput()
			conf, meta := s.loadBalancePaths(in.Domain)
			v := loadBalanceEntry{Domain: in.Domain, Port: in.Port, Nodes: in.Nodes}
			rendered, _ := renderLoadBalanceEntry(v)
			s.wafOwnedDirectory(filepath.Dir(meta), true)
			if e := moduleWrite(meta, map[string]any{"domain": v.Domain, "port": v.Port, "nodes": v.Nodes, "sticky": v.Sticky}); e != nil {
				t.Fatal(e)
			}
			if drift {
				rendered += "# handwritten\n"
			}
			os.WriteFile(conf, []byte(rendered), 0644)
			before := lbFiles(t, s, in.Domain)
			_, e := s.moduleLoadBalance(context.Background(), "save", in)
			if drift {
				if e == nil {
					t.Fatal("legacy drift adopted")
				}
				lbAssertFiles(t, s, in.Domain, before)
			} else {
				if e != nil {
					t.Fatal(e)
				}
				saved, _, e := s.readLoadBalanceEntry(in.Domain)
				if e != nil || saved.Format != 1 || saved.Revision != 1 {
					t.Fatal(saved, e)
				}
			}
		})
	}
}
func TestLoadBalanceSyntaxFailureRollbackAndCancellation(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	lbSave(t, s, in)
	before := lbFiles(t, s, in.Domain)
	checks := 0
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "-t" {
			checks++
			if checks == 1 {
				return "", errors.New("injected syntax failure")
			}
		}
		return "", nil
	}
	in.ExpectedRevision = 1
	in.Sticky = true
	if _, e := s.moduleLoadBalance(context.Background(), "save", in); e == nil || !strings.Contains(e.Error(), "已恢复") {
		t.Fatal(e)
	}
	if checks != 2 {
		t.Fatal("rollback did not validate original", checks)
	}
	lbAssertFiles(t, s, in.Domain, before)
	if _, e := os.Lstat(s.loadBalancePendingPath()); !os.IsNotExist(e) {
		t.Fatal("rollback not committed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.moduleLoadBalance(ctx, "save", in); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	lbAssertFiles(t, s, in.Domain, before)
}
func TestLoadBalanceClosedUnknownListing(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	lbSave(t, s, in)
	_, meta := s.loadBalancePaths(in.Domain)
	if e := os.WriteFile(filepath.Join(filepath.Dir(meta), "unknown.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.loadBalanceEntries(); e == nil {
		t.Fatal("unknown entry omitted")
	}
}
