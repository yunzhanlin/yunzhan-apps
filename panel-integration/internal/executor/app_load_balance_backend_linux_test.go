//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func lbBackendFixture(t *testing.T) (*Service, core.AppModuleInput) {
	t.Helper()
	s := wafPolicyFixture(t)
	if e := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{"id": "load-balance", "version": "1.6.0", "installed_at": core.Now(), "settings": map[string]any{}}); e != nil {
		t.Fatal(e)
	}
	_, ca := lbTLSCertificate(t, "backend.example.test", false)
	in := lbFixtureInput()
	in.BackendTLS = &core.LoadBalanceBackendTLS{ServerName: "backend.example.test", CAPEM: ca}
	return s, in
}
func lbBackendFiles(t *testing.T, s *Service, domain string) map[string][]byte {
	t.Helper()
	files := lbFiles(t, s, domain)
	path := s.loadBalanceCAPath(domain)
	if b, e := os.ReadFile(path); e == nil {
		files[path] = b
	} else if !os.IsNotExist(e) {
		t.Fatal(e)
	}
	return files
}
func lbBackendAssert(t *testing.T, s *Service, domain string, want map[string][]byte) {
	t.Helper()
	got := lbBackendFiles(t, s, domain)
	if len(got) != len(want) {
		t.Fatal("TLS presence changed", len(got), len(want))
	}
	for path, b := range want {
		if string(got[path]) != string(b) {
			t.Fatal("TLS file changed", path)
		}
	}
}
func TestLoadBalanceTLSBackendExplicitLifecycleAndClosedRenderer(t *testing.T) {
	s, in := lbBackendFixture(t)
	got := lbSave(t, s, in)
	caPath := s.loadBalanceCAPath(in.Domain)
	stat, e := os.Lstat(caPath)
	if e != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("CA permissions", e)
	}
	entry, present, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil || !present || entry.Format != 2 {
		t.Fatal(entry, present, e)
	}
	conf, _ := s.loadBalancePaths(in.Domain)
	b, _ := os.ReadFile(conf)
	for _, directive := range []string{"proxy_pass https://panel_lb_", "proxy_ssl_server_name on;", "proxy_ssl_verify on;", "proxy_ssl_name backend.example.test;", "proxy_set_header Host backend.example.test;", "proxy_ssl_protocols TLSv1.2 TLSv1.3;", "proxy_ssl_trusted_certificate \"" + caPath + "\";"} {
		if !strings.Contains(string(b), directive) {
			t.Fatal("missing TLS directive", directive)
		}
	}
	for _, path := range []string{"", "relative.pem", "/tmp/ca;$bad.pem", "/tmp/ca\n.pem", "/tmp/../etc/ca.pem"} {
		if _, e := renderLoadBalanceEntryTrust(entry, path); e == nil {
			t.Fatal("unsafe trust path accepted", path)
		}
	}
	var tx loadBalanceTransaction
	if e := moduleRead(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), got["transaction_id"].(string)+".json"), &tx); e != nil || tx.Format != 2 || len(tx.Changes) != 3 || len(tx.Digests) != 6 {
		t.Fatal(tx, e)
	}
	if e := s.loadBalanceTransactionContract(tx); e != nil {
		t.Fatal(e)
	}
	in.BackendTLS = nil
	in.ExpectedRevision = 1
	lbSave(t, s, in)
	if _, e := os.Lstat(caPath); !os.IsNotExist(e) {
		t.Fatal("explicit HTTP downgrade retained trust file", e)
	}
	entry, _, e = s.readLoadBalanceEntry(in.Domain)
	if e != nil || entry.Format != 1 || entry.BackendTLS != nil {
		t.Fatal(entry, e)
	}
	plain, _ := os.ReadFile(conf)
	if !strings.Contains(string(plain), "proxy_pass http://panel_lb_") || strings.Contains(string(plain), "proxy_ssl_") {
		t.Fatal("explicit downgrade did not restore HTTP")
	}
}
func TestLoadBalanceTLSBackendRequiresActualVersionAndPublicTrust(t *testing.T) {
	s, in := lbBackendFixture(t)
	if e := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{"id": "load-balance", "version": "1.5.0", "installed_at": core.Now(), "settings": map[string]any{}}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.moduleLoadBalance(context.Background(), "save", in); e == nil || !strings.Contains(e.Error(), "1.6.0") {
		t.Fatal("old module accepted TLS business forwarding", e)
	}
	if len(lbBackendFiles(t, s, in.Domain)) != 0 {
		t.Fatal("old module wrote files")
	}
	if core.ValidateLoadBalanceBackendTLS(nil) != nil {
		t.Fatal("legacy opt-out rejected")
	}
	for _, policy := range []*core.LoadBalanceBackendTLS{{ServerName: in.Domain}, {ServerName: "bad;return x", CAPEM: in.BackendTLS.CAPEM}, {ServerName: "127.0.0.1", CAPEM: in.BackendTLS.CAPEM}, {ServerName: in.Domain, CAPEM: "/etc/ssl/certs/ca-certificates.crt"}, {ServerName: in.Domain, CAPEM: "-----BEGIN PRIVATE KEY-----\nsecret"}} {
		if core.ValidateLoadBalanceBackendTLS(policy) == nil {
			t.Fatal("unsafe trust policy accepted")
		}
	}
}
func TestLoadBalanceTLSBackendDurableThreeFileRestoreAllStages(t *testing.T) {
	for stage := 0; stage <= 3; stage++ {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			s, in := lbBackendFixture(t)
			lbSave(t, s, in)
			old := lbBackendFiles(t, s, in.Domain)
			_, ca := lbTLSCertificate(t, "new-backend.example.test", false)
			in.BackendTLS = &core.LoadBalanceBackendTLS{ServerName: "new-backend.example.test", CAPEM: ca}
			in.ExpectedRevision = 1
			got := lbSave(t, s, in)
			var tx loadBalanceTransaction
			if e := moduleRead(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), got["transaction_id"].(string)+".json"), &tx); e != nil {
				t.Fatal(e)
			}
			for _, c := range tx.Changes {
				if e := wafApplyChange(c, false); e != nil {
					t.Fatal(e)
				}
			}
			tx.State = "applying"
			tx.ID = core.ID() // A distinct interrupted attempt; never rewrite a committed archive.
			if e := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
				t.Fatal(e)
			}
			for _, c := range tx.Changes[:stage] {
				if e := wafApplyChange(c, true); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.recoverLoadBalanceBeforeMutation(context.Background(), s.Config.NginxBin); e != nil {
				t.Fatal(e)
			}
			lbBackendAssert(t, s, in.Domain, old)
			if _, e := os.Lstat(s.loadBalancePendingPath()); !os.IsNotExist(e) {
				t.Fatal("pending not archived", e)
			}
		})
	}
}
func TestLoadBalanceTLSBackendRecoveryRejectsExtraTargetsAndExternalCA(t *testing.T) {
	s, in := lbBackendFixture(t)
	got := lbSave(t, s, in)
	var original loadBalanceTransaction
	if e := moduleRead(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), got["transaction_id"].(string)+".json"), &original); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"outside path", "wrong CA", "bad mode", "missing CA", "wrong format", "extra digest"} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(original)
			var tx loadBalanceTransaction
			json.Unmarshal(b, &tx)
			switch name {
			case "outside path":
				tx.Changes[2].Path = "/etc/ssl/certs/ca-certificates.crt"
			case "wrong CA":
				tx.Changes[2].NextData = []byte("other")
				tx.Digests[tx.Changes[2].Path+":next"] = core.Hash("other")
			case "bad mode":
				tx.Changes[2].NextMode = 0644
			case "missing CA":
				tx.Changes = tx.Changes[:2]
			case "wrong format":
				tx.Format = 1
			case "extra digest":
				tx.Digests["unknown:next"] = core.Hash("")
			}
			if e := s.loadBalanceTransactionContract(tx); e == nil {
				t.Fatal("unsafe TLS restore accepted", name)
			}
		})
	}
	before := lbBackendFiles(t, s, in.Domain)
	// Simulate a manual edit, not an authorized transaction. No adoption.
	if e := os.WriteFile(s.loadBalanceCAPath(in.Domain), []byte("external edit"), 0600); e != nil {
		t.Fatal(e)
	}
	changed := lbBackendFiles(t, s, in.Domain)
	if _, _, e := s.readLoadBalanceEntry(in.Domain); e == nil {
		t.Fatal("external CA adopted")
	}
	in.ExpectedRevision = 1
	if _, e := s.moduleLoadBalance(context.Background(), "save", in); e == nil {
		t.Fatal("external CA overwritten")
	}
	lbBackendAssert(t, s, in.Domain, changed)
	if e := os.WriteFile(s.loadBalanceCAPath(in.Domain), before[s.loadBalanceCAPath(in.Domain)], 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.moduleLoadBalance(context.Background(), "remove", core.AppModuleInput{Domain: in.Domain, ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
	entry, present, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil || !present || !entry.Removed || entry.BackendTLS == nil || entry.Format != 2 {
		t.Fatal("TLS tombstone lost identity", entry, e)
	}
	if _, e := os.Lstat(s.loadBalanceCAPath(in.Domain)); !os.IsNotExist(e) {
		t.Fatal("removed entry CA retained live", e)
	}
}
