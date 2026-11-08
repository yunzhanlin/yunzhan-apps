//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

// Private metadata fixtures only. A body policy here neither builds a sealed
// engine nor authorizes activation, a signed installation or a business request.
func TestApacheNativeHistoryArchivePreservesCurrentPolicyAndOriginalBytes(t *testing.T) {
	for _, body := range []bool{false, true} {
		name := "metadata-only"
		if body {
			name = "body-policy-retained"
		}
		t.Run(name, func(t *testing.T) {
			s, tx, path, raw := apacheHistoryFixture(t)
			cfg := core.DefaultApacheWAFConfig()
			if body {
				cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{{SiteID: strings.Repeat("b", 32), Policy: core.DefaultWAFBodyPolicy()}}}
			}
			installed := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
			if err := moduleWrite(installed, map[string]any{"id": "apache-waf", "version": "2.4.0", "settings": core.WAFSettings(cfg), "installed_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z"}); err != nil {
				t.Fatal(err)
			}
			configs := map[string][]byte{}
			identities := map[string]os.FileInfo{}
			for _, c := range tx.Changes {
				var err error
				configs[c.Path], err = os.ReadFile(c.Path)
				if err != nil {
					t.Fatal(err)
				}
				identities[c.Path], err = os.Stat(c.Path)
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			report, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16})
			if err != nil {
				t.Fatal("native2.4 original transaction inventory unavailable", err)
			}
			page := report.(map[string]any)
			if page["total"] != 1 || page["transaction_archive_ready"] != true || page["transaction_replay_ready"] != true || page["configuration_changed"] != false {
				t.Fatal("native2.4 maintenance capability or counters changed", page)
			}
			in := apacheArchiveInput(tx, raw)
			bad := in
			bad.SHA = strings.Repeat("0", 64)
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", bad); err == nil {
				t.Fatal("stale original digest authorized a native archive")
			}
			if _, err := os.Lstat(s.apacheWAFArchiveDir()); !os.IsNotExist(err) {
				t.Fatal("refused native archive created a directory", err)
			}
			out, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", in)
			if err != nil || out.(map[string]any)["replayed"] != false || out.(map[string]any)["configuration_changed"] != false {
				t.Fatal("native original archive failed", err)
			}
			archive := filepath.Join(s.apacheWAFArchiveDir(), tx.ID+".json")
			actual, err := os.ReadFile(archive)
			if err != nil || !bytes.Equal(actual, raw) {
				t.Fatal("native archive rewrote original bytes", err)
			}
			after, err := os.Stat(archive)
			if err != nil {
				t.Fatal(err)
			}
			oldOwner, newOwner := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || oldOwner.Uid != newOwner.Uid || oldOwner.Gid != newOwner.Gid || oldOwner.Nlink != 1 || newOwner.Nlink != 1 {
				t.Fatal("native archive changed original identity, owner or mode", err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("native completed record was not moved", err)
			}
			fresh := New(s.Config).apacheWAFTransactionService()
			again, err := fresh.apacheWAFHistoryOperation(context.Background(), "archive-transaction", in)
			if err != nil || again.(map[string]any)["replayed"] != true {
				t.Fatal("native archived identity cannot be observed after a lost reply", err)
			}
			for name, original := range configs {
				actual, readErr := os.ReadFile(name)
				info, statErr := os.Stat(name)
				if readErr != nil || statErr != nil || !bytes.Equal(actual, original) || !os.SameFile(info, identities[name]) || info.Mode() != identities[name].Mode() {
					t.Fatal("archive changed a current metadata/body configuration", name)
				}
			}
			page = apacheHistoryReport(t, fresh, 0)
			if page["total"] != 1 || page["transaction_active_count"] != 0 || page["transaction_archive_count"] != 1 || page["records_retained"] != true {
				t.Fatal("native archive inventory differs from the original record", page)
			}
			public, _ := json.Marshal(page)
			for _, private := range []string{"old_data", "next_data", "settings", "engine_job_id", "backup_sha256", s.Config.SystemRoot} {
				if bytes.Contains(public, []byte(private)) {
					t.Fatal("native history response exposed private configuration", private)
				}
			}
		})
	}
}

func TestApacheNativeHistoryRefusesUnknownVersionsAndInvalidBodyAuthority(t *testing.T) {
	for _, kind := range []string{"legacy-body", "future-version", "version-alias", "invalid-native-policy"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, raw := apacheHistoryFixture(t)
			version := "2.4.0"
			cfg := core.DefaultApacheWAFConfig()
			cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{{SiteID: strings.Repeat("b", 32), Policy: core.DefaultWAFBodyPolicy()}}}
			switch kind {
			case "legacy-body":
				version = "2.3.0"
			case "future-version":
				version = "2.4.1"
			case "version-alias":
				version = "v2.4.0"
			case "invalid-native-policy":
				cfg.Body.Sites[0].Policy.Mode = "unverified-runtime-mode"
			}
			installed := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
			if err := moduleWrite(installed, map[string]any{"id": "apache-waf", "version": version, "settings": core.WAFSettings(cfg)}); err != nil {
				t.Fatal(err)
			}
			manifest, _ := os.ReadFile(installed)
			before, _ := os.Stat(path)
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
				t.Fatal("unknown version or body authority granted history access", kind)
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, raw)); err == nil {
				t.Fatal("unknown version or body authority granted archive access", kind)
			}
			actual, _ := os.ReadFile(path)
			after, _ := os.Stat(path)
			kept, _ := os.ReadFile(installed)
			if !bytes.Equal(actual, raw) || !bytes.Equal(manifest, kept) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("refusal repaired, rewrote or adopted original records")
			}
			if _, err := os.Lstat(s.apacheWAFArchiveDir()); !os.IsNotExist(err) {
				t.Fatal("refusal created an archive directory", err)
			}
		})
	}
}
