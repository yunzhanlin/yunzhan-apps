//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func wafLegacy201Fixture(t *testing.T, edits ...func(*core.WAFConfig)) (*Service, core.WAFConfig) {
	return wafLegacyVersionFixture(t, "2.0.1", edits...)
}

func TestWAFVerified240UpgradePreservesRotationDraftAndNeverEnablesDeletion(t *testing.T) {
	for _, rotation := range []bool{false, true} {
		t.Run(fmt.Sprint(rotation), func(t *testing.T) {
			s, cfg := wafLegacyVersionFixture(t, "2.4.0", func(cfg *core.WAFConfig) {
				if rotation {
					v := core.DefaultWAFBodyLogRotation()
					v.RotateMiB, v.MaxAgeMinutes = 7, 23
					cfg.BodyLogRotation = &v
				}
			})
			before, err := s.readSoftwareManifest("nginx-waf")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err != nil {
				t.Fatal(err)
			}
			after, err := s.readSoftwareManifest("nginx-waf")
			if err != nil || after.Version != "2.5.0" || after.InstalledAt != before.InstalledAt {
				t.Fatal("upgrade identity lost", err)
			}
			actual, err := core.DecodeWAFConfig(after.Settings)
			cfg.Policy.Revision++
			want, _ := json.Marshal(cfg)
			got, _ := json.Marshal(actual)
			if err != nil || !bytes.Equal(want, got) || actual.BodyLogRetention != nil {
				t.Fatal("upgrade changed draft or opted into deletion", err)
			}
			if _, err := os.Lstat(s.wafBodyRetentionPath()); !os.IsNotExist(err) {
				t.Fatal("upgrade created deletion record", err)
			}
		})
	}
}

func TestWAFUpgradeLogHealthRequiresActualOwnedLock(t *testing.T) {
	for _, fault := range []string{"held", "unlocked", "closed", "foreign"} {
		t.Run(fault, func(t *testing.T) {
			s := wafPolicyFixture(t)
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			switch fault {
			case "unlocked":
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
					t.Fatal(err)
				}
			case "closed":
				lock.Close()
			case "foreign":
				other := wafPolicyFixture(t)
				f, err := other.lockWAFConfiguration()
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				lock = f
			}
			if err := s.verifyWAFHealthLock(lock); (err == nil) != (fault == "held") {
				t.Fatal("lock verification mismatch", fault, err)
			}
		})
	}
}

func wafLegacyVersionFixture(t *testing.T, version string, edits ...func(*core.WAFConfig)) (*Service, core.WAFConfig) {
	t.Helper()
	s := wafPolicyFixture(t)
	cfg := core.DefaultWAFConfig()
	cfg.Policy.Revision = 11
	// A user-authored value resembling the new version must not be changed by
	// version migration. Render version parameters never perform text rewrites.
	cfg.Policy.Lists["ua_deny"] = []core.WAFEntry{{ID: core.ID(), Value: "scanner-" + core.WAFVersion}}
	for _, edit := range edits {
		edit(&cfg)
	}
	if cfg.Body != nil {
		for _, site := range cfg.Body.Sites {
			path := filepath.Join(s.Config.ConfDir, site.SiteID+".conf")
			if err := os.WriteFile(path, []byte("# managed by panel; site="+site.SiteID+"\nserver {\n}\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	plan, err := s.planWAFConfigurationVersion(cfg, false, version)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan {
		if err := s.wafOwnedDirectory(filepath.Dir(change.Path), true); err != nil {
			t.Fatal(err)
		}
		if err := wafApplyChange(change, true); err != nil {
			t.Fatal(err)
		}
	}
	return s, cfg
}

func TestWAFVerified210UpdatePreservesPausedEngineAndRejectsDrift(t *testing.T) {
	for _, fault := range []string{"none", "http-drift", "missing-paused-body-site"} {
		t.Run(fault, func(t *testing.T) {
			id := core.ID()
			policy := core.DefaultWAFBodyPolicy()
			policy.Mode = "off"
			s, cfg := wafLegacyVersionFixture(t, "2.1.0", func(cfg *core.WAFConfig) {
				cfg.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{{SiteID: id, Policy: policy}}}
			})
			before, err := s.readSoftwareManifest("nginx-waf")
			if err != nil {
				t.Fatal(err)
			}
			if fault == "http-drift" {
				h, _ := wafFiles(s)
				data, _ := os.ReadFile(h)
				os.WriteFile(h, append(data, []byte("# external drift\n")...), 0640)
			}
			if fault == "missing-paused-body-site" {
				os.Remove(filepath.Join(s.Config.ConfDir, id+".conf"))
			}
			old, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
			status := s.softwareStatus(context.Background(), "nginx-waf")
			err = s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {})
			if fault != "none" {
				if status.Healthy || err == nil {
					t.Fatal("unverified 2.1.0 update accepted", fault, err)
				}
				current, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
				if !bytes.Equal(old, current) {
					t.Fatal("rejected old body-policy migration wrote manifest")
				}
				return
			}
			if !status.Healthy || err != nil {
				t.Fatal("verified 2.1.0 migration blocked", status, err)
			}
			after, err := s.readSoftwareManifest("nginx-waf")
			if err != nil || after.Version != core.WAFVersion || after.InstalledAt != before.InstalledAt {
				t.Fatal("migration manifest identity lost", after, err)
			}
			got, err := core.DecodeWAFConfig(after.Settings)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Policy.Revision++
			want, _ := json.Marshal(cfg)
			actual, _ := json.Marshal(got)
			if !bytes.Equal(want, actual) || got.Body == nil || got.Body.EngineJobID != cfg.Body.EngineJobID {
				t.Fatal("version-only migration changed or enabled paused body policy")
			}
			main, _ := os.ReadFile(s.Config.NginxConf)
			if strings.Contains(string(main), wafBodyLoaderBegin) {
				t.Fatal("migration silently activated paused engine")
			}
		})
	}
}

func TestWAFVerified211UpgradeKeepsProxyDisabledAndBodyIdentity(t *testing.T) {
	for _, bodyMode := range []string{"absent", "empty", "paused"} {
		for _, drift := range []bool{false, true} {
			t.Run(bodyMode+fmt.Sprint(drift), func(t *testing.T) {
				s, cfg := wafLegacyVersionFixture(t, "2.1.1", func(cfg *core.WAFConfig) {
					if bodyMode != "absent" {
						cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{}}
						if bodyMode == "paused" {
							policy := core.DefaultWAFBodyPolicy()
							policy.Mode = "off"
							cfg.Body.Sites = append(cfg.Body.Sites, core.WAFBodySitePolicy{SiteID: strings.Repeat("b", 32), Policy: policy})
						}
					}
				})
				h, v := wafFiles(s)
				if drift {
					data, _ := os.ReadFile(v)
					if err := os.WriteFile(v, append(data, []byte("# external administrator edit\n")...), 0640); err != nil {
						t.Fatal(err)
					}
				}
				paths := []string{h, v, s.Config.NginxConf, s.softwareManifestPath("nginx-waf")}
				before := map[string][]byte{}
				for _, path := range paths {
					before[path], _ = os.ReadFile(path)
				}
				original, _ := s.readSoftwareManifest("nginx-waf")
				err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {})
				if drift {
					if err == nil {
						t.Fatal("manual 2.1.1 configuration overwritten")
					}
					for path, want := range before {
						got, _ := os.ReadFile(path)
						if !bytes.Equal(got, want) {
							t.Fatal("rejected upgrade wrote", path)
						}
					}
					if _, err := os.Stat(filepath.Join(s.Config.SecurityDir, "waf-backups")); !os.IsNotExist(err) {
						t.Fatal("rejected upgrade created backup", err)
					}
					return
				}
				if err != nil {
					t.Fatal("verified 2.1.1 upgrade rejected", err)
				}
				after, err := s.readSoftwareManifest("nginx-waf")
				if err != nil || after.Version != core.WAFVersion || after.InstalledAt != original.InstalledAt {
					t.Fatal("upgrade identity lost", err)
				}
				got, err := core.DecodeWAFConfig(after.Settings)
				cfg.Policy.Revision++
				want, _ := json.Marshal(cfg)
				actual, _ := json.Marshal(got)
				if err != nil || !bytes.Equal(want, actual) || got.TrustedProxy != nil {
					t.Fatal("upgrade activated proxy or changed body/policy", err)
				}
				main, _ := os.ReadFile(s.Config.NginxConf)
				if !bytes.Equal(main, before[s.Config.NginxConf]) {
					t.Fatal("version-only upgrade changed global Nginx")
				}
			})
		}
	}
}

func TestWAFVerified201UpdatePreservesSettingsAndRequiresActualRules(t *testing.T) {
	s, cfg := wafLegacy201Fixture(t)
	before, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	status := s.softwareStatus(context.Background(), "nginx-waf")
	if !status.Healthy || status.Version != "2.0.1" || !strings.Contains(status.Detail, "旧版 2.0.1") {
		t.Fatal("verified old installation not migratable", status)
	}
	if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err != nil {
		t.Fatal("real migration handler failed", err)
	}
	after, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || after.Version != core.WAFVersion || after.InstalledAt != before.InstalledAt {
		t.Fatal("manifest identity/install time lost", after, err)
	}
	got, err := core.DecodeWAFConfig(after.Settings)
	if err != nil || got.Policy.Revision != cfg.Policy.Revision+1 || got.Body != nil {
		t.Fatal("migration revision/body policy invalid", got, err)
	}
	got.Policy.Revision = cfg.Policy.Revision
	if wafProbeValue(got) != wafProbeValue(cfg) {
		t.Fatal("migration reset existing policy")
	}
	if !s.softwareStatus(context.Background(), "nginx-waf").Healthy {
		t.Fatal("new rules not verified after update")
	}
	if _, err := os.Stat(s.wafPendingPath()); !os.IsNotExist(err) {
		t.Fatal("migration left pending transaction", err)
	}
}

func TestWAFLegacyHealthCannotHideManualEditsOrPendingTransaction(t *testing.T) {
	for _, fault := range []string{"http-bytes", "server-bytes", "permissions", "pending"} {
		t.Run(fault, func(t *testing.T) {
			s, cfg := wafLegacy201Fixture(t)
			h, v := wafFiles(s)
			originalH, _ := os.ReadFile(h)
			originalV, _ := os.ReadFile(v)
			switch fault {
			case "http-bytes", "server-bytes":
				path := h
				if fault == "server-bytes" {
					path = v
				}
				data, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(data, []byte("# administrator change\n")...), 0640) != nil {
					t.Fatal("fault setup failed", err)
				}
			case "permissions":
				if err := os.Chmod(h, 0666); err != nil {
					t.Fatal(err)
				}
			case "pending":
				cfg.Policy.Revision++
				plan, err := s.planWAFConfiguration(cfg, false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.startWAFTransaction(plan); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
			if s.softwareStatus(context.Background(), "nginx-waf").Healthy {
				t.Fatal("damaged old installation reported healthy", fault)
			}
			if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err == nil {
				t.Fatal("unhealthy old installation update accepted", fault)
			}
			after, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
			if string(before) != string(after) {
				t.Fatal("rejected migration mutated installed manifest")
			}
			if fault == "pending" || fault == "permissions" {
				actualH, _ := os.ReadFile(h)
				actualV, _ := os.ReadFile(v)
				if string(actualH) != string(originalH) || string(actualV) != string(originalV) {
					t.Fatal("rejected migration mutated live rules")
				}
			}
		})
	}
}

func TestWAFHistoricalVersionAllowlistIsClosed(t *testing.T) {
	s := wafPolicyFixture(t)
	cfg := core.DefaultWAFConfig()
	for _, version := range []string{"2.0.0", "1.0", "2.0.1; injected", "9.0.0"} {
		if _, err := s.planWAFConfigurationVersion(cfg, false, version); err == nil {
			t.Fatal("unknown old version accepted", version)
		}
	}
	cfg.Body = &core.WAFBodyConfig{}
	if _, err := s.planWAFConfigurationVersion(cfg, false, "2.0.1"); err == nil {
		t.Fatal("body engine falsely attributed to historical metadata-only install")
	}
}

func TestWAF201OnlyUnchangedDisabledCCMayRetainMissingSiteHistory(t *testing.T) {
	for _, fault := range []string{"disabled-only", "active-cc", "site-policy", "list", "rule", "foreign", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			id := core.ID()
			s, original := wafLegacy201Fixture(t, func(cfg *core.WAFConfig) {
				cfg.Policy.CCRules = []core.WAFCCRule{{ID: core.ID(), SiteID: id, Path: "/old-entry", Rate: 2, Burst: 3, Enabled: fault == "active-cc"}}
				switch fault {
				case "site-policy":
					cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: id, Mode: "off"}}
				case "list":
					cfg.Policy.Lists["ua_deny"] = append(cfg.Policy.Lists["ua_deny"], core.WAFEntry{ID: core.ID(), SiteID: id, Value: "scanner"})
				case "rule":
					cfg.Policy.Rules = []core.WAFRule{{ID: core.ID(), SiteID: id, Name: "old", Field: "uri", Operator: "contains", Value: "old", Action: "block", Enabled: false}}
				}
			})
			path := filepath.Join(s.Config.ConfDir, id+".conf")
			if fault == "foreign" {
				if err := os.WriteFile(path, []byte("# administrator-owned\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "symlink" {
				if err := os.Symlink(s.Config.NginxConf, path); err != nil {
					t.Fatal(err)
				}
			}
			healthy := s.softwareStatus(context.Background(), "nginx-waf").Healthy
			before, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
			err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {})
			if fault != "disabled-only" {
				if healthy || err == nil {
					t.Fatal("missing active/other/foreign reference bypassed migration", fault, err)
				}
				after, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
				if string(before) != string(after) {
					t.Fatal("rejected reference migration changed manifest")
				}
				return
			}
			if !healthy || err != nil {
				t.Fatal("inert existing history blocked version-only upgrade", err)
			}
			manifest, _ := s.readSoftwareManifest("nginx-waf")
			cfg, err := core.DecodeWAFConfig(manifest.Settings)
			if err != nil || len(cfg.Policy.CCRules) != 1 || cfg.Policy.CCRules[0] != original.Policy.CCRules[0] || cfg.Policy.CCRules[0].Enabled || cfg.Body != nil {
				t.Fatal("historical rule silently removed/activated", cfg, err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("migration created a website for an archived policy", err)
			}
			if _, err := s.prepareWAFSettings(manifest.Settings, false); err == nil {
				t.Fatal("version-only migration weakened normal policy edit validation")
			}
		})
	}
}

func TestWAF201FinalPlanRejectsEditAfterHealthCheck(t *testing.T) {
	s, _ := wafLegacy201Fixture(t)
	h, _ := wafFiles(s)
	manifest, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	checks := 0
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "-t" {
			checks++
			if checks == 2 {
				data, err := os.ReadFile(h)
				if err != nil {
					return "", err
				}
				return "", os.WriteFile(h, append(data, []byte("# outside edit after verified health\n")...), 0640)
			}
		}
		return "", nil
	}
	if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err == nil {
		t.Fatal("late external edit adopted as an old migration backup")
	}
	after, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if string(manifest) != string(after) {
		t.Fatal("late edit rejection changed manifest")
	}
	data, _ := os.ReadFile(h)
	if !strings.Contains(string(data), "# outside edit after verified health") {
		t.Fatal("late external edit overwritten")
	}
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		t.Fatal("rejected plan started a durable transaction")
	}
}
