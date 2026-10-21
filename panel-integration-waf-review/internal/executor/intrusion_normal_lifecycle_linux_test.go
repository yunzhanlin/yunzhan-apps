//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestIntrusionNormalStatusNeverCertifiesPartialRemoval(t *testing.T) {
	s, lock, p, raw, d, _ := intrusionAdvanceFixtureWithSetup(t, func(_ *Service, p *intrusionJournalPlan) { intrusionRemovalPlanSetup(t, p, []int{22}) })
	for _, slot := range []int{0, 1, 2} {
		if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, slot, "committed"); err != nil {
			t.Fatal(err)
		}
	}
	lock.Close()
	before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
	writes := []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}
	status := s.softwareStatus(context.Background(), "intrusion-prevention")
	if !status.StateUnknown || status.Installed || status.Healthy || status.Settings != nil {
		t.Fatal("partial removal certified", status)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/intrusion-prevention/inspection", nil))
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"state_unknown":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) || !reflect.DeepEqual(writes, []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}) {
		t.Fatal("status mutated original")
	}
}

func TestIntrusionUnbanCannotRacePendingOrExclusiveOwner(t *testing.T) {
	for _, kind := range []string{"pending-sshd", "pending-other", "exclusive-busy"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, _, raw, _, _ := intrusionAdvanceFixture(t)
			if kind != "exclusive-busy" {
				lock.Close()
			}
			before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
			jail := "sshd"
			if kind == "pending-other" {
				jail = "other"
			}
			body := `{"jail":"` + jail + `","ip":"192.0.2.8"}`
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/security/fail2ban/unban", strings.NewReader(body)))
			if w.Code != 409 {
				t.Fatal("manual unban crossed transaction", w.Code, w.Body.String())
			}
			_, again, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(raw, again) || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) {
				t.Fatal("unban altered original evidence", err)
			}
		})
	}
}

func TestIntrusionNormalRoutesRequireOriginalJobAndExactSignedVersion(t *testing.T) {
	for _, item := range []struct {
		action, job, version string
		code                 int
	}{
		{"install", "", "1.1.0", 400}, {"configure", "foreign", "", 400}, {"uninstall", "", "", 400}, {"recover", "", "", 400},
		{"install", core.ID(), "1.0", 409}, {"install", core.ID(), "1.1.0-alias", 409}, {"update", core.ID(), "1.1.0-alias", 409},
	} {
		t.Run(item.action+"/"+item.version+"/"+item.job, func(t *testing.T) {
			s, _, calls := intrusionInspectionFixture(t)
			before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
			raw, _ := json.Marshal(map[string]any{"settings": map[string]any{}, "version": item.version, "job_id": item.job})
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/software/intrusion-prevention/"+item.action, bytes.NewReader(raw)))
			if w.Code != item.code || *calls != 0 || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) {
				t.Fatal("refused normal route changed state", w.Code, w.Body.String(), *calls)
			}
		})
	}
}

func TestIntrusionNormalRecoveryClosesExactOriginalWithoutReplayingCommands(t *testing.T) {
	s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
	lock.Close()
	beforeFiles, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"job_id": core.ID(), "version": "", "settings": map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}})
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/software/intrusion-prevention/recover", bytes.NewReader(request)))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"recovered"`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(d.Scalars) != 0 || len(d.Templates) != 0 || d.Applies != 0 {
		t.Fatal("already-before recovery replayed mutations")
	}
	after, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range after {
		if !hardeningBackupSame(beforeFiles[i], after[i]) {
			t.Fatal("recovery rewrote original unchanged files")
		}
	}
	if _, _, err := s.intrusionJournalPending(); !os.IsNotExist(err) {
		t.Fatal("original latch not closed", err)
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil || len(inventory.Records) != 1 || inventory.Records[p.ID].State != "rolled_back" {
		t.Fatal(inventory, err)
	}
}

func TestIntrusionNormalRouteRejectsDuplicateAndExtraAuthorityBeforeCommands(t *testing.T) {
	id := core.ID()
	for _, body := range []string{
		`{"settings":{},"version":"","job_id":"` + id + `","job_id":"` + core.ID() + `"}`,
		`{"settings":{},"version":"","job_id":"` + id + `","Job_ID":"` + core.ID() + `"}`,
		`{"settings":{"transaction_id":"` + id + `","plan_sha256":"` + strings.Repeat("a", 64) + `","plan_sha256":"` + strings.Repeat("b", 64) + `"},"version":"","job_id":"` + core.ID() + `"}`,
		`{"settings":{},"version":"","job_id":"` + id + `","script":"root"}`,
		`{"settings":{},"version":"","job_id":"` + id + `"}` + strings.Repeat(" ", 4096),
	} {
		s, _, calls := intrusionInspectionFixture(t)
		before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/software/intrusion-prevention/recover", strings.NewReader(body)))
		if w.Code != 400 || *calls != 0 || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) {
			t.Fatal("ambiguous internal authority executed", w.Code, w.Body.String())
		}
	}
}

func TestIntrusionInspectionManagedPolicyKeepsCapacityAndRefusesFallback(t *testing.T) {
	for _, kind := range []string{"consistent", "capacity-drift", "missing-policy", "legacy-jail", "policy-changed"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			manifest, err := s.readSoftwareManifest("intrusion-prevention")
			if err != nil {
				t.Fatal(err)
			}
			manifest.Version = intrusionTransactionVersion
			if err = s.writeSoftwareManifest(manifest); err != nil {
				t.Fatal(err)
			}
			// Use the fixed independently declared fixture identity; no helper may
			// invent or mutate live values to make the persisted policy agree.
			policy := intrusionManagedPolicy{Format: 1, Action: "nftables", Name: "probe_sshd", Table: "f2b-table", Chain: "f2b-chain", IPv4Set: "addr-set-probe_sshd", IPv6Set: "addr6-set-probe_sshd", Ports: []int{22}, MaxMatches: 5}
			policyPath := filepath.Join(s.Config.SecurityDir, intrusionPolicyName)
			encoded, err := intrusionJournalEncode(policy)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(policyPath, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			jail, err := renderIntrusionManagedScope(manifest.Settings, policy)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(s.intrusionJournalPaths()[0], []byte(jail), 0644); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "capacity-drift":
				answers["/usr/bin/fail2ban-client get sshd maxmatches"] = "9\n"
			case "missing-policy":
				if err = os.Remove(policyPath); err != nil {
					t.Fatal(err)
				}
			case "legacy-jail":
				if err = os.WriteFile(s.intrusionJournalPaths()[0], []byte(renderIntrusion(manifest.Settings)), 0644); err != nil {
					t.Fatal(err)
				}
			case "policy-changed":
				run := s.Config.Run
				s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
					v, e := run(ctx, name, args...)
					if name == "/usr/sbin/nft" {
						changed := policy
						changed.MaxMatches = 8
						r, _ := intrusionJournalEncode(changed)
						if err := atomicWrite(policyPath, r, 0600); err != nil {
							t.Fatal(err)
						}
					}
					return v, e
				}
			}
			out, err := s.inspectIntrusion(context.Background())
			if kind == "consistent" {
				if err != nil || !out.Healthy || !out.ConfigMatches {
					t.Fatal(out, err)
				}
			} else if out.Healthy || err == nil && len(out.Warnings) == 0 {
				t.Fatal("unqualified1.1 adopted old defaults", kind, out, err)
			}
		})
	}
}
