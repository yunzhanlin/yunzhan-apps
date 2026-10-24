//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func intrusionPendingObservationFixture(t *testing.T) (*Service, map[string]string, *int, *os.File, intrusionJournalPlan, []byte) {
	return intrusionPendingObservationFixtureWithSetup(t, nil)
}

func intrusionPendingObservationFixtureWithSetup(t *testing.T, setup func(*Service, map[string]string, *intrusionJournalPlan)) (*Service, map[string]string, *int, *os.File, intrusionJournalPlan, []byte) {
	t.Helper()
	s, answers, calls := intrusionRuntimeFixture(t)
	p := intrusionJournalFixture(t)
	jail, err := s.intrusionConfigObservation()
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.softwareManifestDirectory()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hardeningReadBackup(root, "intrusion-prevention.json", s.softwareManifestPath("intrusion-prevention"), true)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	p.Files[0].Before = hardeningJournalFromBackup(jail)
	p.Files[1].Before = hardeningJournalFromBackup(manifest)
	p.ConfigurationBefore, err = s.readIntrusionConfigurationTree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.StartedAt = core.Now()
	p.KernelBefore = []byte(answers["/usr/sbin/nft -j list table inet f2b-table"])
	p.BansBefore = []string{}
	if err = json.Unmarshal([]byte(answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"]), &p.ActionBefore); err != nil {
		t.Fatal(err)
	}
	boot := s.systemPath("/proc/sys/kernel/random/boot_id")
	if err = os.MkdirAll(filepath.Dir(boot), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(boot, []byte(p.BootID+"\n"), 0444); err != nil {
		t.Fatal(err)
	}
	answers["/usr/sbin/sshd -T"] = "port 2882\npasswordauthentication no\n"
	answers["/usr/bin/ss -H -ltnp"] = "LISTEN 0 128 0.0.0.0:2882 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\n"
	if setup != nil {
		setup(s, answers, &p)
	}
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	raw, err := s.intrusionJournalPrepare(lock, p)
	if err != nil {
		t.Fatal(err)
	}
	return s, answers, calls, lock, p, raw
}

func TestIntrusionPendingObservationAloneMayReadIndependentOriginalActionAndKernelPorts(t *testing.T) {
	for _, kind := range []string{"action-after-kernel-before", "action-before-kernel-after"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, _, lock, p, raw := intrusionPendingObservationFixture(t)
			if kind == "action-after-kernel-before" {
				answers["/usr/bin/fail2ban-client get sshd action nftables port"] = "2882\n"
				answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = strings.ReplaceAll(intrusionObservedLazyStart, "'22'", "'2882'")
				policy := p.BeforePolicy
				policy.Ports = []int{2882}
				answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionActionRecipeFixture(t, policy)
			} else {
				answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, []int{2882})
			}
			if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil {
				t.Fatal("ordinary observation silently admitted mixed ports")
			}
			out, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw)
			if err != nil || out.KernelState != "rules_observed" || slices.Equal(out.Policy.Ports, out.KernelScopePorts) || len(out.KernelIdentity) != 64 {
				t.Fatal("bound original recovery observation refused", out, err)
			}
			_, record, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(record, raw) {
				t.Fatal("read-only recovery observation repaired original record", err)
			}
		})
	}
}

func TestIntrusionPendingObservationRejectsMissingLockIdentityOrBootBeforeRuntimeReads(t *testing.T) {
	for _, kind := range []string{"lock", "raw", "id", "boot", "missing-pending"} {
		t.Run(kind, func(t *testing.T) {
			s, _, calls, lock, p, raw := intrusionPendingObservationFixture(t)
			before := *calls
			switch kind {
			case "lock":
				lock = nil
			case "raw":
				raw = append(bytes.Clone(raw), ' ')
			case "id":
				p.ID = core.ID()
			case "boot":
				if err := os.Chmod(s.systemPath("/proc/sys/kernel/random/boot_id"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.systemPath("/proc/sys/kernel/random/boot_id"), []byte("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"), 0444); err != nil {
					t.Fatal(err)
				}
			case "missing-pending":
				if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw); err == nil || *calls != before {
				t.Fatal("unbound pending record reached actual runtime reader", err, *calls-before)
			}
		})
	}
}

func TestIntrusionPendingObservationCannotAdoptThirdPortLimitOrChangedSSH(t *testing.T) {
	for _, kind := range []string{"port", "limit", "ssh"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, _, lock, p, raw := intrusionPendingObservationFixture(t)
			switch kind {
			case "port":
				answers["/usr/bin/fail2ban-client get sshd action nftables port"] = "2222\n"
				answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = strings.ReplaceAll(intrusionObservedLazyStart, "'22'", "'2222'")
				policy := p.BeforePolicy
				policy.Ports = []int{2222}
				answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionActionRecipeFixture(t, policy)
			case "limit":
				answers["/usr/bin/fail2ban-client get sshd maxretry"] = "7\n"
			case "ssh":
				answers["/usr/sbin/sshd -T"] = "port 3333\n"
				answers["/usr/bin/ss -H -ltnp"] = "LISTEN 0 128 0.0.0.0:3333 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\n"
			}
			if _, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw); err == nil {
				t.Fatal("third-party state adopted")
			}
		})
	}
}

func TestIntrusionPendingObservationRechecksOriginalRecordAfterIndependentSamples(t *testing.T) {
	s, _, _, lock, p, raw := intrusionPendingObservationFixture(t)
	run := s.Config.Run
	changed := false
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		result, err := run(ctx, name, args...)
		if !changed && name == "/usr/sbin/nft" {
			if err := os.WriteFile(filepath.Join(s.Config.SecurityDir, intrusionPendingName), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		return result, err
	}
	if _, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw); err == nil || !changed {
		t.Fatal("concurrent record replacement admitted")
	}
	actual, err := os.ReadFile(filepath.Join(s.Config.SecurityDir, intrusionPendingName))
	if err != nil || string(actual) != "{}\n" {
		t.Fatal("foreign record repaired", err)
	}
}
