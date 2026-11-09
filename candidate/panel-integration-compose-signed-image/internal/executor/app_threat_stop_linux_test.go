//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const threatIDSFixtureStopPolicy = "FragmentPath=/etc/systemd/system/panel-network-ids.service\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\n"

func TestThreatIDSRuleFeedSafeStopClosedPolicyAndExplicitResumeChoice(t *testing.T) {
	if !threatIDSLoadedStopPolicy(threatIDSFixtureStopPolicy) {
		t.Fatal("closed fixed policy rejected")
	}
	for _, raw := range []string{
		strings.Replace(threatIDSFixtureStopPolicy, "DropInPaths=", "DropInPaths=/run/systemd/system/external.conf", 1),
		strings.Replace(threatIDSFixtureStopPolicy, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1),
		strings.Replace(threatIDSFixtureStopPolicy, "Transient=no", "Transient=yes", 1),
		threatIDSFixtureStopPolicy + "ExecStop=/usr/bin/foreign\n",
		threatIDSFixtureStopPolicy + "ExecStopPost=/usr/bin/foreign\n",
		strings.Replace(threatIDSFixtureStopPolicy, "FragmentPath=/etc/systemd/system/", "FragmentPath=/run/systemd/system/", 1),
		threatIDSFixtureStopPolicy + "ExecStop=\n", threatIDSFixtureStopPolicy + "Unknown=\n",
		strings.Replace(threatIDSFixtureStopPolicy, "DropInPaths=\n", "", 1), strings.Repeat("x", 8193),
	} {
		if threatIDSLoadedStopPolicy(raw) {
			t.Fatal("external or ambiguous loaded policy accepted")
		}
	}
	if !threatIDSEmptyStopCommands("a(sasbttttuii) 0\na(sasbttttuii) 0\n") {
		t.Fatal("two explicit typed empty arrays rejected")
	}
	for _, raw := range []string{"", "a(sasbttttuii) 0", "a(sasbttttuii) 0\na(sasbttttuii) 1", "as 0\nas 0", "a(sasbttttuii) 0\na(sasbttttuii) 0\nunknown", strings.Repeat(" ", 128) + "a(sasbttttuii) 0\na(sasbttttuii) 0"} {
		if threatIDSEmptyStopCommands(raw) {
			t.Fatal("missing, nonempty or ambiguous stop command arrays accepted")
		}
	}
	for _, state := range []string{"inactive", "failed"} {
		if !threatIDSSafeStopIdle("MainPID=0\nActiveState=" + state + "\n") {
			t.Fatal("attested cold service rejected")
		}
	}
	for _, raw := range []string{"MainPID=0\nActiveState=active", "MainPID=2\nActiveState=inactive", "MainPID=00\nActiveState=inactive", "MainPID=0\nActiveState=inactive\nUnknown=", "MainPID=0\nMainPID=0\nActiveState=inactive", "MainPID=0", "", strings.Repeat("x", 4097)} {
		if threatIDSSafeStopIdle(raw) {
			t.Fatal("ambiguous process state accepted")
		}
	}
	for _, active := range []bool{false, true} {
		for _, stopped := range []bool{false, true} {
			for _, requested := range []bool{false, true} {
				state := &threatIDSRecoveryState{WasActive: active, StopRequested: stopped}
				if threatIDSResumeAfterRecovery(state, requested) != (active && !stopped && requested) || state.WasActive != active || state.StopRequested != stopped {
					t.Fatal("later explicit stop lost or original recovery evidence changed")
				}
			}
		}
	}
	if threatIDSResumeAfterRecovery(nil, true) {
		t.Fatal("missing recovery evidence resumes capture")
	}
}

func threatIDSSafeStopFixture(t *testing.T) (*Service, []wafConfigChange, *threatIDSRecoveryState, *string, *string, *int) {
	t.Helper()
	s, changes, state := threatIDSJournalFixture(t)
	pkg, err := parseThreatAPTMetadata("1:7.0.10-1+deb13u4", "amd64", threatAPTFixture)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Architecture = runtime.GOARCH
	pkg.Filename = strings.Replace(pkg.Filename, "_amd64.deb", "_"+runtime.GOARCH+".deb", 1)
	// A native-architecture ELF is only an identity fixture: it is never run
	// as Suricata and does not prove packet capture or native stop behavior.
	elf, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"bin/suricata": elf, "licenses/GPL-2.txt": []byte("fixture GPL identity"), "licenses/suricata-copyright.txt": []byte("fixture copyright identity")}
	v := threatIDSRuntime{Format: 1, Prefix: threatIDSPackagePrefix(pkg), Platform: runtimecatalog.HostPlatform(), Package: pkg, Files: map[string]string{}}
	base := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix))
	for name, data := range files {
		path := filepath.Join(base, name)
		if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if name == "bin/suricata" {
			mode = 0755
		}
		if err := atomicWrite(path, data, mode); err != nil {
			t.Fatal(err)
		}
		v.Files[name] = core.Hash(string(data))
	}
	for _, path := range []string{filepath.Join(base, "runtime-manifest.json"), filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json")} {
		if err := moduleWrite(path, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := moduleWrite(filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json"), threatIDSAccount{Format: 1, UID: 800, GID: 801}); err != nil {
		t.Fatal(err)
	}
	guard := "/opt/panel/current/bin/panel-executor"
	unit, e1 := threatIDSGatedUnit(v.Prefix, guard)
	recovery, e2 := threatIDSRecoveryUnit(guard)
	syntax, e3 := threatIDSSyntaxUnit(v.Prefix)
	if e1 != nil || e2 != nil || e3 != nil {
		t.Fatal(e1, e2, e3)
	}
	for name, data := range map[string]string{"panel-network-ids.service": unit, "panel-network-ids-recover.service": recovery, "panel-network-ids-check.service": syntax} {
		path := s.systemPath("/etc/systemd/system/" + name)
		if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := moduleWrite(filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json"), threatIDSUnitRecord{Format: 1, Prefix: v.Prefix, Guard: guard, UnitSHA: core.Hash(unit), RecoverySHA: core.Hash(recovery)}); err != nil {
		t.Fatal(err)
	}
	state.UnitSHA = core.Hash(unit)
	state.RuntimeRecordSHA, err = nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
	if err != nil {
		t.Fatal(err)
	}
	policy, current, stops := threatIDSFixtureStopPolicy, "ActiveState=inactive\nMainPID=0\n", 0
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "/usr/bin/getent passwd panel-network-ids":
			return "panel-network-ids:x:800:801::/nonexistent:/usr/sbin/nologin\n", nil
		case "/usr/bin/getent group panel-network-ids":
			return "panel-network-ids:x:801:\n", nil
		case "/usr/bin/id -G panel-network-ids":
			return "801\n", nil
		case "/usr/bin/systemctl show --all panel-network-ids.service --property=FragmentPath,DropInPaths,Transient,NeedDaemonReload":
			return policy, nil
		case "/usr/bin/busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/panel_2dnetwork_2dids_2eservice org.freedesktop.systemd1.Service ExecStop ExecStopPost":
			return "a(sasbttttuii) 0\na(sasbttttuii) 0\n", nil
		case "/usr/bin/systemctl show panel-network-ids.service --property=ActiveState,MainPID":
			return current, nil
		case "/usr/bin/systemctl stop panel-network-ids.service":
			stops++
			return "", nil
		default:
			return "", errors.New("fixture rejects unexpected command: " + name + " " + strings.Join(args, " "))
		}
	}
	return s, changes, state, &policy, &current, &stops
}

func TestThreatIDSRuleFeedSafeStopPreservesDamagedDataAndPendingEvidence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires actual Linux root private fixture, never host-native proof")
	}
	t.Run("damaged-yaml-and-original-rules", func(t *testing.T) {
		s, _, _, policy, current, stops := threatIDSSafeStopFixture(t)
		path := s.threatIDSConfigurationPaths()[0]
		damaged := []byte("private fixture damaged YAML; do not rewrite\n")
		if err := atomicWrite(path, damaged, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.threatIDSImmutable(context.Background()); err == nil {
			t.Fatal("fixture unexpectedly has trusted original rules")
		}
		if value, err := s.stopAttestedThreatIDS(context.Background(), 0); err == nil || value != nil || *stops != 0 {
			t.Fatal("unknown revision bypassed readable revision")
		}
		original := *policy
		*policy = original + "ExecStop=/usr/bin/foreign\n"
		if value, err := s.stopAttestedThreatIDS(context.Background(), 1); err == nil || value != nil || *stops != 0 {
			t.Fatal("foreign loaded stop policy dispatched")
		}
		*policy = original
		result, err := s.stopAttestedThreatIDS(context.Background(), 1)
		if err != nil || result == nil || *stops != 1 {
			t.Fatal("damaged data blocked attested idle stop", result, err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || string(actual) != string(damaged) {
			t.Fatal("stop rewrote damaged data", err)
		}
		*current = "ActiveState=failed\nMainPID=0\n"
		if value, err := s.stopAttestedThreatIDS(context.Background(), 1); err == nil || value != nil || *stops != 2 {
			t.Fatal("non-inactive postcondition falsely reported success")
		}
	})
	t.Run("unreadable-record-only-explicit-zero", func(t *testing.T) {
		s, _, _, _, _, stops := threatIDSSafeStopFixture(t)
		path := s.threatIDSConfigurationPaths()[1]
		damaged := []byte("private fixture broken record\n")
		if err := atomicWrite(path, damaged, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.stopAttestedThreatIDS(context.Background(), 1); err == nil || *stops != 0 {
			t.Fatal("stale readable revision bypassed corrupt record")
		}
		result, err := s.stopAttestedThreatIDS(context.Background(), 0)
		if err != nil || *stops != 1 || result.(map[string]any)["configuration_revision_known"] != false {
			t.Fatal("unknown revision stop not explicit", result, err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || string(actual) != string(damaged) {
			t.Fatal("stop fabricated a repaired record", err)
		}
	})
	t.Run("pending-explicit-stop-does-not-resume", func(t *testing.T) {
		s, changes, state, _, _, stops := threatIDSSafeStopFixture(t)
		state.WasActive = true
		if _, err := s.startWAFTransactionState(changes, state); err != nil {
			t.Fatal(err)
		}
		if _, err := s.stopAttestedThreatIDS(context.Background(), 1); err != nil || *stops != 1 {
			t.Fatal("pending config blocked explicit stop", err)
		}
		pending, err := s.readWAFTransaction()
		if err != nil || !pending.IDS.StopRequested || !pending.IDS.WasActive || threatIDSResumeAfterRecovery(pending.IDS, true) {
			t.Fatal("pending stop lost original activity or resumes", pending, err)
		}
		before, err := os.ReadFile(s.wafPendingPath())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.stopAttestedThreatIDS(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(s.wafPendingPath())
		if err != nil || string(after) != string(before) {
			t.Fatal("idempotent stop rewrote original pending evidence", err)
		}
		for _, change := range changes {
			matches, err := s.wafCurrentMatches(change, false)
			if err != nil || !matches {
				t.Fatal("explicit stop changed pending files/mode/owner", err)
			}
		}
		var decoded wafTransaction
		if json.Unmarshal(after, &decoded) != nil || decoded.IDS.UnitSHA != state.UnitSHA || decoded.IDS.RuntimeRecordSHA != state.RuntimeRecordSHA {
			t.Fatal("pending source binding changed")
		}
	})
}

func TestThreatIDSRecoveryStopDoesNotCancelIdleBootJobOrAdoptUnknownSource(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires actual Linux root private fixture, never host-native proof")
	}
	for _, restore := range []bool{false, true} {
		for _, active := range []string{"inactive", "failed"} {
			t.Run(active+"-restore-"+strconv.FormatBool(restore), func(t *testing.T) {
				s, changes, recovery, _, state, stops := threatIDSSafeStopFixture(t)
				runtime, account, _, err := s.threatIDSIdentity(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				*state = "ActiveState=" + active + "\nMainPID=0\n"
				if err := s.threatIDSRecoveryStopCapture(context.Background(), runtime, account, restore); err != nil || *stops != 0 {
					t.Fatal("idle recovery cancelled dependent boot job", err, *stops)
				}
				if recovery.StopRequested {
					t.Fatal("recovery invented an explicit user stop")
				}
				for _, change := range changes {
					if matches, err := s.wafCurrentMatches(change, false); err != nil || !matches {
						t.Fatal("read-only stop decision rewrote config or ownership", err)
					}
				}
			})
		}
	}
	for _, raw := range []string{
		"", "MainPID=0", "ActiveState=inactive\nMainPID=00\n",
		"ActiveState=inactive\nMainPID=0\nMainPID=0\n",
		"ActiveState=inactive\nMainPID=0\nUnknown=\n",
		"ActiveState=activating\nMainPID=0\n",
		"ActiveState=active\nMainPID=2\n",
		"ActiveState=active\nMainPID=02\n",
		"ActiveState=inactive\nMainPID=2\n",
	} {
		for _, restore := range []bool{false, true} {
			s, _, _, _, state, stops := threatIDSSafeStopFixture(t)
			runtime, account, _, err := s.threatIDSIdentity(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			*state = raw
			if err := s.threatIDSRecoveryStopCapture(context.Background(), runtime, account, restore); err == nil || *stops != 0 {
				t.Fatal("ambiguous state or unverified live process authorized recovery stop", raw, restore, err)
			}
		}
	}
	s, _, _, policy, _, stops := threatIDSSafeStopFixture(t)
	runtime, account, _, err := s.threatIDSIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	*policy = strings.Replace(*policy, "DropInPaths=", "DropInPaths=/run/systemd/system/foreign.conf", 1)
	if err := s.threatIDSRecoveryStopCapture(context.Background(), runtime, account, false); err == nil || *stops != 0 {
		t.Fatal("idle recovery adopted foreign loaded stop policy", err)
	}
}
