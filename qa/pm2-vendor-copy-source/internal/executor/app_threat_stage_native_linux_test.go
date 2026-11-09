//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestThreatIDSPrivateRuntimeSupportedCandidateStagingPreservesCapture(t *testing.T) {
	threatIDSNativeQA(t)
	if os.Getenv("PANEL_THREAT_IDS_NATIVE_STAGE_QA") != "1" {
		t.Skip("explicit download/staging-only candidate acceptance required")
	}
	s := New(Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	nativeLock, err := threatIDSPrepareLock(s.moduleDir("network-threat-detection"))
	if err != nil {
		t.Fatal(err)
	}
	defer nativeLock.Close()
	configLock, err := s.threatIDSTransactionService().lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer configLock.Close()
	state, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		t.Fatal("owned capture must remain stopped", state, err)
	}
	old, account, _, err := s.threatIDSImmutable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json"), filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json"), filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json"), s.threatIDSRotationPath(), "/etc/panel/network-ids/suricata.yaml", "/etc/systemd/system/panel-network-ids.service", "/etc/systemd/system/panel-network-ids-recover.service", "/etc/systemd/system/panel-network-ids-check.service", "/var/lib/panel-network-ids/logs/eve.json"}
	snapshot := func() map[string]string {
		out := map[string]string{}
		for _, p := range paths {
			if p == "/var/lib/panel-network-ids/logs/eve.json" {
				f, _, err := s.openThreatIDSLiveFile(account)
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
				f.Close()
				if err != nil || len(b) > 8<<20 {
					t.Fatal("live output snapshot", err)
				}
				out[p] = core.Hash(string(b))
				continue
			}
			v, e := nfsFileDigest(p, 8<<20)
			if e != nil {
				t.Fatal(e)
			}
			out[p] = v
		}
		return out
	}
	before, beforeUnits, beforePackages := snapshot(), threatIDSNativeUnits(t), threatIDSNativePackages(t)
	var candidate threatIDSRuntime
	if err := s.stagePrivateThreatIDSRuntime(ctx, &candidate); err != nil {
		t.Fatal(err)
	}
	if (candidate.Format != 2 && candidate.Format != 3) || candidate.Source == nil || candidate.Prefix == old.Prefix || threatIDSRequireSupported(candidate.Package.Version) != nil {
		t.Fatal("candidate provenance/security floor missing", candidate)
	}
	if _, err := s.validateThreatIDSRuntime(candidate); err != nil {
		t.Fatal(err)
	}
	if err := s.probeThreatIDSRuntime(ctx, candidate); err != nil {
		t.Fatal("actual candidate ABI/build probe failed", err)
	}
	if !reflect.DeepEqual(before, snapshot()) || !reflect.DeepEqual(beforeUnits, threatIDSNativeUnits(t)) {
		t.Fatal("staging mutated live source/config/account/unit/output or original service")
	}
	afterPackages := threatIDSNativePackages(t)
	for name, version := range beforePackages {
		if afterPackages[name] != version {
			t.Fatal("original package upgraded or removed", name)
		}
	}
	active, err := s.threatIDSRuntime()
	if err != nil || active.Prefix != old.Prefix {
		t.Fatal("candidate activated during staging", active, err)
	}
	b, _ := json.Marshal(candidate)
	t.Log("PASS real authenticated supported candidate staged without activation/capture; runtime", string(b))
}
