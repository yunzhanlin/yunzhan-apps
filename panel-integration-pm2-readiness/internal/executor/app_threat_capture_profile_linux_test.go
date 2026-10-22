//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
)

func TestThreatIDSLegacyCaptureStartGateDoesNotTouchConfigurationOrService(t *testing.T) {
	root := t.TempDir()
	service := New(Config{SystemRoot: root, SecurityDir: root + "/security", Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("legacy start gate ran a command")
		return "", nil
	}})
	in := threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}}
	if err := service.threatIDSAuthorizeConfiguration(in); err == nil || !strings.Contains(err.Error(), "旧单块") {
		t.Fatal("legacy gate did not reject before native state lookup", err)
	}
	if _, err := os.Lstat(service.Config.SecurityDir); !os.IsNotExist(err) {
		t.Fatal("legacy start gate mutated state", err)
	}
}

func TestThreatIDSStoredCaptureMTUDriftRejectsBeforeStart(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil || iface.Flags&net.FlagUp == 0 {
		t.Fatal("Linux loopback fixture unavailable", err)
	}
	in := threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}, CaptureFormat: 1, CaptureMTU: iface.MTU}
	if err := threatIDSCheckInterface(in); err != nil {
		t.Fatal("native unchanged MTU rejected", err)
	}
	in.CaptureMTU--
	if err := threatIDSCheckInterface(in); err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatal("drifted MTU was accepted", err)
	}
}

func TestThreatIDSLegacyToMultiBlockJournalRollsBackExactOriginalBytes(t *testing.T) {
	s, plan, state := threatIDSJournalFixture(t)
	var next threatIDSConfig
	if err := json.Unmarshal(plan[1].NextData, &next); err != nil {
		t.Fatal(err)
	}
	next.CaptureFormat, next.CaptureMTU = 1, 1500
	yaml, err := threatIDSYAML(next, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	plan[0].NextData = []byte(yaml)
	plan[1].NextData, err = json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.startWAFTransactionState(plan, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := wafApplyChange(tx.Changes[0], true); err != nil {
		t.Fatal(err)
	}
	restored, err := s.recoverWAFTransaction()
	if err != nil || !restored {
		t.Fatal("mixed generation did not restore", restored, err)
	}
	for _, change := range tx.Changes {
		matches, err := s.wafCurrentMatches(change, false)
		if err != nil || !matches {
			t.Fatal("legacy generation was relabelled or partially restored", err)
		}
	}
	old, err := s.threatIDSConfig()
	if err != nil || old.CaptureFormat != 0 || old.CaptureMTU != 0 {
		t.Fatal("old record changed", old, err)
	}
	if err := threatIDSRequireCurrentCapture(old); err == nil {
		t.Fatal("rollback silently enabled legacy capture")
	}
}
