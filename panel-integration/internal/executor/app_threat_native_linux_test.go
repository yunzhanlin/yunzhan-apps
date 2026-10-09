//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func threatIDSNativeQA(t *testing.T) {
	t.Helper()
	if os.Getenv("PANEL_THREAT_IDS_NATIVE_QA") != "1" {
		t.Skip("requires explicit isolated owned VM native companion acceptance")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || strings.TrimSpace(string(host)) != "lima-panel-analytics23s-unit-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-analytics23t-unit-debian13" {
		t.Fatal("native IDS QA cannot run on Main or another user's server")
	}
}
func threatIDSNativePackages(t *testing.T) map[string]string {
	t.Helper()
	data, err := exec.Command("/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n").Output()
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, version, ok := strings.Cut(line, "\t")
		if !ok || name == "" || version == "" {
			t.Fatal("incomplete package snapshot")
		}
		result[name] = version
	}
	return result
}
func threatIDSNativeUnits(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, unit := range []string{"nginx", "panel", "panel-executor", "suricata"} {
		data, err := exec.Command("/usr/bin/systemctl", "show", "--property=LoadState,MainPID,ExecMainStartTimestampMonotonic,ActiveState", unit).Output()
		if err != nil {
			t.Fatal(err)
		}
		result[unit] = string(data)
	}
	return result
}
func TestThreatIDSPrivateRuntimeNativePreparation(t *testing.T) {
	threatIDSNativeQA(t)
	beforePackages := threatIDSNativePackages(t)
	beforeUnits := threatIDSNativeUnits(t)
	if !strings.Contains(beforeUnits["suricata"], "LoadState=not-found\n") {
		t.Fatal("existing system Suricata must not be changed")
	}
	for _, path := range []string{"/etc/suricata", "/etc/systemd/system/panel-network-ids.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("existing IDS host config must not be adopted", path)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := installPrivateThreatIDSRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	service := New(Config{})
	runtime, err := service.threatIDSRuntime()
	if err != nil {
		t.Fatal(err)
	}
	output, err := service.moduleCommand(ctx, 10*time.Second, runtime.Binary, "--build-info")
	if err != nil || !strings.Contains(strings.ToLower(output), "suricata") || !strings.Contains(output, "AF_PACKET") {
		t.Fatal("actual private binary/library probe failed", output, err)
	}
	afterPackages := threatIDSNativePackages(t)
	for name, version := range beforePackages {
		if afterPackages[name] != version {
			t.Fatal("original package removed/upgraded", name, version, afterPackages[name])
		}
	}
	for name, state := range beforeUnits {
		if threatIDSNativeUnits(t)[name] != state {
			t.Fatal("original native service identity changed", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(service.moduleDir("network-threat-detection"), "native-runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if err := installPrivateThreatIDSRuntime(ctx); err != nil {
		t.Fatal("read-only dependency replay", err)
	}
	replay, err := os.ReadFile(filepath.Join(service.moduleDir("network-threat-detection"), "native-runtime.json"))
	if err != nil || sha256.Sum256(replay) != digest {
		t.Fatal("valid runtime replay rewrote source record")
	}
	for _, path := range []string{"/etc/suricata", "/etc/systemd/system/panel-network-ids.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("private preparation installed host service", path)
		}
	}
	t.Log("PASS actual authenticated package/digest/architecture/licenses, private native library probe, unchanged existing package versions and service PIDs; record SHA", hex.EncodeToString(digest[:]))
}
func TestThreatIDSPrivateRuntimeNativePassiveSyntax(t *testing.T) {
	threatIDSNativeQA(t)
	service := New(Config{})
	runtime, err := service.threatIDSRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(appNativeRoot, "network-threat-detection/rules")
	_, existingRules := os.Lstat(rulesDir)
	if existingRules != nil && !os.IsNotExist(existingRules) {
		t.Fatal(existingRules)
	}
	if err := threatIDSTrustedParents(rulesDir, true); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"cloudstack.rules": threatIDSOriginalRules, "LICENSE": threatIDSOriginalRulesLicense, "classification.config": threatIDSOriginalClassifications, "reference.config": threatIDSOriginalReferences} {
		if existingRules == nil {
			path := filepath.Join(rulesDir, name)
			data, e := os.ReadFile(path)
			info, statErr := os.Lstat(path)
			if e != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || ownedRuntimePath(path, false) != nil || string(data) != contents {
				t.Fatal("existing rule evidence differs; preserve rather than overwrite", name)
			}
			continue
		}
		if err := atomicWrite(filepath.Join(rulesDir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	thresholdPath := filepath.Join(rulesDir, "threshold.config")
	if data, err := os.ReadFile(thresholdPath); err == nil {
		if string(data) != "# Original starter rules have no global suppression overrides.\n" || ownedRuntimePath(thresholdPath, false) != nil {
			t.Fatal("existing threshold record differs; preserve")
		}
	} else if os.IsNotExist(err) {
		if err := atomicWrite(thresholdPath, []byte("# Original starter rules have no global suppression overrides.\n"), 0644); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal(err)
	}
	if err := threatIDSTrustedParents("/var/lib/panel-network-ids/logs", true); err != nil {
		t.Fatal(err)
	}
	yaml, err := threatIDSYAML(threatIDSConfig{Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}, filepath.Join(rulesDir, "cloudstack.rules"), "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output, err := service.moduleCommand(ctx, 60*time.Second, runtime.Binary, "--init-errors-fatal", "--strict-rule-keywords", "-v", "-T", "-c", path)
	if err != nil || !strings.Contains(output, "6 rules successfully loaded") || !strings.Contains(output, "0 rules failed") {
		t.Fatal("actual generated passive configuration/rule validation failed", output, err)
	}
	// The positive test must really inspect this exact config. A bad rule
	// supplied only in this private QA directory must fail, not warn-and-run.
	invalid := filepath.Join(dir, "invalid.rules")
	if err = os.WriteFile(invalid, []byte("this is not a valid rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = service.moduleCommand(ctx, 60*time.Second, runtime.Binary, "--init-errors-fatal", "--strict-rule-keywords", "-T", "-c", path, "-S", invalid); err == nil {
		t.Fatal("actual invalid rule silently accepted")
	}
	t.Log("PASS actual private Suricata parsed fixed passive AF_PACKET YAML and original licensed starter rules; no live capture started")
}
