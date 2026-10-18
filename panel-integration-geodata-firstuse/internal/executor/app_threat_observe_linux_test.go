//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreatIDSReportClosedInputAndNoPreparationSideEffects(t *testing.T) {
	root := t.TempDir()
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("read-only absent-runtime report invoked a command")
		return "", errors.New("unexpected command")
	}})
	for _, in := range []core.AppModuleInput{
		{Severity: "0"}, {Severity: "01"}, {Severity: "5"}, {Severity: ";id"},
		{FromTime: "2026-10-09T11:00:00"}, {ToTime: "2101-01-01T00:00:00Z"},
		{FromTime: "2026-10-09T01:00:01Z", ToTime: "2026-10-09T01:00:00Z"},
		{Limit: 201}, {Offset: 20001}, {Search: "x\nUser=root"},
	} {
		if _, err := s.moduleThreatIDSReport(context.Background(), in); err == nil {
			t.Fatal("unsafe report input accepted", in)
		}
	}
	for _, severity := range []string{"", "1", "2", "3", "4"} {
		v, err := s.moduleThreatIDSReport(context.Background(), core.AppModuleInput{Severity: severity, FromTime: "2026-10-09T11:00:00+08:00", Limit: 1})
		if err != nil || v.(threatIDSObservation).State != "not-prepared" {
			t.Fatal(v, err)
		}
	}
	if _, err := os.Lstat(s.Config.SecurityDir); !os.IsNotExist(err) {
		t.Fatal("read-only report prepared directories", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readThreatEVE(ctx, strings.NewReader(""), threatEVEFilter{}, false); !errors.Is(err, context.Canceled) {
		t.Fatal("empty stream swallowed cancellation", err)
	}
}

func TestThreatIDSServicePrepareRequiresExplicitIntentAndKeepsCaptureOff(t *testing.T) {
	root := t.TempDir()
	calls := 0
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), Run: func(ctx context.Context, name string, args ...string) (string, error) {
		calls++
		if name != "/usr/bin/systemctl" || strings.Join(args, " ") != "start --no-block panel-app-dependencies@network-threat-detection" {
			t.Fatal("unexpected service mutation", name, args)
		}
		return "", nil
	}})
	if _, err := s.moduleThreatIDSControl(context.Background(), "ids-prepare", core.AppModuleInput{}); err == nil || calls != 0 {
		t.Fatal("silent preparation allowed", err, calls)
	}
	value, err := s.moduleThreatIDSControl(context.Background(), "ids-prepare", core.AppModuleInput{PrepareIDS: true})
	if err != nil || calls != 1 || value.(map[string]any)["capture_started"] != false {
		t.Fatal(value, err, calls)
	}
	if _, err := os.Lstat(s.Config.SecurityDir); !os.IsNotExist(err) {
		t.Fatal("dependency dispatch created configuration", err)
	}
}

func TestThreatIDSObservedStatusRefusesMissingDuplicateAndPrivilegeWidening(t *testing.T) {
	v := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	status := "Name:\tsuricata\nUid:\t800\t800\t800\t800\nGid:\t801\t801\t801\t801\nCapInh:\t0000000000002000\nCapPrm:\t0000000000002000\nCapEff:\t0000000000002000\nCapBnd:\t0000000000002000\nCapAmb:\t0000000000002000\nNoNewPrivs:\t1\n"
	if !threatIDSProcessStatus([]byte(status), v) {
		t.Fatal("bounded non-root status rejected")
	}
	for _, bad := range []string{strings.Replace(status, "800", "0", 1), strings.Replace(status, "801", "0", 1), strings.Replace(status, "0000000000002000", "0000000000003000", 1), strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), status + "Uid:\t800\t800\t800\t800\n", strings.Replace(status, "CapAmb:\t0000000000002000\n", "", 1)} {
		if threatIDSProcessStatus([]byte(bad), v) {
			t.Fatal("wider/missing privilege status accepted")
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		line := key + ":\t0000000000002000\n"
		for _, invalid := range []string{"", key + ":\t0000000000003000\n", key + ":\t0000000000000000\n", key + ":\t2000\n", key + ":\t0000000000002000junk\n", line + line} {
			t.Run(key+"/"+strings.TrimSpace(invalid), func(t *testing.T) {
				if threatIDSProcessStatus([]byte(strings.Replace(status, line, invalid, 1)), v) {
					t.Fatal("missing, duplicate, changed or noncanonical kernel capability set accepted", key)
				}
			})
		}
	}
	valid := "LoadState=loaded\nActiveState=inactive\nMainPID=0\nExecMainStartTimestampMonotonic=0\nUser=panel-network-ids\nGroup=panel-network-ids\nMemoryMax=402653184\nMemorySwapMax=0\nTasksMax=32\nLimitFSIZE=8388608\nProtectSystem=strict\nNoNewPrivileges=yes\nCapabilityBoundingSet=cap_net_raw\nAmbientCapabilities=cap_net_raw\n"
	if _, err := threatIDSUnitValues(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", valid + "MainPID=42\n", valid + "Unreviewed=thing\n", strings.Replace(valid, "MemorySwapMax=0\n", "", 1), valid + strings.Repeat("x", 32<<10)} {
		if _, err := threatIDSUnitValues(bad); err == nil {
			t.Fatal("malformed state accepted")
		}
	}
	root := t.TempDir()
	service := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security")})
	if out := service.observeThreatIDS(context.Background(), threatEVEFilter{}); out.State != "not-prepared" || out.RuntimeReady || out.ProcessVerified || out.Configuration != nil || len(out.Report.Alerts) != 0 {
		t.Fatal("absent runtime fabricated observation", out)
	}
	if out := service.observeThreatIDS(context.Background(), threatEVEFilter{Limit: 201}); out.State != "invalid-filter" || out.Error == "" {
		t.Fatal("invalid query widened", out)
	}
}

func TestThreatIDSObservedPrivateOutputIdentityAndResourceBounds(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual ownership fixture requires Linux root; pure parsers are separate")
	}
	root := t.TempDir()
	service := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security")})
	dir := filepath.Join(root, "var/lib/panel-network-ids/logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 800, 801); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "eve.json")
	body := threatEVEFixture("2026-10-09T01:00:01Z", 1, 9000001) + "\n"
	write := func() {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 800, 801); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	v := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	if out, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err != nil || len(out.Alerts) != 1 {
		t.Fatal(out, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("public event output accepted")
	}
	write()
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("foreign event owner accepted")
	}
	write()
	if err := os.Link(path, path+".second"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("hard-linked event output accepted")
	}
	if err := os.Remove(path + ".second"); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, threatEVEByteLimit+1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("oversized actual event file read")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("linked event path accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	write()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := service.readThreatIDSFile(context.Background(), v, threatEVEFilter{}); err == nil {
		t.Fatal("public log directory accepted")
	}
}

func TestThreatIDSPrivateRuntimeNativePassiveObservation(t *testing.T) {
	threatIDSNativeQA(t)
	beforeUnits := threatIDSNativeUnits(t)
	beforePackages := threatIDSNativePackages(t)
	service := New(Config{})
	var owner struct {
		Format         int    `json:"format"`
		UID            string `json:"uid"`
		GID            string `json:"gid"`
		FailedProofSHA string `json:"failed_proof_sha256"`
	}
	b, err := ftpPrivateRead("/var/lib/panel-network-ids/qa-account-ownership.json", 2048)
	if err != nil || decodeFTPPrivateJSON(b, &owner) != nil || owner.Format != 1 || owner.UID != "988" || owner.GID != "982" || owner.FailedProofSHA != "7851ccf2739c2e5f1af5988a0280440416f49ff58709264c02430dd96b3f82d4" {
		t.Fatal("native observer requires exact own retained capture fixture", err)
	}
	for name, value := range map[string]any{"capture-account.json": threatIDSAccount{Format: 1, UID: 988, GID: 982}, "ids-config.json": threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}} {
		path := filepath.Join(service.moduleDir("network-threat-detection"), name)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("retain existing observation record", path)
		}
		if err := moduleWrite(path, value); err != nil {
			t.Fatal(err)
		}
	}
	first := service.observeThreatIDS(context.Background(), threatEVEFilter{Limit: 200})
	if first.State != "not-running" || first.Error != "" || !first.RuntimeReady || first.ProcessVerified || len(first.Report.Alerts) != 5 {
		t.Fatal("actual stopped fixture not reported accurately", first)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/bin/systemctl", "stop", "panel-network-ids").CombinedOutput(); err != nil {
			t.Errorf("own observation stop %s %v", out, err)
		}
	})
	if out, err := exec.Command("/usr/bin/systemctl", "start", "panel-network-ids").CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var initial threatIDSObservation
	for time.Now().Before(deadline) {
		initial = service.observeThreatIDS(context.Background(), threatEVEFilter{})
		if initial.ProcessVerified {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if initial.State != "unknown" || !initial.ProcessVerified || initial.StartedAt == "" || initial.Error != "" {
		t.Fatal("previous start counters reused as healthy", initial)
	}
	deadline = time.Now().Add(12 * time.Second)
	var observed threatIDSObservation
	for time.Now().Before(deadline) {
		observed = service.observeThreatIDS(context.Background(), threatEVEFilter{Severity: 1, Search: "scanner", Limit: 1})
		if observed.State == "observing" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if observed.State != "observing" || observed.Error != "" || !observed.ProcessVerified || len(observed.Report.Alerts) != 1 || observed.Report.Alerts[0].SignatureID != 9000003 || observed.Report.MatchingAlerts != 1 {
		t.Fatal("actual observing/filter metadata wrong", observed)
	}
	encoded, _ := json.Marshal(observed)
	if strings.Contains(string(encoded), "IDS_PRIVATE_SENTINEL_") || strings.Contains(string(encoded), "request_headers") || strings.Contains(string(encoded), "fixture.invalid") {
		t.Fatal("actual report leaked private fixture data")
	}
	if out, err := exec.Command("/usr/bin/systemctl", "stop", "panel-network-ids").CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	stopped := service.observeThreatIDS(context.Background(), threatEVEFilter{})
	if stopped.State != "not-running" || stopped.ProcessVerified || stopped.Error != "" {
		t.Fatal("stopped process reported observing", stopped)
	}
	afterPackages := threatIDSNativePackages(t)
	for name, version := range beforePackages {
		if afterPackages[name] != version {
			t.Fatal("observation changed package", name)
		}
	}
	for name, state := range beforeUnits {
		if threatIDSNativeUnits(t)[name] != state {
			t.Fatal("observation changed original native service", name)
		}
	}
	t.Log("PASS actual native read-only observer verifies live executable, immutable rule/config/unit digests, UID/GID/capabilities/argv/process-start identity; old counters unknown, fresh counters observing, metadata-only query and stop; original native service/package identities unchanged")
}
