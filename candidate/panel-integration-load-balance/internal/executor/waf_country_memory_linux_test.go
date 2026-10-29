//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

func TestWAFCountryMemoryKernelMembershipRefusesV1MixedAndEscapingPaths(t *testing.T) {
	for _, name := range []string{"/", "/system.slice/nginx.service", "/system.slice/panel-executor.service", "/user.slice/user-501.slice/session-2.scope"} {
		if got, err := wafCountryMemoryCgroup([]byte("0::" + name + "\n")); err != nil || got != name {
			t.Fatal(name, got, err)
		}
	}
	for _, raw := range []string{"", "0::/", "0::/system.slice/nginx.service\r\n", "0::/system.slice/nginx.service\n0::/other\n", "1:memory:/system.slice/nginx.service\n", "0::/system.slice/../foreign\n", "0:://system.slice/nginx.service\n", "0::/system.slice/./nginx.service\n", "0::/system.slice/nginx.service/\n", "0::/system.slice/%2e%2e\n", "0::/system.slice/evil\x00\n"} {
		if got, err := wafCountryMemoryCgroup([]byte(raw)); err == nil || got != "" {
			t.Fatal("unknown membership became a readable scope", raw, got, err)
		}
	}
}

func TestWAFCountryCapacityMissingPolicyNeverNeedsAResourceProbe(t *testing.T) {
	s := &Service{Config: Config{Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("inactive capacity policy executed a command")
		return "", nil
	}}}
	if check, err := s.prepareWAFCountryMemory(context.Background(), core.DefaultWAFConfig(), "/not-a-command"); err != nil || check != nil {
		t.Fatal("old no-country configuration gained capacity requirements", err)
	}
}

func TestWAFCountryCapacityStopKeepsDataAndDoesNotReadKernelOrCache(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root-only production selector, exercised by Root Linux CI")
	}
	s := &Service{Config: Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", SecurityDir: "/etc/panel/security-apps", Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("stopping country rule executed a command")
		return "", nil
	}}}
	for _, kind := range []string{"disabled", "master-off", "all-rules-off"} {
		cfg := core.DefaultWAFConfig()
		cfg.Country = countryRenderFixture()
		switch kind {
		case "disabled":
			cfg.Country.Enabled = false
		case "master-off":
			cfg.Policy.Mode = "off"
		case "all-rules-off":
			cfg.Country.Global = core.WAFCountryRule{Mode: "off", Countries: []string{}}
		}
		before, _ := json.Marshal(cfg)
		if check, err := s.prepareWAFCountryMemory(context.Background(), cfg, "/not-a-command"); err != nil || check != nil {
			t.Fatal("stop was made conditional on a data or memory probe", kind, err)
		}
		after, _ := json.Marshal(cfg)
		if string(before) != string(after) {
			t.Fatal("stop changed original country selection", kind)
		}
	}
}

func TestWAFCountryMemoryCancelledAndForeignRootNeverExecutes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Service{Config: Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", SecurityDir: "/etc/panel/security-apps", Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("invalid/cancelled admission executed command")
		return "", nil
	}}}
	if err := s.admitWAFCountryMemory(ctx, "", geodata.CountrySelectionMetadata{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled admission became a budget", err)
	}
	s.Config.SystemRoot = t.TempDir()
	if s.admitWAFCountryMemory(context.Background(), "", geodata.CountrySelectionMetadata{}) == nil {
		t.Fatal("relocated system accepted as actual capacity")
	}
	if probeWAFCountryMemory(context.Background(), 1, wafCountryMemoryBudget{}) == nil {
		t.Fatal("PID1 adopted as Nginx")
	}
}

var wafCountryNativeMemoryReadOnly = flag.Bool("waf-country-memory-native-readonly", false, "only in an owned non-DEV QA with the original signed CN/US cache; no installation or policy change")

func TestWAFCountryMemoryNativeVerifiedExistingSelectionAndActualKernel(t *testing.T) {
	if !*wafCountryNativeMemoryReadOnly {
		t.Skip("explicit existing-cache native read-only component required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual Root Linux QA required")
	}
	if _, err := os.Lstat("/opt/panel/DEVELOPMENT_RELEASE"); !os.IsNotExist(err) {
		t.Fatal("Main DEV or unknown layout is forbidden")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	const dataset = "e9d0ab29314d796c94b73b72355326dd89315d4a6d43862f031aecfd1ffe13f1-640129bf1a437ba6e47800e6c76adb17daa4b5b5c2203ce734366c10c46d8215"
	store := countryCacheStore{base: countryCacheRoot, trust: appcatalog.Default(), now: time.Now}
	base, err := store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	entry, authority, err := store.loadAuthority(ctx, base, dataset)
	if err != nil || !entry.Published || entry.Networks != 237408 || entry.Bytes != 5053023 || !reflect.DeepEqual(entry.Countries, []string{"CN", "US"}) {
		t.Fatal("original signed selection unavailable", entry, err)
	}
	directory, err := countryCacheDirectory(base, dataset)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	metadata, err := countryCacheVerifySelection(ctx, directory.Root, authority, entry.Countries)
	if err != nil || metadata.Networks != entry.Networks || metadata.Bytes != entry.Bytes || !base.current() || !directory.current() {
		t.Fatal(metadata, err)
	}
	budget, err := wafCountryReloadMemoryBudget(metadata)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "nginx.service", "--property=MainPID", "--value").Output()
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || perr != nil || pid <= 1 {
		t.Fatal("actual Nginx master unavailable", err, perr)
	}
	nginx, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Config: Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", SecurityDir: "/etc/panel/security-apps", Run: func(ctx context.Context, binary string, args ...string) (string, error) {
		if binary != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"show", "nginx", "--property=ActiveState,MainPID"}) {
			t.Fatal("readonly native component attempted another command", binary, args)
		}
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		return string(out), err
	}}}
	if err := s.admitWAFCountryMemory(ctx, nginx, metadata); err != nil {
		t.Fatal("actual kernel/host capacity refused", metadata, budget, err)
	}
	status, err := wafCountryMemoryRead("/proc/"+strconv.Itoa(pid)+"/status", 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := wafCountryMemoryWithMaster(budget, status)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native readonly complete signed networks=%d radix_nodes=%d data_parser_bytes=%d effective_parser_bytes=%d effective_reload_bytes=%d effective_host_required_bytes=%d", metadata.Networks, metadata.RadixNodes, budget.Parser, effective.Parser, effective.Reload, effective.Host)
}
