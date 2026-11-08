//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApacheNumericLogNativeAuthority(t *testing.T) {
	if os.Getenv("PANEL_QA_C50_NUMERIC_NATIVE") != "1" {
		t.Skip("explicit private Root native fixture required")
	}
	values := map[string]string{}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	if os.Geteuid() != 0 || values["CapEff"] != "000000000000001b" || values["CapBnd"] != "000000000000001b" || values["NoNewPrivs"] != "1" {
		t.Fatal("unexpected native authority", values["CapEff"], values["CapBnd"], values["NoNewPrivs"])
	}
	base := os.Getenv("PANEL_QA_C50_PRIVATE")
	if !strings.HasPrefix(base, "/opt/panel-c50-numeric-logs-") || len(strings.TrimPrefix(base, "/opt/panel-c50-numeric-logs-")) != 32 {
		t.Fatal("private QA output identity")
	}
	mount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || mount == os.Getenv("PANEL_QA_C50_ORIGINAL_MOUNT_NS") {
		t.Fatal("native fixture has no private mount namespace", err)
	}
	netns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || netns == os.Getenv("PANEL_QA_C50_ORIGINAL_NET_NS") {
		t.Fatal("native fixture has no private network namespace", err)
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(cgroup)), "\n")
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "0::/") {
		t.Fatal("native cgroup2 identity", string(cgroup))
	}
	path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(rows[0], "0::"))
	limits := map[string]string{}
	for _, name := range []string{"memory.max", "memory.swap.max", "pids.max"} {
		b, e := os.ReadFile(filepath.Join(path, name))
		if e != nil {
			t.Fatal(e)
		}
		limits[name] = strings.TrimSpace(string(b))
	}
	if limits["memory.max"] != "402653184" || limits["memory.swap.max"] != "0" || limits["pids.max"] != "64" {
		t.Fatal("native resource limits", limits)
	}
	out, err := json.MarshalIndent(map[string]any{"ok": true, "effective_capabilities": values["CapEff"], "bounded_capabilities": values["CapBnd"], "NoNewPrivs": values["NoNewPrivs"], "private_mount_namespace": mount, "private_network_namespace": netns, "limits": limits, "scope": "Private actual Linux filesystem and BSD flock primitives, not installed application or commercial acceptance"}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(base, "native-authority-proof.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(out); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}
