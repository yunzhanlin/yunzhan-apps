//go:build linux

package executor

import (
	"fmt"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatIDSRuleFeedUnitStateRequiresActualColdZeroAndPreservesIncompleteExit(t *testing.T) {
	valid := "MainPID=0\nExecMainStartTimestampMonotonic=0\nLoadState=loaded\nActiveState=inactive\n"
	for _, scenario := range []struct {
		name, raw, state         string
		wantError, wantAttention bool
	}{
		{"fresh-zero", valid, "queued", false, false},
		{"running", strings.ReplaceAll(strings.ReplaceAll(valid, "MainPID=0", "MainPID=123"), "ActiveState=inactive", "ActiveState=active"), "running", false, false},
		{"before-child", strings.ReplaceAll(valid, "ActiveState=inactive", "ActiveState=activating"), "running", false, false},
		{"exited-without-result", strings.ReplaceAll(valid, "TimestampMonotonic=0", "TimestampMonotonic=321"), "needs-attention", false, true},
		{"inactive-with-live-pid", strings.ReplaceAll(valid, "MainPID=0", "MainPID=123"), "needs-attention", false, true},
		{"failed-without-result", strings.ReplaceAll(valid, "ActiveState=inactive", "ActiveState=failed"), "needs-attention", false, true},
		{"omitted-timestamp", strings.ReplaceAll(valid, "ExecMainStartTimestampMonotonic=0\n", ""), "", true, false},
		{"empty-timestamp", strings.ReplaceAll(valid, "TimestampMonotonic=0", "TimestampMonotonic="), "", true, false},
		{"omitted-pid", strings.ReplaceAll(valid, "MainPID=0\n", ""), "", true, false},
		{"duplicate", valid + "MainPID=0\n", "", true, false},
		{"unknown", valid + "Foreign=0\n", "", true, false},
		{"capture-property-is-not-a-job-property", valid + "User=root\n", "", true, false},
		{"leading-space-key", " " + valid, "", true, false},
		{"blank-line", valid + "\n", "", true, false},
		{"oversized", valid + strings.Repeat("x", 4097), "", true, false},
		{"not-loaded", strings.ReplaceAll(valid, "LoadState=loaded", "LoadState=not-found"), "", true, false},
		{"unknown-active-state", strings.ReplaceAll(valid, "ActiveState=inactive", "ActiveState=unknown"), "", true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			state, detail, err := threatIDSRuleFeedUnitState(scenario.raw)
			if (err != nil) != scenario.wantError || state != scenario.state || (detail != "") != scenario.wantAttention {
				t.Fatalf("wrong immutable task observation: %q %q %v", state, detail, err)
			}
		})
	}
	for _, field := range []string{"MainPID", "ExecMainStartTimestampMonotonic"} {
		for _, value := range []string{"", "00", "01", "-1", "+1", " 0", "0 ", "1.0", "18446744073709551616"} {
			t.Run(fmt.Sprintf("%s-%q", field, value), func(t *testing.T) {
				raw := strings.ReplaceAll(valid, field+"=0", field+"="+value)
				if state, _, err := threatIDSRuleFeedUnitState(raw); err == nil || state != "" {
					t.Fatal("invented an actionable state from a malformed kernel property", state, err)
				}
			})
		}
	}
}

func TestThreatIDSRuleFeedJobInventoryClosedIdentityAndBudgets(t *testing.T) {
	for _, scenario := range []string{"empty", "published", "partial-stage", "unknown-job", "linked-job", "directory-mode", "missing-request", "unknown-file", "linked-file", "hardlink", "file-mode", "oversize-request", "oversize-envelope", "lock-data", "stage-result", "too-many-files", "sixteen", "seventeen"} {
		t.Run(scenario, func(t *testing.T) {
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			id := core.ID()
			name := id
			if strings.HasPrefix(scenario, "stage-") || scenario == "partial-stage" {
				name = ".request-" + id
			}
			if scenario != "empty" {
				if err := root.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Chmod(name, 0700); err != nil {
					t.Fatal(err)
				}
				child, err := root.OpenRoot(name)
				if err != nil {
					t.Fatal(err)
				}
				if scenario != "partial-stage" {
					for _, member := range []string{"request.json", "envelope.json"} {
						if err := ruleFeedStoreWrite(child, member, []byte("{}"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				child.Close()
			}
			path := filepath.Join(base, name)
			switch scenario {
			case "unknown-job":
				err = root.Rename(name, "foreign")
			case "linked-job":
				err = root.Rename(name, "retained")
				if err == nil {
					err = os.Symlink(filepath.Join(base, "retained"), path)
				}
			case "directory-mode":
				err = os.Chmod(path, 0755)
			case "missing-request":
				err = os.Remove(filepath.Join(path, "request.json"))
			case "unknown-file":
				err = os.WriteFile(filepath.Join(path, "extra.conf"), []byte("{}"), 0600)
			case "linked-file":
				err = os.Rename(filepath.Join(path, "request.json"), filepath.Join(base, "retained.json"))
				if err == nil {
					err = os.Symlink(filepath.Join(base, "retained.json"), filepath.Join(path, "request.json"))
				}
			case "hardlink":
				err = os.Link(filepath.Join(path, "request.json"), filepath.Join(base, "retained.json"))
			case "file-mode":
				err = os.Chmod(filepath.Join(path, "request.json"), 0644)
			case "oversize-request":
				err = os.Truncate(filepath.Join(path, "request.json"), 8193)
			case "oversize-envelope":
				err = os.Truncate(filepath.Join(path, "envelope.json"), appcatalog.MaxRuleFeedEnvelopeBytes+1)
			case "lock-data":
				err = os.WriteFile(filepath.Join(path, "install.lock"), []byte("not empty"), 0600)
			case "stage-result":
				err = os.WriteFile(filepath.Join(path, "result.json"), []byte("{}"), 0600)
			case "too-many-files":
				for _, member := range []string{"result.json", "install.lock", "extra"} {
					if e := os.WriteFile(filepath.Join(path, member), []byte("{}"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "sixteen", "seventeen":
				count := 16
				if scenario == "seventeen" {
					count = 17
				}
				for i := 1; i < count; i++ {
					stage := ".request-" + core.ID()
					if e := root.Mkdir(stage, 0700); e != nil {
						t.Fatal(e)
					}
					if e := root.Chmod(stage, 0700); e != nil {
						t.Fatal(e)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			accepted := scenario == "empty" || scenario == "published" || scenario == "partial-stage" || scenario == "sixteen"
			if err := threatIDSRuleFeedJobInventory(root); (err == nil) != accepted {
				t.Fatal("wrong closed inventory result", scenario, err)
			}
			if scenario == "unknown-file" {
				if raw, err := os.ReadFile(filepath.Join(path, "extra.conf")); err != nil || string(raw) != "{}" {
					t.Fatal("unknown evidence removed or changed", err)
				}
			}
		})
	}
}
