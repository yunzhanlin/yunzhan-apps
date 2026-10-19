//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func maintenanceRootFixture(t *testing.T) (platformMaintenanceStore, core.PlatformMaintenanceNativeRequest, *int) {
	t.Helper()
	f := geoStoreRootFixture(t)
	calls := new(int)
	plan := core.PlatformMaintenancePlan{Format: 1, SHA: strings.Repeat("e", 64), Commands: core.PlatformMaintenanceCommands()}
	s := platformMaintenanceStore{base: filepath.Join(filepath.Dir(f.store.base), "maintenance-jobs"), plan: func(context.Context) (core.PlatformMaintenancePlan, error) { return plan, nil }, run: func(context.Context, string) error { *calls++; return nil }}
	in := core.PlatformMaintenanceNativeRequest{Format: 1, GrantID: strings.Repeat("a", 64), ActorID: strings.Repeat("b", 32), Input: core.PlatformMaintenanceInput{RequestID: strings.Repeat("c", 32), Command: "nginx-reload", ExpectedPlanSHA: plan.SHA, Confirm: "RELOAD NGINX " + plan.SHA}}
	return s, in, calls
}
func TestPlatformMaintenanceRootOriginalReceiptsAndExactOnceReplay(t *testing.T) {
	s, in, calls := maintenanceRootFixture(t)
	row, e := s.execute(context.Background(), in)
	if e != nil || row.State != "completed" || row.Outcome != "reload_signal_submitted" || *calls != 1 {
		t.Fatal(row, e, *calls)
	}
	request := filepath.Join(s.base, in.Input.RequestID+".request.json")
	before, _ := os.Stat(request)
	raw, _ := os.ReadFile(request)
	again, e := s.execute(context.Background(), in)
	if e != nil || again != row || *calls != 1 {
		t.Fatal("original command reran", e, *calls)
	}
	after, _ := os.Stat(request)
	got, _ := os.ReadFile(request)
	if !geoStoreStableInfo(before, after) || !bytes.Equal(raw, got) {
		t.Fatal("original receipt replaced")
	}
	changed := in
	changed.Input.ExpectedPlanSHA = strings.Repeat("f", 64)
	changed.Input.Confirm = "RELOAD NGINX " + changed.Input.ExpectedPlanSHA
	if _, e = s.execute(context.Background(), changed); e == nil || *calls != 1 {
		t.Fatal("ID rebound or command reran")
	}
	n, pending, e := s.inventory()
	if e != nil || n != 1 || pending {
		t.Fatal(n, pending, e)
	}
}
func TestPlatformMaintenanceRootInterruptedAndChangedPlanNeverReplays(t *testing.T) {
	for _, point := range []string{"after-durable-start", "after-command-before-result"} {
		t.Run(point, func(t *testing.T) {
			s, in, calls := maintenanceRootFixture(t)
			s.fault = func(p string) error {
				if p == point {
					return errors.New("synthetic crash")
				}
				return nil
			}
			if _, e := s.execute(context.Background(), in); e == nil {
				t.Fatal("fault unobserved")
			}
			count := *calls
			s.fault = nil
			row, e := s.execute(context.Background(), in)
			if e != nil || row.State != "started" || *calls != count {
				t.Fatal("uncertain original replayed", row, e, *calls)
			}
			other := in
			other.Input.RequestID = strings.Repeat("d", 32)
			if _, e = s.execute(context.Background(), other); e == nil || *calls != count {
				t.Fatal("changed ID bypassed pending reload")
			}
		})
	}
	s, in, calls := maintenanceRootFixture(t)
	s.plan = func(context.Context) (core.PlatformMaintenancePlan, error) {
		return core.PlatformMaintenancePlan{Format: 1, SHA: strings.Repeat("f", 64), Commands: core.PlatformMaintenanceCommands()}, nil
	}
	row, e := s.execute(context.Background(), in)
	if e != nil || row.State != "failed" || row.Outcome != "plan_changed_before_command" || *calls != 0 {
		t.Fatal(row, e, *calls)
	}
}
func TestPlatformMaintenanceRootUnsafeRecordsRejectWithoutRepair(t *testing.T) {
	for _, mode := range []string{"foreign", "symlink", "hardlink", "changed", "unknown", "missing-lock", "lock-mode", "lock-content"} {
		t.Run(mode, func(t *testing.T) {
			s, in, calls := maintenanceRootFixture(t)
			if _, e := s.execute(context.Background(), in); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(s.base, in.Input.RequestID+".request.json")
			switch mode {
			case "foreign":
				if e := os.Chown(p, 65534, 65534); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(p, p+".held"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(p+".held", p); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(p, filepath.Join(filepath.Dir(s.base), "extra-link")); e != nil {
					t.Fatal(e)
				}
			case "changed":
				if e := os.WriteFile(p, []byte(`{"format":1}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown":
				if e := os.WriteFile(filepath.Join(s.base, "unknown"), []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing-lock":
				if e := os.Rename(filepath.Join(s.base, in.Input.RequestID+".lock"), filepath.Join(filepath.Dir(s.base), "retained-lock")); e != nil {
					t.Fatal(e)
				}
			case "lock-mode":
				if e := os.Chmod(filepath.Join(s.base, in.Input.RequestID+".lock"), 0644); e != nil {
					t.Fatal(e)
				}
			case "lock-content":
				if e := os.WriteFile(filepath.Join(s.base, in.Input.RequestID+".lock"), []byte("unowned content"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, _, e := s.inventory(); e == nil {
				t.Fatal("unsafe inventory accepted")
			}
			if *calls != 1 {
				t.Fatal("repair reran command")
			}
			if strings.HasPrefix(mode, "lock-") || mode == "missing-lock" {
				if _, e := s.execute(context.Background(), in); e == nil || *calls != 1 {
					t.Fatal("damaged original lock accepted or replayed")
				}
			}
		})
	}
}
