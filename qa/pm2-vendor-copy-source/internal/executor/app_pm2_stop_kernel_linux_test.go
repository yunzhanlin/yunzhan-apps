//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Kernel faults belong only to fresh, bounded child processes. Service
// commands remain fixed in-process responses in this source fixture; actual
// installed PM2 acceptance is separate.
func TestPM2StopKernelStorageFaults(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private native kernel fixtures require root")
	}
	for _, mode := range []string{"read-only", "fsync-EIO", "read-only-missing-lock", "fsync-EIO-missing-lock"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestPM2StopKernelStorageFaultChild$", "-test.v", "-test.count=1")
			cmd.Env = append(os.Environ(), "PANEL_PM2_STOP_KERNEL_CHILD="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil || !bytes.Contains(out, []byte("PM2_STOP_KERNEL_ACCEPTED "+mode+"\n")) {
				t.Fatalf("kernel stop fixture failed: %v %v\n%s", err, ctx.Err(), out)
			}
			t.Logf("%s", out)
		})
	}
}

func pm2StopReadOnlyPrivateMount(t *testing.T, dir string) func() {
	t.Helper()
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(dir, dir, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		if err := unix.Unmount(dir, 0); err != nil {
			t.Error("private stop fixture mount cleanup failed", err)
		}
	}
	if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
		cleanup()
		t.Fatal(err)
	}
	probe, err := os.OpenFile(filepath.Join(dir, ".owned-readonly-probe"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		probe.Close()
		cleanup()
		t.Fatal("private fixture did not acquire actual kernel EROFS")
	}
	if !errors.Is(err, unix.EROFS) {
		cleanup()
		t.Fatal("private fixture did not return EROFS", err)
	}
	return cleanup
}

func TestPM2StopKernelStorageFaultChild(t *testing.T) {
	mode := os.Getenv("PANEL_PM2_STOP_KERNEL_CHILD")
	if mode == "" {
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned kernel child requires root")
	}
	switch mode {
	case "read-only", "fsync-EIO", "read-only-missing-lock", "fsync-EIO-missing-lock":
	default:
		t.Fatal("unknown owned stop fixture")
	}
	s, app, appPath, calls := pm2StopFixture(t)
	dir := s.moduleDir("pm2-manager")
	// Seed healthy old reports but no new ledger, so persistence must actually
	// try the unavailable storage instead of failing on malformed input first.
	history := filepath.Join(dir, "history.json")
	report := filepath.Join(dir, "last-report.json")
	if err := s.writeModuleRetrospectiveRecord("pm2-manager", "history.json", []moduleEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := s.writeModuleRetrospectiveRecord("pm2-manager", "last-report.json", map[string]any{"time": core.Now(), "action": "run", "result": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "locks"), 0700); err != nil {
		t.Fatal(err)
	}
	missing := strings.HasSuffix(mode, "-missing-lock")
	if !missing {
		lease, err := s.pm2StopProjectLease(app.ID)
		if err != nil {
			t.Fatal(err)
		}
		lease.Close()
	}
	type original struct {
		info os.FileInfo
		raw  []byte
	}
	before := map[string]original{}
	for _, name := range []string{appPath, filepath.Join(dir, "installed.json"), history, report} {
		info, err := os.Lstat(name)
		raw, readErr := os.ReadFile(name)
		if err != nil || readErr != nil {
			t.Fatal(err, readErr)
		}
		before[name] = original{info, raw}
	}
	if strings.HasPrefix(mode, "read-only") {
		defer pm2StopReadOnlyPrivateMount(t, dir)()
	} else {
		probe, err := os.OpenFile(filepath.Join(t.TempDir(), "owned-sync-probe"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()
		pm2KernelDenyFsync(t)
		if err := probe.Sync(); !errors.Is(err, unix.EIO) {
			t.Fatal("private fixture did not acquire actual kernel fsync EIO", err)
		}
	}
	mux := http.NewServeMux()
	s.appModuleRoutes(mux)
	read := httptest.NewRecorder()
	mux.ServeHTTP(read, httptest.NewRequest("GET", "/v1/app-modules/pm2-manager/projects", nil))
	var page map[string]any
	if err := json.Unmarshal(read.Body.Bytes(), &page); err != nil || read.Code != 200 || len(*calls) != 1 || page["projects_readonly"] != true || page["project_page_complete"] != true || page["history_or_report_written"] != false || len(page["apps"].([]any)) != 1 {
		t.Fatal("kernel storage fault prevented the independent original project read", read.Code, len(*calls), err)
	}
	if page["apps"].([]any)[0].(map[string]any)["state"] != "active" {
		t.Fatal("original project read did not observe the still active service")
	}
	*calls = nil
	body, _ := json.Marshal(core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision})
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest("POST", "/v1/app-modules/pm2-manager/stop", bytes.NewReader(body)))
	if missing {
		if recorder.Code != 409 || len(*calls) != 0 {
			t.Fatal("storage failure without the original lease dispatched a service command", recorder.Code, len(*calls))
		}
	} else {
		var result map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || recorder.Code != 200 || len(*calls) != 3 || result["service_outcome_verified"] != true || result["configuration_preserved"] != true || result["configuration_or_deployment_replayed"] != false || result["state"] != "inactive" || result["boot_enabled"] != false || result["history_persisted"] != false || result["last_report_persisted"] != false || result["persistence_warning"] == "" {
			t.Fatal("verified service stop and failed persistence were conflated", recorder.Code, len(*calls), err)
		}
	}
	for name, old := range before {
		info, err := os.Lstat(name)
		raw, readErr := os.ReadFile(name)
		if err != nil || readErr != nil || !programQueueSame(old.info, info) || !bytes.Equal(old.raw, raw) {
			t.Fatal("kernel stop fixture changed an original project, installation or report", filepath.Base(name), err, readErr)
		}
	}
	fmt.Printf("PM2_STOP_KERNEL_ACCEPTED %s\n", mode)
}
