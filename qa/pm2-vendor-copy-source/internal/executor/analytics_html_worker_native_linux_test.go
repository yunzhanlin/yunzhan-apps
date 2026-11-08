//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Called only after the actual preliminary CLI worker completed inside the
// private read-only-host-root fixture with the production capability budget.
func TestAnalyticsHTMLActualCLIWorkerReadyRecord(t *testing.T) {
	id := os.Getenv("PANEL_QA_ANALYTICS_WORKER_JOB")
	if id == "" {
		t.Skip("requires a completed CLI build in a dedicated private fixture")
	}
	var fs syscall.Statfs_t
	if os.Getenv("PANEL_QA_ANALYTICS_NATIVE") != "1" || os.Geteuid() != 0 || !core.ValidID(id) || syscall.Statfs("/", &fs) != nil || fs.Flags&1 == 0 {
		t.Fatal("CLI worker verification requires a private read-only host root")
	}
	self, e := os.Readlink("/proc/self/ns/mnt")
	init, e2 := os.Readlink("/proc/1/ns/mnt")
	// The fixture captures PID 1 while its mount helper still has the
	// namespace setup capabilities. The production worker drops CAP_SYS_PTRACE,
	// so procfs can correctly deny a later read of PID 1's namespace. Validate
	// the captured identity against our own, and against PID 1 when readable;
	// do not add capabilities just to make a QA probe work.
	captured := os.Getenv("PANEL_QA_ANALYTICS_INIT_MOUNT_NAMESPACE")
	namespace := regexp.MustCompile(`^mnt:\[[1-9][0-9]{0,19}\]$`)
	if e != nil || !namespace.MatchString(self) || !namespace.MatchString(captured) || self == captured || (e2 == nil && init != captured) || (e2 != nil && !errors.Is(e2, os.ErrPermission)) {
		t.Fatal("CLI worker verification requires a private mount namespace")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "CapBnd:\t00000000000000eb\n") {
		t.Fatal("production capability boundary and NoNewPrivileges were not enforced")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := nativeWAFService()
	record, err := s.verifyAnalyticsHTMLBuild(ctx, id)
	if err != nil || record.State != "ready" || !record.ABIValidated {
		t.Fatal("actual CLI output failed the production closed-schema/source/ABI/tree verifier", err)
	}
	result, err := s.analyticsHTMLStatus(ctx, id)
	if err != nil || result.State != "ready" || !result.BuildOnly || !result.IntegrityVerified || !result.ABIValidated || result.JobID != id {
		t.Fatal("actual CLI ready output failed the real read-only executor status path", err)
	}
	for _, path := range []string{"/etc/panel/analytics-html/active.json", "/etc/panel/analytics-html/health.conf"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a build improperly activated the module", path, err)
		}
	}
	path := filepath.Join(analyticsHTMLBuilds, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := runAnalyticsHTMLBuild(ctx, id); err == nil {
		t.Fatal("completed CLI job was overwritten or reused")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("CLI replay changed the completed build evidence", err)
	}
	cancelled := strings.Repeat("e", 32)
	if cancelled == id {
		t.Fatal("private fixture job collision")
	}
	for _, directory := range []string{analyticsHTMLRequests, analyticsHTMLCancellations} {
		if err := s.createAnalyticsHTMLControl(directory, cancelled); err != nil {
			t.Fatal(err)
		}
	}
	if err := runAnalyticsHTMLBuild(ctx, cancelled); err == nil {
		t.Fatal("durably cancelled CLI request began a build")
	}
	if _, err := os.Lstat(filepath.Join(analyticsHTMLBuilds, cancelled+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled request created a build record", err)
	}
	if _, err := s.verifyAnalyticsHTMLBuild(ctx, id); err != nil {
		t.Fatal("CLI cancellation or replay changed a previously ready program", err)
	}
	t.Log("PASS actual preliminary CLI worker ready record, fixed source/ABI/tree verification, immutable replay and durable pre-dispatch cancellation; production capability/resource budget; no activation or original service/site mutation; not signed release or authenticated panel API acceptance")
}
