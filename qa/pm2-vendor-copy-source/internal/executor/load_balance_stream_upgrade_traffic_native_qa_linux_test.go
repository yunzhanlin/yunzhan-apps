//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// These are closed reader tests on fresh private Root fixtures, not an installed
// service, a committed Core history, or permission to replay a prior native job.
func TestLoadBalanceStreamUpgradeTrafficNamespacesNativeExactAndUnchanged(t *testing.T) {
	streamUpgradeNativeAnchor(t)
	for _, fault := range []string{"absent", "empty-jobs", "closed", "closed-128", "missing-jobs", "missing-original", "unknown-original", "refused-with-root", "symlink", "fifo", "bad-mode", "invalid-id", "false-closed", "too-many", "state-without-commit", "generation-without-commit", "configuration-without-commit", "configuration-publication-without-commit", "replaced-after-read", "created-after-absent-read"} {
		t.Run(fault, func(t *testing.T) {
			base := t.TempDir()
			jobs := filepath.Join(base, strings.TrimPrefix(loadBalanceStreamJobsRoot, "/"))
			closed := map[string]bool{}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			if fault != "absent" && fault != "created-after-absent-read" {
				must(os.MkdirAll(jobs, 0700))
			}
			one := core.ID()
			switch fault {
			case "closed", "closed-128", "missing-jobs", "missing-original", "replaced-after-read", "false-closed":
				closed[one] = true
			}
			if fault == "closed" || fault == "closed-128" || fault == "replaced-after-read" || fault == "false-closed" {
				must(os.Mkdir(filepath.Join(jobs, one), 0700))
			}
			switch fault {
			case "closed-128":
				for len(closed) < 128 {
					id := core.ID()
					must(os.Mkdir(filepath.Join(jobs, id), 0700))
					closed[id] = true
				}
			case "missing-jobs":
				must(os.Rename(jobs, jobs+".retained"))
			case "unknown-original", "refused-with-root":
				must(os.Mkdir(filepath.Join(jobs, one), 0700))
			case "symlink":
				must(os.Symlink(base, filepath.Join(jobs, one)))
			case "fifo":
				must(unix.Mkfifo(filepath.Join(jobs, one), 0600))
			case "bad-mode":
				must(os.Chmod(jobs, 0755))
			case "invalid-id":
				must(os.Mkdir(filepath.Join(jobs, "own"), 0700))
			case "false-closed":
				closed[one] = false
			case "too-many":
				for i := 0; i < 129; i++ {
					id := core.ID()
					must(os.Mkdir(filepath.Join(jobs, id), 0700))
					closed[id] = true
				}
			}
			orphan := map[string]string{"state-without-commit": loadBalanceStreamStateRoot,
				"generation-without-commit":                loadBalanceStreamGenerationPublicationsRoot,
				"configuration-without-commit":             loadBalanceStreamConfigurationRoot,
				"configuration-publication-without-commit": loadBalanceStreamConfigurationPublicationsRoot}[fault]
			if orphan != "" {
				must(os.MkdirAll(filepath.Join(base, strings.TrimPrefix(orphan, "/")), 0700))
			}
			r := &programQueueReader{ctx: context.Background(), root: base}
			err := streamUpgradeControlNamespaces(r, closed)
			valid := fault == "absent" || fault == "empty-jobs" || fault == "closed" || fault == "closed-128" || fault == "replaced-after-read" || fault == "created-after-absent-read"
			if (err == nil) != valid {
				t.Fatal("native namespace was truncated, adopted, or mistaken for closed", err)
			}
			if !valid {
				return
			}
			if err := r.unchanged(); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "replaced-after-read":
				must(os.Rename(filepath.Join(jobs, one), filepath.Join(base, "original-retained")))
				must(os.Mkdir(filepath.Join(jobs, one), 0700))
			case "created-after-absent-read":
				must(os.MkdirAll(jobs, 0700))
			default:
				return
			}
			if r.unchanged() == nil {
				t.Fatal("changed native identity/absence was silently adopted")
			}
		})
	}
}
