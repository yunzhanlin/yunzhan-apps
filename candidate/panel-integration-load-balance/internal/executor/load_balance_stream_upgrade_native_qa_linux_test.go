//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func streamUpgradeNativeAnchor(t *testing.T) {
	t.Helper()
	anchor := os.Getenv("PANEL_LBSTREAM_UPGRADE_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit original isolated Root upgrade models only")
	}
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Geteuid() != 0 || os.Getegid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/qa-l4-account-negative24bmvi-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) || threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("closed distinct original Root upgrade fixture required")
	}
}

func TestLoadBalanceStreamUpgradeInventoryNativeClosedBoundedUnchanged(t *testing.T) {
	streamUpgradeNativeAnchor(t)
	for _, fault := range []string{"valid", "invalid-id", "symlink", "hardlink", "fifo", "bad-mode", "unexpected-leaf", "too-many", "changed-after-read"} {
		t.Run(fault, func(t *testing.T) {
			base := t.TempDir()
			relative := strings.TrimPrefix(loadBalanceStreamInstallationJobsRoot, "/")
			path := filepath.Join(base, relative)
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			job := strings.Repeat("a", 32)
			if fault == "invalid-id" {
				job = "bad"
			}
			casePath := filepath.Join(path, job)
			if err := os.Mkdir(casePath, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(casePath, "run.lock")
			if err := os.WriteFile(name, nil, 0600); err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "symlink":
				must(os.Rename(name, name+".retained"))
				must(os.Symlink(name+".retained", name))
			case "hardlink":
				must(os.Link(name, filepath.Join(base, "other-hard-link")))
			case "fifo":
				must(os.Rename(name, filepath.Join(base, "retained")))
				must(unix.Mkfifo(name, 0600))
			case "bad-mode":
				must(os.Chmod(name, 0644))
			case "unexpected-leaf":
				must(os.WriteFile(filepath.Join(casePath, "unknown.json"), []byte("{}"), 0600))
			case "too-many":
				for i := 0; i < 129; i++ {
					_, err := os.MkdirTemp(path, "unbounded-")
					must(err)
				}
			}
			r := &programQueueReader{ctx: context.Background(), root: base}
			inventory, err := streamUpgradeInventory(r, loadBalanceStreamInstallationJobsRoot, true, 0)
			defer streamUpgradeClearInventory(inventory)
			if fault == "valid" || fault == "changed-after-read" {
				if err != nil || len(inventory) != 1 || len(inventory[job]) != 1 {
					t.Fatal("closed private inventory refused", err)
				}
				if fault == "changed-after-read" {
					must(os.WriteFile(name, []byte("drift"), 0600))
					if r.unchanged() == nil {
						t.Fatal("read snapshot became a lease across changed original inode")
					}
				} else if r.unchanged() != nil {
					t.Fatal("readonly inventory changed original metadata")
				}
			} else if err == nil {
				t.Fatal("unbounded or ambiguous native evidence accepted", fault)
			}
		})
	}
}

func TestLoadBalanceStreamUpgradeCoreNativeCompleteOriginalAndWALRevocation(t *testing.T) {
	streamUpgradeNativeAnchor(t)
	base, writer, grant := streamInstallAuthorityNativeFixtureChecked(t, "update")
	if _, err := writer.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.install-request',?,?,?)", grant.ActorID, grant.JobID, grant.PayloadSHA256, grant.JobCreatedAt); err != nil {
		t.Fatal(err)
	}
	source, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &loadBalanceStreamCoreAuthority{source: source}
	defer r.close()
	jobs, err := r.upgradeJobs(context.Background(), &grant)
	if err != nil || len(jobs) != 1 || jobs[0].Authority != grant || jobs[0].State != "running" {
		t.Fatal("complete exact original read-only source refused", err)
	}
	if _, err = r.upgradeJobs(context.Background(), nil); err == nil {
		t.Fatal("pending native original vanished from whole programme admission")
	}
	if _, err = writer.DB.Exec("UPDATE app_user_roles SET role='viewer'"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.upgradeJobs(context.Background(), &grant); err == nil {
		t.Fatal("revoked live WAL authority became a selected-ID exemption")
	}
	if _, err = source.db.Exec("DELETE FROM load_balance_stream_install_requests"); err == nil {
		t.Fatal("upgrade reader gained a writer")
	}
}
