//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Kernel witness ONLY. Both roles need an explicit isolated Root QA case.
// A PRIVATE tmpfs must hide the host's complete executor namespace; the test
// store is bound into that tmpfs. No real installation/grant/NSS is produced.
// The deliberately invalid envelope must remain invalid in the positive case.
func streamParentKernelFixture(t *testing.T) (string, string) {
	t.Helper()
	root := os.Getenv("PANEL_LBSTREAM_PARENT_QA_ROOT")
	if root == "" {
		t.Skip("explicit private-mount Linux parent witness only; not account or application authority")
	}
	job := os.Getenv("PANEL_LBSTREAM_PARENT_QA_JOB")
	if os.Geteuid() != 0 || os.Getegid() != 0 ||
		!regexp.MustCompile(`^/opt/panel-qa-lbstream-parent24bmop-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(root) ||
		!core.ValidID(job) || threatIDSTrustedParents(root, false) != nil {
		t.Fatal("exact new private Root model case required")
	}
	var fs unix.Statfs_t
	if unix.Statfs("/var/lib/panel-executor", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("refuse the host executor namespace; an isolated tmpfs is mandatory")
	}
	if _, err := os.Lstat("/var/lib/panel-executor/installs"); !os.IsNotExist(err) {
		t.Fatal("real or foreign native ledger must not be visible inside this model namespace")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !streamAccountParentRootStatus(status) {
		t.Fatal("actual Root NoNewPrivs kernel identity required", err)
	}
	return root, job
}

func streamParentKernelWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		f.Close()
		t.Fatal("private QA evidence write failed", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func streamParentKernelWait(t *testing.T, path string, maximum time.Duration) []byte {
	t.Helper()
	end := time.Now().Add(maximum)
	for time.Now().Before(end) {
		info, err := os.Lstat(path)
		if err == nil {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || info.Mode() != 0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || info.Size() <= 0 || info.Size() > 4096 {
				t.Fatal("foreign private QA evidence", path)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("bounded private QA rendezvous expired", filepath.Base(path))
	return nil
}

func TestLoadBalanceStreamAccountParentKernelNativeParentRole(t *testing.T) {
	root, job := streamParentKernelFixture(t)
	if os.Getenv("PANEL_LBSTREAM_PARENT_QA_ROLE") != "parent" {
		t.Fatal("wrong explicit isolated role")
	}
	ctx := context.Background()
	seedRaw, submission := streamInstallationJournalNativeSeed(t, "install")
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil {
		t.Fatal(err)
	}
	seed.JobID = job
	seedRaw, err = loadbalancestream.InstallationSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	j, err := createLoadBalanceStreamInstallationJournalAt(ctx, loadBalanceStreamInstallationJobsRoot, seedRaw, submission)
	if err != nil {
		t.Fatal("new private model journal refused", err)
	}
	defer j.close()
	if err := j.appendOriginal(ctx, loadbalancestream.InstallationEvidence{}); err != nil {
		t.Fatal("private original account-intent phase refused", err)
	}
	raw, records, chain, err := j.original(ctx)
	if err != nil || len(records) != 2 || chain.Complete || !chain.OriginalUnknown {
		t.Fatal("exact private unknown account-intent required", err)
	}
	dir, err := j.root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := j.lock.Stat()
	if err != nil {
		t.Fatal(err)
	}
	ds, ok1 := dir.Sys().(*syscall.Stat_t)
	ls, ok2 := lock.Sys().(*syscall.Stat_t)
	start, err := moduleProcessStart("/proc", os.Getpid())
	if !ok1 || !ok2 || err != nil {
		t.Fatal("actual parent journal/kernel identities unavailable", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, exe); err != nil {
		exe.Close()
		t.Fatal(err)
	}
	exe.Close()
	permit := loadbalancestream.AccountChildPermit{Format: 1, AppVersion: seed.AppVersion, JobID: job,
		ActorID: seed.ActorID, Nonce: seed.Nonce, BootID: strings.TrimSpace(string(boot)),
		ParentPID: uint32(os.Getpid()), ParentStartTicks: start, ParentExeSHA256: hex.EncodeToString(h.Sum(nil)),
		ProgrammeInputsSHA256: seed.ProgrammeInputsSHA256, SeedSHA256: core.Hash(string(raw)),
		AccountIntentSHA256: core.Hash(string(records[1])), JournalDevice: uint64(ds.Dev), JournalInode: ds.Ino,
		RunLockDevice: uint64(ls.Dev), RunLockInode: ls.Ino, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	encoded, err := loadbalancestream.AccountChildPermitBytes(permit)
	if err != nil {
		t.Fatal(err)
	}
	streamParentKernelWrite(t, filepath.Join(root, "permit.json"), encoded)
	streamParentKernelWait(t, filepath.Join(root, "unlock-requested.json"), 40*time.Second)
	// QA-only intentional withdrawal of the original private model's lock.
	// There is no real controller, account, service or customer journal here.
	if err := syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	streamParentKernelWrite(t, filepath.Join(root, "parent-unlocked.json"), []byte("{\"private_model_only\":true}\n"))
	streamParentKernelWait(t, filepath.Join(root, "parent-finish-requested.json"), 20*time.Second)
}

func TestLoadBalanceStreamAccountParentKernelNativeChildRole(t *testing.T) {
	root, job := streamParentKernelFixture(t)
	if os.Getenv("PANEL_LBSTREAM_PARENT_QA_ROLE") != "child" {
		t.Fatal("wrong explicit isolated role")
	}
	raw := streamParentKernelWait(t, filepath.Join(root, "permit.json"), 10*time.Second)
	permit, err := loadbalancestream.DecodeAccountChildPermit(raw)
	if err != nil || permit.JobID != job {
		t.Fatal("exact original private permit required", err)
	}
	j, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, job)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if authority, err := j.officialAuthority(ctx); err == nil || authority.Matches(loadbalancestream.AppVersion, strings.Repeat("1", 64)) {
		t.Fatal("fake private serialization fixture became official authority")
	}
	w, err := holdLoadBalanceStreamAccountParent(ctx, permit, j)
	if err != nil || w == nil {
		t.Fatal("real original kernel/unit/pidfd/write-FLOCK positive refused", err)
	}
	defer w.Close()
	if err := w.current(ctx); err != nil {
		t.Fatal("original live parent changed before any mutation", err)
	}
	for name, change := range map[string]func(*loadbalancestream.AccountChildPermit){
		"self-pid": func(p *loadbalancestream.AccountChildPermit) { p.ParentPID = uint32(os.Getpid()) },
		"wrong-boot": func(p *loadbalancestream.AccountChildPermit) {
			if p.BootID[0] == 'a' {
				p.BootID = "b" + p.BootID[1:]
			} else {
				p.BootID = "a" + p.BootID[1:]
			}
		},
		"expired": func(p *loadbalancestream.AccountChildPermit) {
			p.CreatedAt = time.Now().Add(-loadbalancestream.AccountChildPermitLifetime - time.Second).UTC().Format(time.RFC3339)
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := permit
			change(&altered)
			got, err := holdLoadBalanceStreamAccountParent(ctx, altered, j)
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("foreign or expired parent borrowed the original kernel witness")
			}
		})
	}
	streamParentKernelWrite(t, filepath.Join(root, "unlock-requested.json"), []byte("{\"private_model_only\":true}\n"))
	streamParentKernelWait(t, filepath.Join(root, "parent-unlocked.json"), 5*time.Second)
	if w.current(ctx) == nil {
		t.Fatal("live parent without its exact original WRITE FLOCK retained authority")
	}
	streamParentKernelWrite(t, filepath.Join(root, "parent-finish-requested.json"), []byte("{\"private_model_only\":true}\n"))
	end := time.Now().Add(5 * time.Second)
	for w.live() && time.Now().Before(end) {
		time.Sleep(20 * time.Millisecond)
	}
	if w.live() || w.current(ctx) == nil {
		t.Fatal("original pidfd must reject a naturally exited parent without a signal or replacement")
	}
	result, err := json.Marshal(map[string]any{"ok": true, "component_only": true,
		"actual_live_parent_same_exe_original_unit_pidfd_and_write_FLOCK": true,
		"self_pid_wrong_boot_expired_unlocked_and_exited_refused":         true,
		"host_executor_namespace_hidden_by_private_tmpfs":                 true,
		"fake_envelope_never_official_authority":                          true, "NSS_or_account_or_application_effects": 0,
		"installer_or_customer_job_replayed": false, "commercial_acceptance": false})
	if err != nil {
		t.Fatal(err)
	}
	streamParentKernelWrite(t, filepath.Join(root, "kernel-witness.json"), append(result, '\n'))
}
