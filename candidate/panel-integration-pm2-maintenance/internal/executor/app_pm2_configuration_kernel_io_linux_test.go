//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Every restrictive kernel policy belongs to a fresh, bounded child process.
// This is native fault-fixture evidence, separate from a real installed
// programme's lifecycle and store-update acceptance.
func TestPM2ConfigurationKernelStorageFaults(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native private-ledger fault fixtures require root")
	}
	for _, mode := range []string{"terminal-report", "original-nonce", "start-guard", "programme-queue", "empty-store", "zero-intent", "partial-intent", "ENOSPC-intent"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestPM2ConfigurationKernelStorageFaultChild$", "-test.v", "-test.count=1")
			cmd.Env = append(os.Environ(), "PANEL_PM2_KERNEL_IO_CHILD="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil || !bytes.Contains(out, []byte("PM2_KERNEL_IO_ACCEPTED "+mode)) {
				t.Fatalf("native kernel fault was not qualified: %v %v\n%s", err, ctx.Err(), out)
			}
			t.Logf("%s", out)
		})
	}
}

func pm2KernelDenyFsync(t *testing.T) {
	t.Helper()
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		t.Fatal("native PM2 kernel fixture architecture is not supported")
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_FSYNC), Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EIO)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(program)
	if errno != 0 || result != 0 {
		t.Fatalf("cannot apply child-only synchronized kernel fault: %v %d", errno, result)
	}
}

func pm2KernelPrivateFileSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		info, err := os.Lstat(path)
		if err != nil || !moduleRecordInfo(info, false, false) {
			t.Fatal("fault changed private original identity", e.Name(), err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fmt.Sprintf("%d:%d:%s", info.Size(), info.ModTime().UnixNano(), pm2ConfigHash(raw))
	}
	return out
}

func pm2KernelFillPrivateTmpfs(t *testing.T, dir string) func() {
	t.Helper()
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		t.Fatal("native ENOSPC fixture needs a private mount namespace", err)
	}
	// Make propagation private before creating any mount. The parent process
	// and host's mount view must never see this disposable 64 KiB filesystem.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("panel-pm2-native-io-qa", dir, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "size=64k,mode=0700,uid=0,gid=0"); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		if err := unix.Unmount(dir, 0); err != nil {
			t.Error("owned native fault mount cleanup failed", err)
		}
	}
	fill, err := os.OpenFile(filepath.Join(dir, ".unlinked-quota-fixture"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := os.Remove(fill.Name()); err != nil {
		fill.Close()
		cleanup()
		t.Fatal(err)
	}
	full := false
	for i := 0; i < 128; i++ {
		if _, err := fill.Write(make([]byte, 4096)); err != nil {
			if !errors.Is(err, unix.ENOSPC) {
				fill.Close()
				cleanup()
				t.Fatal(err)
			}
			full = true
			break
		}
	}
	if !full {
		fill.Close()
		cleanup()
		t.Fatal("bounded private filesystem did not reach actual ENOSPC")
	}
	return func() { fill.Close(); cleanup() }
}

func TestPM2ConfigurationKernelStorageFaultChild(t *testing.T) {
	mode := os.Getenv("PANEL_PM2_KERNEL_IO_CHILD")
	if mode == "" {
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel child must be root in its owned fixture")
	}
	allowed := map[string]bool{"terminal-report": true, "original-nonce": true, "start-guard": true, "programme-queue": true, "empty-store": true, "zero-intent": true, "partial-intent": true, "ENOSPC-intent": true}
	if !allowed[mode] {
		t.Fatal("unknown owned child case")
	}
	if strings.HasSuffix(mode, "intent") {
		s, app, path := pm2StateAppFixture(t)
		before, _ := os.ReadFile(path)
		d, err := s.openPM2ConfigStore(true)
		if err != nil {
			t.Fatal(err)
		}
		d.Close()
		dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
		if mode == "ENOSPC-intent" {
			defer pm2KernelFillPrivateTmpfs(t, dir)()
		} else {
			signal.Ignore(unix.SIGXFSZ)
			limit := uint64(0)
			if mode == "partial-intent" {
				limit = 64
			}
			if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: limit, Max: limit}); err != nil {
				t.Fatal(err)
			}
		}
		queries := 0
		s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
			if name != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" {
				t.Fatalf("storage refusal dispatched a service mutation: %s %v", name, args)
			}
			queries++
			return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
		}
		id := core.ID()
		result, err := s.modulePM2(context.Background(), "update", core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, PM2OperationID: id, MemoryMB: 192})
		if err == nil || result != nil || !strings.Contains(err.Error(), "无法持久保存") || queries != 2 {
			t.Fatal("kernel storage refusal was acknowledged or lost", result, err, queries)
		}
		current, _ := os.ReadFile(path)
		failed := filepath.Join(dir, id+".intent.json")
		info, statErr := os.Lstat(failed)
		wantBytes := int64(0)
		if mode == "partial-intent" {
			wantBytes = 64
		}
		if statErr != nil || !moduleRecordInfo(info, false, false) || info.Size() != wantBytes || !bytes.Equal(before, current) {
			t.Fatal("failed original or live ciphertext changed", statErr, info)
		}
		originals := pm2KernelPrivateFileSnapshot(t, dir)
		if _, err = s.modulePM2(context.Background(), "configuration", core.AppModuleInput{ResourceID: app.ID}); err == nil {
			t.Fatal("damaged original was reported as complete")
		}
		if err = s.checkPM2ConfigurationStart(context.Background(), app.ID); err == nil {
			t.Fatal("damaged original allowed a new service start")
		}
		after := pm2KernelPrivateFileSnapshot(t, dir)
		a, _ := json.Marshal(originals)
		z, _ := json.Marshal(after)
		if !bytes.Equal(a, z) || queries != 2 {
			t.Fatal("read-only fault observation changed or replayed the original")
		}
		t.Logf("PM2_KERNEL_IO_ACCEPTED %s original_bytes=%d before_sha=%s unchanged_sha=%s service_mutations=0", mode, info.Size(), pm2ConfigHash(before), pm2ConfigHash(current))
		return
	}
	if mode == "programme-queue" {
		_, _, _, record := pm2ConfigFixtureIntent(t)
		root := programQueueFixture(t)
		dir := filepath.Join(root, "etc/panel/security-apps/modules/pm2-manager/configuration-transactions")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		receipt, _ := json.Marshal(pm2ConfigReceipt{Format: 1, ID: record.Intent.ID, IntentSHA: record.SHA, State: "rolled_back", ManifestSHA: record.Intent.BeforeSHA, FinishedAt: core.Now()})
		for n, raw := range map[string][]byte{record.Intent.ID + ".intent.json": record.Raw, record.Intent.ID + ".result.json": receipt} {
			if err := os.WriteFile(filepath.Join(dir, n), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		originals := pm2KernelPrivateFileSnapshot(t, dir)
		pm2KernelDenyFsync(t)
		reader := &programQueueReader{ctx: context.Background(), root: root}
		if err := reader.pm2Configurations(); !errors.Is(err, unix.EIO) {
			t.Fatal("programme preflight accepted an unacknowledged terminal record", err)
		}
		a, _ := json.Marshal(originals)
		z, _ := json.Marshal(pm2KernelPrivateFileSnapshot(t, dir))
		if !bytes.Equal(a, z) {
			t.Fatal("programme preflight rewrote the original")
		}
		t.Log("PM2_KERNEL_IO_ACCEPTED " + mode + " kernel_fsync=EIO original_records_retained=true")
		return
	}
	s, app, path := pm2StateAppFixture(t)
	dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
	in := core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, PM2OperationID: core.ID(), MemoryMB: 192}
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" {
			t.Fatal("setup attempted a real service mutation", name, args)
		}
		return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
	}
	if mode == "empty-store" {
		d, err := s.openPM2ConfigStore(true)
		if err != nil {
			t.Fatal(err)
		}
		d.Close()
	} else if _, err := s.modulePM2(context.Background(), "update", in); err != nil {
		t.Fatal("healthy original stopped commit failed", err)
	}
	before, _ := os.ReadFile(path)
	originals := pm2KernelPrivateFileSnapshot(t, dir)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("uncertain terminal observation dispatched a service command")
		return "", errors.New("unreachable")
	}
	pm2KernelDenyFsync(t)
	var result any
	var err error
	switch mode {
	case "terminal-report", "empty-store":
		result, err = s.modulePM2(context.Background(), "configuration", core.AppModuleInput{ResourceID: app.ID})
	case "original-nonce":
		result, err = s.modulePM2(context.Background(), "update", in)
	case "start-guard":
		err = s.checkPM2ConfigurationStart(context.Background(), app.ID)
	}
	if !errors.Is(err, unix.EIO) || result != nil {
		t.Fatal("kernel fsync error became a usable terminal result", result, err)
	}
	after, _ := os.ReadFile(path)
	a, _ := json.Marshal(originals)
	z, _ := json.Marshal(pm2KernelPrivateFileSnapshot(t, dir))
	if !bytes.Equal(a, z) || !bytes.Equal(before, after) {
		t.Fatal("uncertain terminal observation changed original records or configuration")
	}
	t.Log("PM2_KERNEL_IO_ACCEPTED " + mode + " kernel_fsync=EIO original_records_and_cipher_retained=true service_mutations=0")
}
