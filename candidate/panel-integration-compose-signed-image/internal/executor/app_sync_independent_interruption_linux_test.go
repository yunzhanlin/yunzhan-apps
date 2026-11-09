//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Test-only framing forwards original native OpenSSH packets. On the second
// read-only open of the selected archived file (after the full source review),
// hold one genuine DATA reply after the first 32 KiB reached the local copy.
// No data, status or filesystem result is synthesized; production has no hook.
type remoteIndependentReadGate struct {
	source           string
	opens            atomic.Int32
	openID, readID   atomic.Uint32
	handle           atomic.Pointer[string]
	notified         atomic.Bool
	reached, release chan struct{}
}
type remoteIndependentGateReader struct {
	source  io.Reader
	gate    *remoteIndependentReadGate
	pending []byte
}

func independentPacketString(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n > 2048 || n > len(b)-4 {
		return "", nil, errors.New("owned read gate string bound")
	}
	return string(b[4 : 4+n]), b[4+n:], nil
}
func (r *remoteIndependentGateReader) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		header := make([]byte, 4)
		if _, err := io.ReadFull(r.source, header); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(header)
		if n < 1 || n > 1<<20 {
			return 0, errors.New("owned read gate frame bound")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r.source, b); err != nil {
			return 0, err
		}
		if len(b) >= 9 {
			value, rest, err := independentPacketString(b[5:])
			if err == nil && b[0] == 3 && value == r.gate.source && r.gate.opens.Add(1) == 2 {
				r.gate.openID.Store(binary.BigEndian.Uint32(b[1:5]))
			}
			if err == nil && b[0] == 5 && len(rest) >= 8 {
				if h := r.gate.handle.Load(); h != nil && value == *h && binary.BigEndian.Uint64(rest[:8]) == 32768 {
					r.gate.readID.Store(binary.BigEndian.Uint32(b[1:5]))
				}
			}
		}
		r.pending = append(header, b...)
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

type remoteIndependentGateWriter struct {
	target  io.Writer
	gate    *remoteIndependentReadGate
	pending []byte
}

func (w *remoteIndependentGateWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for len(w.pending) >= 4 {
		n := int(binary.BigEndian.Uint32(w.pending[:4]))
		if n < 1 || n > 1<<20 {
			return 0, errors.New("owned read gate reply bound")
		}
		if len(w.pending) < n+4 {
			break
		}
		packet := w.pending[:n+4]
		if n >= 5 {
			request := binary.BigEndian.Uint32(packet[5:9])
			if packet[4] == 102 && request == w.gate.openID.Load() && request != 0 {
				handle, _, err := independentPacketString(packet[9:])
				if err != nil {
					return 0, err
				}
				w.gate.handle.Store(&handle)
			}
			if packet[4] == 103 && request == w.gate.readID.Load() && request != 0 && w.gate.notified.CompareAndSwap(false, true) {
				close(w.gate.reached)
				<-w.gate.release
			}
		}
		n, err := w.target.Write(packet)
		if err != nil {
			return 0, err
		}
		if n != len(packet) {
			return 0, io.ErrShortWrite
		}
		w.pending = w.pending[len(packet):]
	}
	return len(p), nil
}
func TestRemoteIndependentCopyTrueMidReadKillPreservesPartialAndRecovers(t *testing.T) {
	if base := os.Getenv("PANEL_INDEPENDENT_COPY_KILL_CHILD"); base != "" {
		// testing.TempDir bounds long test-name prefixes. Bind the stable,
		// distinctive prefix and exact private leaf rather than the truncated tail.
		if !filepath.IsAbs(base) || !strings.Contains(filepath.Clean(base), string(filepath.Separator)+"TestRemoteIndependentCopyTrueMidReadKill") || filepath.Base(base) != "security" {
			t.Fatal("not an owned temporary test namespace")
		}
		s := New(Config{SecurityDir: base})
		cfg, err := s.readRemoteConfig(os.Getenv("PANEL_INDEPENDENT_COPY_TARGET"))
		if err != nil {
			t.Fatal(err)
		}
		id := os.Getenv("PANEL_INDEPENDENT_COPY_TX")
		in := core.AppModuleInput{RemoteTargetID: cfg.ID, ExpectedRevision: cfg.Revision, ResourceID: id, ExpectedSHA: os.Getenv("PANEL_INDEPENDENT_COPY_SHA"), Confirm: "COPY BACKUP " + id}
		if _, err = s.moduleRemoteSync(context.Background(), "copy-remote-backup", in); err != nil {
			t.Fatal(err)
		}
		t.Fatal("parent did not interrupt the genuine native read")
	}
	f := newRemoteSyncFixture(t)
	content := strings.Repeat("original-content-", 65536)
	fixtureWrite(t, f.s, f.site, "copy.txt", content)
	if job := f.run(t, core.ID()); job.State != "succeeded" {
		t.Fatal(job)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "new-content")
	if job := f.run(t, core.ID()); job.State != "succeeded" {
		t.Fatal(job)
	}
	entries, err := os.ReadDir(filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID))
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, e := range entries {
		files, err := os.ReadDir(filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			id = e.Name()
		}
	}
	in := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, ResourceID: id}
	out, err := f.s.moduleRemoteSync(t.Context(), "remote-backup-preview", in)
	if err != nil {
		t.Fatal(err)
	}
	row := out.(map[string]any)["backup_maintenance"].(map[string]any)
	in.ExpectedSHA = row["backup_snapshot_sha256"].(string)
	in.Confirm = "ARCHIVE BACKUP " + id
	if _, err = f.s.moduleRemoteSync(t.Context(), "archive-remote-backup", in); err != nil {
		t.Fatal(err)
	}
	if err = moduleWrite(filepath.Join(f.s.moduleDir("files-sync"), "installed.json"), map[string]any{"id": "files-sync", "version": appcatalog.FilesSyncIndependentBackupVersion, "settings": map[string]any{}, "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	_, _, remote := remoteBackupArchivePaths(f.cfg, id)
	originalTree := privateFixtureTree(t, f.backup)
	checkpoint, _ := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	gate := &remoteIndependentReadGate{source: filepath.Join(remote, "staged"), reached: make(chan struct{}), release: make(chan struct{})}
	f.independentReadGate.Store(gate)
	var once sync.Once
	defer once.Do(func() { close(gate.release) })
	child := exec.Command(os.Args[0], "-test.run=^TestRemoteIndependentCopyTrueMidReadKillPreservesPartialAndRecovers$", "-test.v", "-test.timeout=45s")
	child.Env = append(os.Environ(), "PANEL_INDEPENDENT_COPY_KILL_CHILD="+f.s.Config.SecurityDir, "PANEL_INDEPENDENT_COPY_TARGET="+f.cfg.ID, "PANEL_INDEPENDENT_COPY_TX="+id, "PANEL_INDEPENDENT_COPY_SHA="+in.ExpectedSHA)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			child.Process.Kill()
			child.Wait()
		}
	}()
	select {
	case <-gate.reached:
	case <-time.After(25 * time.Second):
		child.Process.Kill()
		child.Wait()
		waited = true
		t.Fatal("native read gate not reached", output.String())
	}
	original, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || original.Result != nil || len(original.Attempts) != 1 {
		t.Fatal(original, err)
	}
	d, err := f.s.remoteCopyDirectory(f.cfg.ID, id, original.Attempts[0], false)
	if err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(d.paths[len(d.paths)-1], "staged")
	d.Close()
	before, err := os.Stat(partial)
	data, readErr := os.ReadFile(partial)
	if err != nil || readErr != nil || before.Size() != 32768 || string(data) != content[:32768] {
		t.Fatal("no actual partial local bytes before kill", before, err, readErr)
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child.Process.Pid), "status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		for _, key := range []string{"CapPrm:", "CapEff:", "CapAmb:"} {
			if strings.HasPrefix(line, key) && strings.TrimSpace(strings.TrimPrefix(line, key)) != "0000000000000000" {
				t.Fatal("unprivileged child gained capabilities", key)
			}
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1") {
		t.Fatal("NoNewPrivileges missing")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	waited = true
	exit, ok := err.(*exec.ExitError)
	if !ok || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("not genuine child SIGKILL", err)
	}
	once.Do(func() { close(gate.release) })
	f.independentReadGate.Store(nil)
	fresh := New(Config{SecurityDir: f.s.Config.SecurityDir})
	record, err := fresh.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || record.Result != nil || record.Bytes != 32768 {
		t.Fatal("interruption was not retained as partial", record, err)
	}
	in.ExpectedSHA, in.Confirm = remoteCopyStateSHA(record), "RECOVER COPY "+id
	if _, err = fresh.moduleRemoteSync(t.Context(), "recover-remote-copy", in); err != nil {
		t.Fatal(err)
	}
	complete, local := independentOriginal(t, &remoteSyncFixture{s: fresh, cfg: f.cfg}, id)
	after, _ := os.Stat(partial)
	preserved, _ := os.ReadFile(partial)
	finished, _ := os.ReadFile(local)
	if !os.SameFile(before, after) || !bytes.Equal(data, preserved) || string(finished) != content || len(complete.Attempts) != 2 || complete.Result.AttemptID == original.Attempts[0] {
		t.Fatal("recovery replaced original fragment or did not create a separate complete copy")
	}
	currentCheckpoint, _ := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	if !reflect.DeepEqual(originalTree, privateFixtureTree(t, f.backup)) || !bytes.Equal(checkpoint, currentCheckpoint) {
		t.Fatal("real interruption/recovery changed original remote bytes or checkpoint")
	}
	t.Logf("actual_native_read_partial_bytes=%d actual_signal=SIGKILL preserved_original_inode=true new_complete_attempt=true source_bytes=%d", len(data), len(content))
}
