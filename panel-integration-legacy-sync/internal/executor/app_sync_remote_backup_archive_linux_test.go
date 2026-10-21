//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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

func backupArchiveFixture(t *testing.T) (*remoteSyncFixture, string, core.AppModuleInput) {
	t.Helper()
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "old")
	if j := f.run(t, core.ID()); j.State != "succeeded" {
		t.Fatal(j)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "new-content")
	if j := f.run(t, core.ID()); j.State != "succeeded" {
		t.Fatal(j)
	}
	entries, err := os.ReadDir(filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID))
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, e := range entries {
		files, err := os.ReadDir(filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			id = e.Name()
		}
	}
	if !core.ValidID(id) {
		t.Fatal("actual first transfer transaction not found")
	}
	in := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, ResourceID: id}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backup-preview", in)
	if err != nil {
		t.Fatal(err)
	}
	row := out.(map[string]any)["backup_maintenance"].(map[string]any)
	if row["backup_archive_state"] != "reviewed" || row["content_verified"] != true || out.(map[string]any)["remote_files_changed"] != false {
		t.Fatal(out)
	}
	in.ExpectedSHA = row["backup_snapshot_sha256"].(string)
	in.Confirm = "ARCHIVE BACKUP " + id
	return f, id, in
}
func privateFixtureTree(t *testing.T, base string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(base, func(p string, e os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !e.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[strings.TrimPrefix(p, base+"/")] = core.Hash(string(b))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestRemoteSyncBackupArchiveActualTransferReplayAndPreservation(t *testing.T) {
	f, id, in := backupArchiveFixture(t)
	before := privateFixtureTree(t, f.s.remoteSyncDir())
	source := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, id)
	st, err := os.Stat(filepath.Join(source, "staged"))
	if err != nil {
		t.Fatal(err)
	}
	identity := st.Sys().(*syscall.Stat_t)
	out, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in)
	if err != nil {
		t.Fatal(err)
	}
	row := out.(map[string]any)["backup_maintenance"].(map[string]any)
	if row["backup_archive_state"] != "committed" || row["content_verified"] != true {
		t.Fatal(out)
	}
	if _, err = os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("active slot not released", err)
	}
	_, _, destination := remoteBackupArchivePaths(f.cfg, id)
	after, err := os.Stat(filepath.Join(destination, "staged"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Sys().(*syscall.Stat_t).Ino != identity.Ino || after.Sys().(*syscall.Stat_t).Nlink != identity.Nlink || after.Mode() != st.Mode() || remoteFixtureRead(t, filepath.Join(destination, "staged")) != "old" {
		t.Fatal("archive did not preserve actual bytes, inode, links and permissions")
	}
	for relative, digest := range before {
		b, err := os.ReadFile(filepath.Join(f.s.remoteSyncDir(), relative))
		if err != nil || core.Hash(string(b)) != digest {
			t.Fatal("archive changed credentials/checkpoint/plans/jobs", relative, err)
		}
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "new-content" {
		t.Fatal("archive changed public target")
	}
	active, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f))
	if err != nil || active.(map[string]any)["total"] != 1 || active.(map[string]any)["backup_bytes"] != int64(14) {
		t.Fatal(active, err)
	}
	listing := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, Limit: 1}
	archived, err := f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", listing)
	if err != nil || archived.(map[string]any)["total"] != 1 || archived.(map[string]any)["archive_bytes"] != int64(3) || archived.(map[string]any)["content_verified"] != false {
		t.Fatal(archived, err)
	}
	journal, err := os.ReadFile(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, id))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in)
	if err != nil || replay.(map[string]any)["replayed"] != true || replay.(map[string]any)["remote_files_changed"] != false {
		t.Fatal(replay, err)
	}
	current, _ := os.ReadFile(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, id))
	if !bytes.Equal(current, journal) {
		t.Fatal("replay rewrote immutable operation identity")
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "third")
	if job := f.run(t, core.ID()); job.State != "succeeded" {
		t.Fatal(job)
	}
	if remoteFixtureRead(t, filepath.Join(destination, "staged")) != "old" {
		t.Fatal("later transfer deleted old archive")
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{f.secret, string(f.privateKey), f.backup, "new-content"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("archive disclosed private content or authentication")
		}
	}
	t.Log("PASS actual native SFTP archive releases one active slot, retains bytes/inode/links/permissions and all original jobs/checkpoints/credentials, original request replay never moves twice")
}
func TestRemoteSyncBackupArchiveClosedInputsIdleAndStaleContent(t *testing.T) {
	f, id, in := backupArchiveFixture(t)
	before := privateFixtureTree(t, f.s.remoteSyncDir())
	backupBefore := privateFixtureTree(t, f.backup)
	for _, change := range []func(*core.AppModuleInput){func(v *core.AppModuleInput) { v.Password = "not-accepted" }, func(v *core.AppModuleInput) { v.Enabled = true }, func(v *core.AppModuleInput) { v.Path = "../other" }, func(v *core.AppModuleInput) { v.Excludes = []string{"cache"} }, func(v *core.AppModuleInput) { v.ExpectedRevision-- }, func(v *core.AppModuleInput) { v.ExpectedSHA = strings.Repeat("0", 64) }, func(v *core.AppModuleInput) { v.Confirm += " " }} {
		bad := in
		change(&bad)
		if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", bad); err == nil {
			t.Fatal("unsafe closed input accepted", bad)
		}
		if !reflect.DeepEqual(privateFixtureTree(t, f.s.remoteSyncDir()), before) || !reflect.DeepEqual(privateFixtureTree(t, f.backup), backupBefore) {
			t.Fatal("rejection mutated actual records")
		}
	}
	queued := f.queue(t, core.ID())
	if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("archive accepted queued transfer")
	}
	if _, err := f.s.cancelRemoteSync(core.AppModuleInput{RemoteRequestID: queued.ID}); err != nil {
		t.Fatal(err)
	}
	plan := core.AppModuleInput{ResourceID: "archive-paused-plan", SiteID: f.site, RemoteTargetID: f.cfg.ID, RemoteTargetRevision: f.cfg.Revision, Interval: 300, Enabled: true}
	if _, err := f.s.moduleRemoteSync(context.Background(), "schedule-remote-plan", plan); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("archive accepted enabled plan")
	}
	if _, err := f.s.moduleRemoteSync(context.Background(), "pause-remote-plan", core.AppModuleInput{ResourceID: plan.ResourceID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, id, "staged")
	if err := os.WriteFile(p, []byte("OLD"), 0600); err != nil {
		t.Fatal(err)
	} // Existing file mode is intentionally unchanged.
	if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("archive accepted same-length changed content")
	}
	if remoteFixtureRead(t, p) != "OLD" || remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "new-content" {
		t.Fatal("stale digest rejection overwrote external content")
	}
	t.Log("PASS closed credentials/policy/revision/confirmation, actual queued jobs, enabled plan and same-length external content reject archive before remote mutation")
}
func TestRemoteSyncBackupArchiveUnsafeNamespacesAndCapacity(t *testing.T) {
	f, id, in := backupArchiveFixture(t)
	base, _, _ := remoteBackupArchivePaths(f.cfg, id)
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(base, "unknown")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("unknown archive namespace taken over")
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	} // Only this test-created empty rejection fixture.
	// Synthetic empty transaction records exercise exact quota, not 512 actual transfers.
	for i := 0; i < remoteBackupArchiveMax; i++ {
		tx := core.ID()
		_, container, destination := remoteBackupArchivePaths(f.cfg, tx)
		if err := os.Mkdir(container, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(destination, 0700); err != nil {
			t.Fatal(err)
		}
		v := remoteBackupSnapshot{TargetID: f.cfg.ID, TransactionID: tx, Revision: f.cfg.Revision, SpecSHA: f.cfg.SpecSHA, Owner: uint32(os.Geteuid()), Files: []remoteBackupArchiveFile{}}
		r := remoteBackupArchiveRecord{Snapshot: v, SHA: remoteBackupSnapshotSHA(v), State: "committed", CreatedAt: core.Now(), CompletedAt: core.Now()}
		if err := moduleWrite(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, tx), r); err != nil {
			t.Fatal(err)
		}
	}
	query := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, Limit: 1, Offset: 511}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query)
	if err != nil || out.(map[string]any)["total"] != 512 || len(out.(map[string]any)["remote_backup_archive"].([]map[string]any)) != 1 {
		t.Fatal(out, err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("full archive admitted new migration")
	}
	if remoteFixtureRead(t, filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, id, "staged")) != "old" {
		t.Fatal("quota refusal cleaned actual backup")
	}
	if err = os.Mkdir(filepath.Join(base, core.ID()), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query); err == nil {
		t.Fatal("513 remote entries returned partial archive")
	}
	t.Log("PASS native SFTP unknown namespace rejection, synthetic exactly-full 512 archive is readable, full admission and oversized directory fail closed without deleting actual backup")
}
func TestRemoteSyncBackupArchiveExternalMutationAfterCommit(t *testing.T) {
	f, id, in := backupArchiveFixture(t)
	if _, err := f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err != nil {
		t.Fatal(err)
	}
	_, _, destination := remoteBackupArchivePaths(f.cfg, id)
	p := filepath.Join(destination, "staged")
	before := privateFixtureTree(t, f.s.remoteSyncDir())
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, []byte("BAD"), 0600); err != nil {
		t.Fatal(err)
	} // Unlike remoteFixtureWrite, do not chmod this content-only mutation.
	mutated, err := os.Stat(p)
	if err != nil || mutated.Mode() != st.Mode() || mutated.Size() != st.Size() {
		t.Fatal("content-only fixture unexpectedly changed metadata", err)
	}
	preview := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, ResourceID: id}
	for _, action := range []string{"remote-backup-preview", "archive-remote-backup"} {
		body := in
		if action == "remote-backup-preview" {
			body = preview
		}
		if _, err := f.s.moduleRemoteSync(context.Background(), action, body); err == nil {
			t.Fatal("changed archived content declared verified", action)
		}
	}
	if remoteFixtureRead(t, p) != "BAD" || !reflect.DeepEqual(privateFixtureTree(t, f.s.remoteSyncDir()), before) {
		t.Fatal("rejection rewrote external file or original records")
	}
	query := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, Limit: 1}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query)
	if err != nil || out.(map[string]any)["content_verified"] != false {
		t.Fatal("metadata falsely claimed full content verification", out, err)
	}
	if err = os.WriteFile(p, []byte("CHANGED-LENGTH"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query); err == nil {
		t.Fatal("changed metadata silently omitted")
	}
	t.Log("PASS actual same-length archive mutation rejects full-content review and original-key replay; readonly metadata never claims hash verification, changed length fails closed and original evidence remains")
}

func TestRemoteSyncBackupArchiveLogicalByteCapacity(t *testing.T) {
	f, id, in := backupArchiveFixture(t)
	base, _, _ := remoteBackupArchivePaths(f.cfg, id)
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	// Actual sparse native filesystem files exercise metadata quota without
	// consuming 1 GiB of disk. These synthetic ledger hashes are NOT content
	// verification and these are NOT 64 actual completed transfer transactions.
	create := func(size int64, names []string) {
		t.Helper()
		tx := core.ID()
		_, container, destination := remoteBackupArchivePaths(f.cfg, tx)
		for _, p := range []string{container, destination} {
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		}
		v := remoteBackupSnapshot{TargetID: f.cfg.ID, TransactionID: tx, Revision: f.cfg.Revision, SpecSHA: f.cfg.SpecSHA, Owner: uint32(os.Geteuid()), Files: []remoteBackupArchiveFile{}}
		for _, name := range names {
			p := filepath.Join(destination, name)
			file, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err = file.Truncate(size); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(p)
			if err != nil || st.Size() != size || size > 1 && st.Sys().(*syscall.Stat_t).Blocks*512 >= size {
				t.Fatal("quota fixture is not actual logical sparse metadata", err)
			}
			v.Files = append(v.Files, remoteBackupArchiveFile{name, moduleFile{SHA: core.Hash("synthetic metadata only " + tx + name), Size: size, Mode: 0600}})
		}
		r := remoteBackupArchiveRecord{Snapshot: v, SHA: remoteBackupSnapshotSHA(v), State: "committed", CreatedAt: core.Now(), CompletedAt: core.Now()}
		if err := moduleWrite(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, tx), r); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 64; i++ {
		create(8<<20, []string{"previous", "staged"})
	}
	query := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, Limit: 1, Offset: 63}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query)
	if err != nil || out.(map[string]any)["total"] != 64 || out.(map[string]any)["archive_bytes"] != int64(1<<30) || out.(map[string]any)["content_verified"] != false {
		t.Fatal("exactly full logical archive not readable", out, err)
	}
	before := privateFixtureTree(t, f.s.remoteSyncDir())
	if _, err = f.s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("1 GiB full archive accepted another actual backup")
	}
	if !reflect.DeepEqual(privateFixtureTree(t, f.s.remoteSyncDir()), before) || remoteFixtureRead(t, filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, id, "staged")) != "old" {
		t.Fatal("byte budget refusal modified actual source or records")
	}
	create(1, []string{"staged"})
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backup-archive", query); err == nil {
		t.Fatal("over-budget actual inventory returned partial report")
	}
	t.Log("PASS actual native sparse metadata exactly 1 GiB is readable without claiming hashes or physical disk use; new real archive admission and 1 GiB+1 inventory fail closed, actual backup retained")
}

// Test-only packet framing forwards the exact native OpenSSH response bytes.
// Withhold ONLY a successful mkdir/rename reply AFTER the actual filesystem
// change, so the parent can SIGKILL before the next local/remote transition.
// No filesystem metadata/result is fabricated and production contains no hook.
type remoteBackupReplyGate struct {
	source, destination string
	action              byte
	umask               string
	renameID            atomic.Uint32
	notified            atomic.Bool
	reached, release    chan struct{}
}
type remoteBackupGateReader struct {
	source  io.Reader
	gate    *remoteBackupReplyGate
	pending []byte
}

func (r *remoteBackupGateReader) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		header := make([]byte, 4)
		if _, err := io.ReadFull(r.source, header); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(header)
		if n > 1<<20 || n < 1 {
			return 0, errors.New("owned gate frame bound")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r.source, b); err != nil {
			return 0, err
		}
		if len(b) > 9 && b[0] == r.gate.action {
			payload := bytes.NewReader(b[5:])
			readString := func() (string, error) {
				var size uint32
				if err := binary.Read(payload, binary.BigEndian, &size); err != nil {
					return "", err
				}
				if size > 2048 || size > uint32(payload.Len()) {
					return "", errors.New("owned gate path bound")
				}
				v := make([]byte, size)
				_, err := io.ReadFull(payload, v)
				return string(v), err
			}
			old, e1 := readString()
			match := e1 == nil && r.gate.action == 14 && old == r.gate.destination
			if r.gate.action == 18 {
				next, e2 := readString()
				match = e1 == nil && e2 == nil && old == r.gate.source && next == r.gate.destination
			}
			if match {
				r.gate.renameID.Store(binary.BigEndian.Uint32(b[1:5]))
			}
		}
		r.pending = append(header, b...)
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

type remoteBackupGateWriter struct {
	target  io.Writer
	gate    *remoteBackupReplyGate
	pending []byte
}

func (w *remoteBackupGateWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for len(w.pending) >= 4 {
		n := int(binary.BigEndian.Uint32(w.pending[:4]))
		if n < 1 || n > 1<<20 {
			return 0, errors.New("owned reply frame bound")
		}
		if len(w.pending) < n+4 {
			break
		}
		packet := w.pending[:n+4]
		if n >= 9 && packet[4] == 101 && w.gate.renameID.Load() != 0 && binary.BigEndian.Uint32(packet[5:9]) == w.gate.renameID.Load() && binary.BigEndian.Uint32(packet[9:13]) == 0 && w.gate.notified.CompareAndSwap(false, true) {
			close(w.gate.reached)
			<-w.gate.release
		}
		written, err := w.target.Write(packet)
		if err != nil {
			return 0, err
		}
		if written != len(packet) {
			return 0, io.ErrShortWrite
		}
		w.pending = w.pending[n+4:]
	}
	return len(p), nil
}
func TestRemoteSyncBackupArchiveTrueMidMoveKill(t *testing.T) {
	backupArchiveGenuineKill(t, "rename")
}

func TestRemoteSyncBackupArchiveTruePreparedKill(t *testing.T) {
	for _, phase := range []string{"base-mkdir", "container-mkdir"} {
		t.Run(phase, func(t *testing.T) { backupArchiveGenuineKill(t, phase) })
	}
}

func backupArchiveGenuineKill(t *testing.T, phase string) {
	t.Helper()
	if base := os.Getenv("PANEL_BACKUP_ARCHIVE_KILL_CHILD"); base != "" {
		if !filepath.IsAbs(base) || !strings.Contains(base, strings.Split(t.Name(), "/")[0]) || filepath.Base(base) != "security" {
			t.Fatal("not owned private test namespace")
		}
		s := New(Config{SecurityDir: base})
		cfg, err := s.readRemoteConfig(os.Getenv("PANEL_BACKUP_ARCHIVE_TARGET"))
		if err != nil {
			t.Fatal(err)
		}
		id := os.Getenv("PANEL_BACKUP_ARCHIVE_TX")
		in := core.AppModuleInput{RemoteTargetID: cfg.ID, ExpectedRevision: cfg.Revision, ResourceID: id, ExpectedSHA: os.Getenv("PANEL_BACKUP_ARCHIVE_SHA"), Confirm: "ARCHIVE BACKUP " + id}
		if _, err = s.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err != nil {
			t.Fatal(err)
		}
		t.Fatal("parent did not kill before local archive commit")
	}
	f, id, in := backupArchiveFixture(t)
	source := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID, id)
	base, container, destination := remoteBackupArchivePaths(f.cfg, id)
	gate := &remoteBackupReplyGate{action: 18, source: source, destination: destination, reached: make(chan struct{}), release: make(chan struct{})}
	expectedState := "reserved"
	if phase != "rename" {
		gate.action, gate.umask, expectedState = 14, "022", "prepared"
		gate.destination = base
		if phase == "container-mkdir" {
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			gate.destination = container
		}
	}
	f.archiveReplyGate.Store(gate)
	var release sync.Once
	defer release.Do(func() { close(gate.release) })
	before := privateFixtureTree(t, f.s.remoteSyncDir())
	child := exec.Command(os.Args[0], "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$", "-test.v", "-test.timeout=45s")
	child.Env = append(os.Environ(), "PANEL_BACKUP_ARCHIVE_KILL_CHILD="+f.s.Config.SecurityDir, "PANEL_BACKUP_ARCHIVE_TARGET="+f.cfg.ID, "PANEL_BACKUP_ARCHIVE_TX="+id, "PANEL_BACKUP_ARCHIVE_SHA="+in.ExpectedSHA)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	defer func() {
		if !killed {
			child.Process.Kill()
			child.Wait()
		}
	}()
	select {
	case <-gate.reached:
	case <-time.After(25 * time.Second):
		child.Process.Kill()
		child.Wait()
		killed = true
		t.Fatal("actual native mutation response not reached", phase, output.String())
	}
	r, err := f.s.readRemoteBackupArchiveRecord(f.cfg.ID, id)
	if err != nil || r.State != expectedState {
		t.Fatal("actual journal not at expected interrupted phase", phase, r, err)
	}
	if phase == "rename" {
		if _, err = os.Lstat(source); !os.IsNotExist(err) || remoteFixtureRead(t, filepath.Join(destination, "staged")) != "old" {
			t.Fatal("actual OpenSSH rename did not occur before kill")
		}
	} else {
		st, err := os.Stat(gate.destination)
		children, readErr := os.ReadDir(gate.destination)
		if err != nil || readErr != nil || st.Mode().Perm() != 0755 || len(children) != 0 || remoteFixtureRead(t, filepath.Join(source, "staged")) != "old" {
			t.Fatal("actual native umask-022 mkdir did not leave original source and empty 0755 prepared namespace", phase, err, readErr)
		}
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child.Process.Pid), "status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		for _, key := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
			if strings.HasPrefix(line, key) && strings.TrimSpace(strings.TrimPrefix(line, key)) != "0000000000000000" {
				t.Fatal("child widened capabilities", key)
			}
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1") {
		t.Fatal("child lost no-new-privileges")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	killed = true
	exit, ok := err.(*exec.ExitError)
	if !ok || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("not genuine SIGKILL", err)
	}
	release.Do(func() { close(gate.release) })
	f.archiveReplyGate.Store(nil)
	fresh := New(Config{SecurityDir: f.s.Config.SecurityDir})
	cfg, err := fresh.readRemoteConfig(f.cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := fresh.remoteBackupArchivePending(cfg.ID); err != nil || !pending {
		t.Fatal("restart lost original pending identity", pending, err)
	}
	if busy, err := fresh.remoteTargetBusy(cfg.ID); err != nil || !busy {
		t.Fatal("pending archive did not fence new transfer", busy, err)
	}
	if err = fresh.remoteSyncUninstallPreflight(); err == nil {
		t.Fatal("pending archive permitted uninstall")
	}
	if _, err = fresh.moduleRemoteSync(context.Background(), "archive-remote-backup", in); err == nil {
		t.Fatal("blind re-submit accepted interrupted archive")
	}
	if phase != "rename" {
		query := core.AppModuleInput{RemoteTargetID: cfg.ID, ExpectedRevision: cfg.Revision, Limit: 1}
		out, err := fresh.moduleRemoteSync(context.Background(), "remote-backup-archive", query)
		st, statErr := os.Stat(gate.destination)
		if err != nil || statErr != nil || st.Mode().Perm() != 0755 || out.(map[string]any)["remote_files_changed"] != false || out.(map[string]any)["archive_bytes"] != int64(0) {
			t.Fatal("read-only prepared inventory repaired permissions or claimed moved bytes", phase, out, err)
		}
		original, err := os.ReadFile(fresh.remoteBackupArchiveRecordPath(cfg.ID, id))
		if err != nil {
			t.Fatal(err)
		}
		unknown := filepath.Join(gate.destination, "unknown-owned-test-only")
		if err = os.WriteFile(unknown, []byte("do-not-touch"), 0600); err != nil {
			t.Fatal(err)
		}
		bad := in
		bad.Confirm = "RECOVER BACKUP " + id
		for _, action := range []string{"remote-backup-archive", "recover-remote-backup"} {
			body := bad
			if action == "remote-backup-archive" {
				body = query
			}
			if _, err = fresh.moduleRemoteSync(context.Background(), action, body); err == nil {
				t.Fatal("unknown nonempty prepared namespace was taken over", phase, action)
			}
		}
		st, err = os.Stat(gate.destination)
		if err != nil || st.Mode().Perm() != 0755 || remoteFixtureRead(t, unknown) != "do-not-touch" {
			t.Fatal("unknown prepared directory rejection altered permissions or file", phase, err)
		}
		if err = os.Remove(unknown); err != nil {
			t.Fatal(err)
		} // Remove only this newly-created private rejection-test file.
		p := filepath.Join(source, "staged")
		if err = os.WriteFile(p, []byte("BAD"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = fresh.moduleRemoteSync(context.Background(), "recover-remote-backup", bad); err == nil {
			t.Fatal("prepared permission repair accepted stale original content")
		}
		st, err = os.Stat(gate.destination)
		current, readErr := os.ReadFile(fresh.remoteBackupArchiveRecordPath(cfg.ID, id))
		if err != nil || readErr != nil || st.Mode().Perm() != 0755 || !bytes.Equal(current, original) || remoteFixtureRead(t, p) != "BAD" {
			t.Fatal("stale prepared recovery changed permissions, evidence or content", phase, err, readErr)
		}
		if err = os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	in.Confirm = "RECOVER BACKUP " + id
	out, err := fresh.moduleRemoteSync(context.Background(), "recover-remote-backup", in)
	if err != nil || out.(map[string]any)["recovered"] != true {
		t.Fatal(out, err)
	}
	for relative, digest := range before {
		b, err := os.ReadFile(filepath.Join(f.s.remoteSyncDir(), relative))
		if err != nil || core.Hash(string(b)) != digest {
			t.Fatal("recovery changed original credentials/jobs/checkpoint", relative, err)
		}
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "new-content" {
		t.Fatal("recovery changed public target")
	}
	if pending, err := fresh.remoteBackupArchivePending(cfg.ID); err != nil || pending {
		t.Fatal("explicit verified recovery did not clear fence", pending, err)
	}
	for _, p := range []string{base, container, destination} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0700 {
			t.Fatal("explicit recovery did not retain private archive", p, err)
		}
	}
	again, err := fresh.moduleRemoteSync(context.Background(), "recover-remote-backup", in)
	if err != nil || again.(map[string]any)["replayed"] != true {
		t.Fatal(again, err)
	}
	if phase == "rename" {
		t.Log("PASS true SIGKILL after actual native OpenSSH directory move and BEFORE local archive commit; fresh service fences transfer/uninstall, explicit original-digest recovery retains all bytes and original jobs/credentials/checkpoint, replay never moves twice")
	} else {
		t.Log("PASS true SIGKILL after actual native OpenSSH umask-022 mkdir BEFORE chmod/reservation; read-only inventory retains empty 0755 prepared namespace, explicit original-digest recovery alone narrows permissions and archives once", phase)
	}
}
