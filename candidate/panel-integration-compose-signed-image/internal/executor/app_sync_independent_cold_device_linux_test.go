//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func TestRemoteIndependentCopyLegacyDeviceWitnessKeepsOfflineReadAndOriginalReceipt(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	if _, err := f.s.moduleRemoteSync(t.Context(), "copy-remote-backup", in); err != nil {
		t.Fatal(err)
	}
	r, local := independentOriginal(t, f, id)
	// An old completed receipt on the same persistent filesystem can carry a
	// different device number after cold enumeration. No other field changes.
	result := *r.Result
	result.Files = append([]remoteCopyFile(nil), r.Result.Files...)
	for i := range result.Files {
		result.Files[i].Device += 16
	}
	receipt := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(local))), "result.json")
	if err := moduleWrite(receipt, result); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(receipt)
	f.listener.Close()
	current, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || current.Result == nil {
		t.Fatal(current, err)
	}
	if err = f.s.verifyRemoteCopy(current); err != nil {
		t.Fatal("offline verification rejected only a past boot device number", err)
	}
	chunk, err := f.s.remoteIndependentChunk(f.cfg.ID, id, "staged", 0, r.SHA)
	if err != nil || string(chunk.Bytes) != "old" || chunk.FileSHA != core.Hash("old") {
		t.Fatal(chunk, err)
	}
	after, _ := os.Lstat(receipt)
	actual, _ := os.ReadFile(receipt)
	if !os.SameFile(before, after) || !bytes.Equal(original, actual) {
		t.Fatal("read rewrote the original receipt")
	}
	// Keep all substantive bindings, including the recorded group, strict.
	for _, name := range []string{"inode", "uid", "gid", "mode", "bytes", "sha256"} {
		t.Run(name, func(t *testing.T) {
			bad := result
			bad.Files = append([]remoteCopyFile(nil), result.Files...)
			switch name {
			case "inode":
				bad.Files[0].Inode++
			case "uid":
				bad.Files[0].UID++
			case "gid":
				bad.Files[0].GID++
			case "mode":
				bad.Files[0].Mode = 0644
			case "bytes":
				bad.Files[0].Bytes++
			case "sha256":
				bad.Files[0].SHA = core.Hash("different")
			}
			if err := moduleWrite(receipt, bad); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.readRemoteCopyRecord(f.cfg.ID, id); err == nil {
				t.Fatal("changed durable identity accepted", name)
			}
			if err := moduleWrite(receipt, result); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemoteIndependentCopyRetainedDeviceWitnessPreservesOriginalCondition(t *testing.T) {
	f, id, _ := independentCopyFixture(t)
	r, _, _ := seedIndependentAttempt(t, f, id, []byte("o"))
	in := core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, ResourceID: id, ExpectedSHA: remoteCopyStateSHA(r), Confirm: "RETAIN COPY " + id}
	if _, err := f.s.retainRemoteCopy(f.cfg, in); err != nil {
		t.Fatal(err)
	}
	r, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || r.Retained == nil {
		t.Fatal(err)
	}
	retained := *r.Retained
	retained.Files = append([]remoteCopyFile(nil), r.Retained.Files...)
	for i := range retained.Files {
		retained.Files[i].Device += 16
	}
	path := filepath.Join(f.s.remoteSyncDir(), "independent-backups", f.cfg.ID, id, "retained.json")
	if err := moduleWrite(path, retained); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	beforeInfo, _ := os.Lstat(path)
	r, err = f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || r.Retained == nil {
		t.Fatal(err)
	}
	in.ExpectedSHA = remoteCopyStateSHA(r)
	if _, err = f.s.retainRemoteCopy(f.cfg, in); err != nil {
		t.Fatal("offline explicit original-condition replay", err)
	}
	after, _ := os.ReadFile(path)
	afterInfo, _ := os.Lstat(path)
	if !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("retained receipt was rewritten")
	}
}

func TestRemoteUnpublishedCopyRetainedDeviceWitnessPreservesOriginalSnapshotSHA(t *testing.T) {
	s, cfg, in, base := unpublishedFixture(t, []byte("untrusted partial original"))
	v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedSHA = v.SHA
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, remoteUnpublishedReceipt)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt remoteUnpublishedRetention
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Snapshot.Directory.Device += 16
	for i := range receipt.Snapshot.Fragments {
		receipt.Snapshot.Fragments[i].Device += 16
	}
	receipt.SnapshotSHA = remoteUnpublishedSHA(receipt.Snapshot)
	if err = moduleWrite(path, receipt); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	beforeInfo, _ := os.Lstat(path)
	current, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || current.Retained == nil || current.SHA != receipt.SnapshotSHA {
		t.Fatal(current, err)
	}
	in.ExpectedSHA = receipt.SnapshotSHA
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal("old persisted exact condition rejected", err)
	}
	after, _ := os.ReadFile(path)
	afterInfo, _ := os.Lstat(path)
	if !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("opaque original closure receipt rewritten")
	}
}

func TestRemoteIndependentRootRejectCurrentCrossFilesystemFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native Root mount fixture")
	}
	s, _, _ := appReliabilityFixture(t)
	d, err := s.remoteCopyDirectory("owned-target", core.ID(), core.ID(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	name := filepath.Join(d.paths[len(d.paths)-1], "staged")
	if err = os.WriteFile(name, []byte("local"), 0600); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.MkdirTemp("/dev/shm", "panel-owned-independent-device-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(foreign); err != nil {
			t.Error(err)
		}
	})
	outside := filepath.Join(foreign, "source")
	if err = os.WriteFile(outside, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	moduleTestBind(t, outside, name)
	info, err := d.Lstat("staged")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remoteCopyFileMetadata(d, info, "staged", ""); err == nil {
		t.Fatal("live file outside its held private filesystem accepted")
	}
	actual, _ := os.ReadFile(outside)
	if string(actual) != "other" {
		t.Fatal("foreign bytes changed")
	}
}
