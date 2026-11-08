//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func remoteBackupQuery(f *remoteSyncFixture) core.AppModuleInput {
	return core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, Limit: 16}
}
func TestRemoteSyncBackupsActualTransfersReadOnlyAndPrivateContent(t *testing.T) {
	f := newRemoteSyncFixture(t)
	in := remoteBackupQuery(f)
	if _, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", in); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatal("read-only empty query created namespace", err)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "old")
	if j := f.run(t, core.ID()); j.State != "succeeded" {
		t.Fatal(j)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "new-content")
	if j := f.run(t, core.ID()); j.State != "succeeded" {
		t.Fatal(j)
	}
	before := map[string]string{}
	err := filepath.WalkDir(base, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			b, er := os.ReadFile(p)
			if er != nil {
				return er
			}
			before[p] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", in)
	if err != nil {
		t.Fatal(err)
	}
	v := out.(map[string]any)
	rows := v["remote_backups"].([]remoteBackupTransaction)
	if len(rows) != 2 || v["total"] != 2 || v["backup_bytes"] != int64(17) || v["remote_files_changed"] != false || v["next_transaction_capacity_available"] != true {
		t.Fatal(v)
	}
	for p, value := range before {
		if remoteFixtureRead(t, p) != value {
			t.Fatal("inventory changed original file", p)
		}
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "new-content" {
		t.Fatal("public target changed")
	}
	raw, _ := json.Marshal(v)
	for _, secret := range []string{f.secret, string(f.privateKey), "new-content", f.root, f.backup} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private content/path disclosed")
		}
	}
	if in.Offset = 1; in.Offset != 0 {
		paged, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", in)
		if err != nil || len(paged.(map[string]any)["remote_backups"].([]remoteBackupTransaction)) != 1 {
			t.Fatal(paged, err)
		}
	}
	t.Log("PASS actual native SFTP old/new backups, byte totals, pagination and read-only content preservation")
}
func TestRemoteSyncBackupsExactlyFullAndOversizedNamespace(t *testing.T) {
	f := newRemoteSyncFixture(t)
	base := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	// Synthetic empty records test quota; do not claim 512 real transfers.
	for i := 0; i < remoteBackupTransactions; i++ {
		if err := os.Mkdir(filepath.Join(base, core.ID()), 0700); err != nil {
			t.Fatal(err)
		}
	}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f))
	if err != nil {
		t.Fatal(err)
	}
	v := out.(map[string]any)
	if v["total"] != 512 || v["transaction_slots_available"] != 0 || v["next_transaction_capacity_available"] != false {
		t.Fatal(v)
	}
	conn, err := f.s.dialRemoteSync(context.Background(), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	owner, err := remoteRoots(conn.client, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remoteNamespace(conn.client, f.cfg, owner); err == nil {
		t.Fatal("full quota admitted new transaction")
	}
	if err = os.Mkdir(filepath.Join(base, core.ID()), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f)); err == nil {
		t.Fatal("513 records returned incomplete inventory")
	}
	t.Log("PASS exactly-full actual native SFTP inventory remains readable; 513 entries fail closed, no evidence cleaned")
}
func TestRemoteSyncBackupsSparseByteQuotaAndUnsafeEntries(t *testing.T) {
	f := newRemoteSyncFixture(t)
	base := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		dir := filepath.Join(base, core.ID())
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"staged", "previous"} {
			file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = file.Truncate(8 << 20)
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f))
	if err != nil {
		t.Fatal(err)
	}
	v := out.(map[string]any)
	if v["backup_bytes"] != remoteBackupBytes || v["bytes_available"] != int64(0) || v["next_transaction_capacity_available"] != false {
		t.Fatal(v)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, entries[0].Name())
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f)); err == nil {
		t.Fatal("unsafe private permissions omitted")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(dir, "unknown")
	if err = os.WriteFile(unknown, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f)); err == nil {
		t.Fatal("unknown child omitted")
	}
	if err = os.Remove(unknown); err != nil {
		t.Fatal(err)
	} // owned disposable rejection fixture
	link := filepath.Join(base, core.ID())
	if err = os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f)); err == nil {
		t.Fatal("directory symlink counted")
	}
	t.Log("PASS real SFTP metadata of synthetic 256 MiB sparse files, exact full byte quota, unsafe modes/unknown children/symlink rejection")
}
func TestRemoteSyncBackupsClosedInputsAndPendingRecovery(t *testing.T) {
	f := newRemoteSyncFixture(t)
	good := remoteBackupQuery(f)
	bad := []core.AppModuleInput{}
	for _, change := range []func(*core.AppModuleInput){func(in *core.AppModuleInput) { in.Password = "never-send" }, func(in *core.AppModuleInput) { in.SiteID = f.site }, func(in *core.AppModuleInput) { in.Limit = 33 }, func(in *core.AppModuleInput) { in.Offset = 513 }, func(in *core.AppModuleInput) { in.ExpectedRevision++ }, func(in *core.AppModuleInput) { in.Enabled = true }} {
		in := good
		change(&in)
		bad = append(bad, in)
	}
	for _, in := range bad {
		if _, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", in); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual")
	j := f.run(t, core.ID())
	if j.State != "succeeded" {
		t.Fatal(j)
	}
	cp, err := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	cp.Pending = &remoteSyncPending{ID: entries[0].Name(), JobID: j.ID, Path: "copy.txt", New: cp.Files["copy.txt"]}
	if err = moduleWrite(f.s.remoteCheckpointPath(f.cfg.ID), cp); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", good)
	if err != nil {
		t.Fatal(err)
	}
	v := out.(map[string]any)
	rows := v["remote_backups"].([]remoteBackupTransaction)
	if v["pending_recovery"] != true || !rows[0].Pending {
		t.Fatal("pending recovery hidden", v)
	}
	after, err := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if err != nil || !reflect.DeepEqual(cp, after) {
		t.Fatal("query silently recovered or altered checkpoint", err)
	}
	t.Log("PASS closed policy/credential input rejection and pending transaction reported without executing recovery")
}
