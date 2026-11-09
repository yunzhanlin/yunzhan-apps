//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// A separate original native unit runs these tests with the ACTUAL existing
// executor group, not a synthetic setegid inside a concurrent Go process. No
// installation/account/host-directory creation is authorized by this fixture.
func streamRPCGroupNativeFixture(t *testing.T) (*os.Root, string) {
	t.Helper()
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Getenv("PANEL_LBSTREAM_RPC_GROUP_NATIVE") != "1" {
		t.Skip("explicit actual Root:panel native filesystem component only")
	}
	gid, err := strconv.Atoi(os.Getenv("PANEL_LBSTREAM_RPC_GROUP_GID"))
	if err != nil || gid < 1 || gid > 1<<30 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != gid || os.Getegid() != gid {
		t.Fatal("actual separately measured Root:panel process profile required")
	}
	path := t.TempDir()
	if threatIDSTrustedParents(path, false) != nil {
		t.Fatal("trusted private original native fixture required")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, path
}

func TestLoadBalanceStreamRPCGroupNativeFreshPrivateDirectoriesAndOldRefusal(t *testing.T) {
	root, path := streamRPCGroupNativeFixture(t)
	if err := createStreamRootPrivateDirectory(root, "new-private"); err != nil {
		t.Fatal("actual Root:panel could not create new Root:Root private record directory", err)
	}
	info, err := root.Lstat("new-private")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		t.Fatal("new directory did not retain strict Root:Root 0700 boundary", err)
	}
	if err := createStreamRootPrivateDirectory(root, "new-private"); !errors.Is(err, os.ErrExist) {
		t.Fatal("old new-private directory was adopted/repaired", err)
	}
	if after, err := root.Lstat("new-private"); err != nil || !geoStoreStableInfo(info, after) {
		t.Fatal("old original directory metadata changed")
	}
	if err := os.Mkdir(filepath.Join(path, "old-panel-group"), 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := root.Lstat("old-panel-group")
	owner := before.Sys().(*syscall.Stat_t)
	if owner.Gid != uint32(os.Getegid()) {
		t.Fatal("fixture was not created with the actual executor group")
	}
	if err := createStreamRootPrivateDirectory(root, "old-panel-group"); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing foreign-group directory repaired", err)
	}
	after, err := root.Lstat("old-panel-group")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("foreign-group refusal changed original metadata")
	}
	for _, name := range []string{"", ".", "..", "../escape", "a/b"} {
		if createStreamRootPrivateDirectory(root, name) == nil {
			t.Fatal("non-leaf directory escaped fixed creation", name)
		}
	}
}

func TestLoadBalanceStreamRPCGroupNativeNewMutationLockNeverRepairsOldFile(t *testing.T) {
	root, path := streamRPCGroupNativeFixture(t)
	f, err := openStreamRootMutationFile(root, "load-balance-stream.lock")
	if err != nil {
		t.Fatal("Root:panel fresh mutation record refused", err)
	}
	info, err := f.Stat()
	f.Close()
	if err != nil || !streamJournalFileInfo(info, 0) {
		t.Fatal("fresh lock is not strict Root:Root 0600", err)
	}
	f, err = openStreamRootMutationFile(root, "load-balance-stream.lock")
	if err != nil {
		t.Fatal("unchanged exact existing original lock refused", err)
	}
	after, err := f.Stat()
	f.Close()
	if err != nil || !geoStoreStableInfo(info, after) {
		t.Fatal("existing original lock metadata changed")
	}
	if err := os.Rename(filepath.Join(path, "load-balance-stream.lock"), filepath.Join(path, "retained-original.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "load-balance-stream.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat("load-balance-stream.lock")
	if err != nil || before.Sys().(*syscall.Stat_t).Gid != uint32(os.Getegid()) {
		t.Fatal("old foreign-group fixture invalid")
	}
	if file, err := openStreamRootMutationFile(root, "load-balance-stream.lock"); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("existing foreign-group original lock repaired")
	}
	after, err = root.Lstat("load-balance-stream.lock")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("foreign original lock changed on refusal")
	}
	if file, err := openStreamRootMutationFile(root, "arbitrary-name"); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("unknown mutation filename created")
	}
}

func TestLoadBalanceStreamRPCGroupNativeWholeReadonlyProgrammeAdmission(t *testing.T) {
	streamRPCGroupNativeFixture(t)
	if err := CheckProgramUpgradeQueues(); err != nil {
		var refusal *programQueueNativeRefusal
		if errors.As(err, &refusal) {
			t.Log("actual native refusal", refusal.observation.Unit, refusal.observation.ActiveState, refusal.observation.SubState)
		}
		t.Fatal("actual Root:panel full read-only admission refused", err)
	}
}

func TestLoadBalanceStreamRPCGroupNativeLegacyMigrationRetainsOldGroupAndInode(t *testing.T) {
	streamRPCGroupNativeFixture(t)
	m := streamModuleNativeFixtureChecked(t, true)
	before := m.held.before
	originalOwner := before.Sys().(*syscall.Stat_t)
	if originalOwner.Gid != uint32(os.Getegid()) {
		t.Fatal("legacy private fixture lost actual Root:panel group")
	}
	p, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize)
	if err != nil {
		t.Fatal("private original Root:panel preparation refused", err)
	}
	defer p.close()
	if _, err = p.publish(context.Background(), streamModuleModelAuthorize); err != nil {
		t.Fatal("private atomic migration refused", err)
	}
	if err = checkStreamModulePublicationIntent(m.publication, m.module, m.seed, m.proposal); err != nil {
		t.Fatal("original group/inode/metadata completion refused", err)
	}
	old, err := readStreamRetainedOriginalModule(m.module, p.job)
	if err != nil || !bytes.Equal(old, m.original) {
		t.Fatal("retained exact Root:panel original could not be read", err)
	}
	after, err := m.module.Lstat(".lbstream-publication-" + p.job + ".json")
	if err != nil || !os.SameFile(before, after) || after.Sys().(*syscall.Stat_t).Gid != originalOwner.Gid {
		t.Fatal("old inode/group was changed during migration", err)
	}
	native, err := holdLoadBalanceStreamModuleAt(m.module, m.held.anchor)
	if err != nil {
		t.Fatal("new native record refused", err)
	}
	defer native.close()
	if !streamJournalFileInfo(native.before, loadBalanceStreamModuleLimit) {
		t.Fatal("new native record did not retain strict Root:Root boundary")
	}
	native.close()
	if err := os.Chown(filepath.Join(m.modulePath, "installed.json"), 0, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	wrong, err := m.module.Lstat("installed.json")
	if err != nil {
		t.Fatal(err)
	}
	if held, err := holdLoadBalanceStreamModuleAt(m.module, m.held.anchor); err == nil || held != nil {
		if held != nil {
			held.close()
		}
		t.Fatal("legacy group compatibility widened new native record ownership")
	}
	current, err := m.module.Lstat("installed.json")
	if err != nil || !geoStoreStableInfo(wrong, current) {
		t.Fatal("invalid native group was silently repaired")
	}
}
