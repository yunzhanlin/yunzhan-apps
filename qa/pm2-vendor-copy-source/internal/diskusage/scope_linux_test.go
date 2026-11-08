//go:build linux

package diskusage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Root-native fixtures are retained in a fresh, root-private directory, never
// placed in a website, /tmp, production app state, or a pre-existing leaf.
func nativeHostFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-native host fixture not executed; not commercial/native evidence")
	}
	for _, p := range []string{"/", "/var", "/var/lib"} {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			t.Fatal("native fixture parent missing or unsafe; do not repair existing directories")
		}
	}
	// CI may lack this fixed fixture anchor. Create only the missing final
	// directory after trusted ancestors, never repair any existing directory.
	if err := os.Mkdir("/var/lib/panel-executor", 0750); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal("native fixture anchor unavailable", err)
	}
	var anchor unix.Stat_t
	if unix.Lstat("/var/lib/panel-executor", &anchor) != nil || anchor.Mode&unix.S_IFMT != unix.S_IFDIR || anchor.Uid != 0 || anchor.Mode&0022 != 0 {
		t.Fatal("pre-existing fixture anchor unsafe; not repaired")
	}
	base, err := os.MkdirTemp("/var/lib/panel-executor", "disk-host-scope-test.")
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Lstat(base, &st) != nil || st.Mode&0777 != 0700 || st.Uid != 0 {
		t.Fatal("fresh fixture identity invalid")
	}
	t.Log("retained owned native fixture:", base)
	return base
}

func nativeMountFor(t *testing.T, p string) (Inventory, Mount, string) {
	t.Helper()
	i, err := ReadInventory()
	if err != nil || !i.MountListComplete || i.SnapshotConsistent {
		t.Fatalf("native mount inventory unavailable: %v", err)
	}
	var selected Mount
	for _, m := range i.Mounts {
		if m.Point == p || strings.HasPrefix(p, strings.TrimSuffix(m.Point, "/")+"/") {
			if len(m.Point) > len(selected.Point) {
				selected = m
			}
		}
	}
	if selected.ID == "" || selected.Class != "local" || !selected.Actionable {
		t.Fatal("owned fixture is not on a supported native local mount")
	}
	// Covered/stacked mounts share a point but not a kernel mount identity.
	// In this test-only helper the path is an already-owned fixture; identify
	// the actual visible mount rather than relying on mountinfo row order.
	var st unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, selected.Point, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st) != nil || st.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("native visible fixture mount identity unavailable")
	}
	for _, m := range i.Mounts {
		if m.Point == selected.Point && m.ID == strconv.FormatUint(st.Mnt_id, 10) {
			selected = m
			break
		}
	}
	if selected.ID != strconv.FormatUint(st.Mnt_id, 10) {
		t.Fatal("visible fixture mount missing from complete inventory")
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(p, selected.Point), "/")
	return i, selected, relative
}

func nativeScopeFor(t *testing.T, p string) (*Scope, *Directory, Mount) {
	t.Helper()
	i, m, relative := nativeMountFor(t, p)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatalf("native bound mount unavailable: %v", err)
	}
	d, err := s.OpenDirectory(context.Background(), relative)
	if err != nil {
		s.Close()
		t.Fatalf("native relative directory unavailable: %v", err)
	}
	t.Cleanup(func() { d.Close(); s.Close() })
	return s, d, m
}

func nativeAllEntries(t *testing.T, d *Directory) map[string]Entry {
	t.Helper()
	out := map[string]Entry{}
	for {
		entries, err := d.ReadBatch(context.Background())
		if len(entries) > ReadBatchSize {
			t.Fatal("native batch exceeds bound")
		}
		for _, e := range entries {
			if _, duplicate := out[e.Name]; duplicate {
				t.Fatal("native directory entry repeated")
			}
			out[e.Name] = e
		}
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("native directory read failed: %v", err)
		}
	}
}

func nativeWrite(t *testing.T, p string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(data)
	if err == nil && len(data) > 0 {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("fresh owned fixture write failed")
	}
}

func TestHostScopeNativeMetadataOnlySparseHardlinksAndRawNames(t *testing.T) {
	base := nativeHostFixture(t)
	p := filepath.Join(base, "sparse.bin")
	nativeWrite(t, p, []byte("owned-fixture"))
	if os.Truncate(p, 64<<20) != nil || os.Link(p, filepath.Join(base, "alias.bin")) != nil || os.Chmod(p, 0) != nil {
		t.Fatal("sparse/hardlink fixture creation failed")
	}
	oldTime := []unix.Timespec{{Sec: 1}, {Sec: 1}}
	if unix.UtimesNano(p, oldTime) != nil {
		t.Fatal("fixture timestamps failed")
	}
	var before unix.Stat_t
	if unix.Lstat(p, &before) != nil || uint64(before.Blocks)*512 >= uint64(before.Size) {
		t.Fatal("native sparse prerequisite not established")
	}
	if os.Mkdir(filepath.Join(base, "nested"), 0700) != nil || os.Symlink("nested", filepath.Join(base, "inner-link")) != nil || os.Symlink("/proc/self/fd", filepath.Join(base, "magic-link")) != nil || unix.Mkfifo(filepath.Join(base, "metadata-only-fifo"), 0600) != nil || unix.Mknod(filepath.Join(base, "metadata-only-device"), unix.S_IFCHR|0600, int(unix.Mkdev(1, 3))) != nil {
		t.Fatal("native non-regular fixture creation failed")
	}
	for _, name := range []string{"raw-\xff.bin", "control-\n.bin", `literal\040.bin`, "unicode-\u00a0.bin"} {
		nativeWrite(t, filepath.Join(base, name), nil)
	}
	for n := range 137 {
		nativeWrite(t, filepath.Join(base, fmt.Sprintf("wide-%03d.bin", n)), nil)
	}
	start := time.Now()
	s, d, m := nativeScopeFor(t, base)
	rows := nativeAllEntries(t, d)
	if len(rows) != 148 || time.Since(start) > 10*time.Second {
		t.Fatalf("native batch/FIFO count or nonblocking prerequisite failed: %d", len(rows))
	}
	for name, e := range rows {
		if e.Error != nil || !s.checkIdentity(e.Metadata) {
			t.Fatalf("native metadata error for owned fixture %q: %v", name, e.Error)
		}
	}
	a, b := rows["sparse.bin"].Metadata, rows["alias.bin"].Metadata
	if a.Identity != b.Identity || a.Links != 2 || a.Bytes != 64<<20 || a.Blocks != uint64(before.Blocks) || a.Blocks*512 >= a.Bytes || MetadataIdentityKey(a) != MetadataIdentityKey(b) {
		t.Fatal("native hardlink/sparse identity or allocation mismatch")
	}
	for name, kind := range map[string]uint16{"inner-link": unix.S_IFLNK, "magic-link": unix.S_IFLNK, "metadata-only-fifo": unix.S_IFIFO, "metadata-only-device": unix.S_IFCHR, "nested": unix.S_IFDIR} {
		if rows[name].Metadata.Mode&unix.S_IFMT != kind {
			t.Fatalf("non-regular metadata incorrectly classified: %s", name)
		}
	}
	if rows["raw-\xff.bin"].Actionable || rows["control-\n.bin"].Actionable || !rows[`literal\040.bin`].Actionable || !rows["unicode-\u00a0.bin"].Actionable {
		t.Fatal("native GUI action grammar changed raw metadata identities")
	}
	for _, relative := range []string{"inner-link", "inner-link/child", "magic-link"} {
		if opened, err := s.OpenDirectory(context.Background(), strings.TrimPrefix(base, strings.TrimSuffix(m.Point, "/")+"/")+"/"+relative); !errors.Is(err, ErrUnsafePath) {
			if opened != nil {
				opened.Close()
			}
			t.Fatalf("symlink or magic-link resolved as a directory: %v", err)
		}
	}
	var after unix.Stat_t
	if unix.Lstat(p, &after) != nil || before != after {
		t.Fatal("metadata scanner changed source inode or read file content/atime")
	}
}

func TestHostScopeNativeReplacedDirectoryCancellationAndClosedDescriptors(t *testing.T) {
	base := nativeHostFixture(t)
	if os.Mkdir(filepath.Join(base, "changing"), 0700) != nil {
		t.Fatal("fresh directory fixture failed")
	}
	s, d, _ := nativeScopeFor(t, base)
	rows := nativeAllEntries(t, d)
	entry := rows["changing"]
	if os.Rename(filepath.Join(base, "changing"), filepath.Join(base, "retained-original")) != nil || os.Mkdir(filepath.Join(base, "changing"), 0700) != nil {
		t.Fatal("owned inode replacement fixture failed")
	}
	if child, err := d.OpenChild(context.Background(), entry); !errors.Is(err, ErrMountChanged) {
		if child != nil {
			child.Close()
		}
		t.Fatalf("replaced directory followed instead of original inode binding: %v", err)
	}
	entry.Name = "../escape"
	if _, err := d.OpenChild(context.Background(), entry); !errors.Is(err, ErrUnsafePath) {
		t.Fatal("forged GUI entry accepted")
	}
	for _, relative := range []string{"../escape", "/etc", "a/../b", "a//b", "a/", "control\n"} {
		if _, err := s.OpenDirectory(context.Background(), relative); !errors.Is(err, ErrUnsafePath) {
			t.Fatal("unsafe relative path accepted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.ReadBatch(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled directory read started")
	}
	if _, err := s.OpenDirectory(cancelled, "."); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled directory open started")
	}
	if d.Close() != nil || d.Close() != nil {
		t.Fatal("directory close is not idempotent")
	}
	if _, err := d.ReadBatch(context.Background()); !errors.Is(err, ErrScopeClosed) {
		t.Fatal("closed directory reused")
	}
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("scope close is not idempotent")
	}
	if _, err := s.Capacity(context.Background()); !errors.Is(err, ErrScopeClosed) {
		t.Fatal("closed mount capacity probed")
	}
}

func TestHostScopeNativeKernelCapacityAndBindingRejection(t *testing.T) {
	base := nativeHostFixture(t)
	i, m, _ := nativeMountFor(t, base)
	s, d, _ := nativeScopeFor(t, base)
	defer d.Close()
	c, err := s.Capacity(context.Background())
	var st unix.Statfs_t
	if err != nil || c.State != "available" || unix.Fstatfs(int(s.root.Fd()), &st) != nil || c.TotalBytes == nil || *c.TotalBytes != *capacityFromStatfs(st, m).TotalBytes || !c.MayOverlap || c.SnapshotConsistent {
		t.Fatalf("native held-FD capacity was not independently verified: %v", err)
	}
	for n := range 100 {
		if _, err := i.OpenMount(context.Background(), m.ID, strings.Repeat(strconv.Itoa(n%10), 64)); !errors.Is(err, ErrMountChanged) {
			t.Fatal("unbound mount accepted")
		}
	}
	if _, err := i.OpenMount(context.Background(), "0", m.BindingSHA); !errors.Is(err, ErrMountChanged) {
		t.Fatal("unlisted mount accepted")
	}
	for _, candidate := range i.Mounts {
		if candidate.Class != "local" && candidate.Actionable {
			if _, err := i.OpenMount(context.Background(), candidate.ID, candidate.BindingSHA); !errors.Is(err, ErrNotLocal) {
				t.Fatal("nonlocal/kernel filesystem was probed")
			}
		}
	}
}

func TestHostScopeNativeFailureAndCancellationReleaseDescriptors(t *testing.T) {
	base := nativeHostFixture(t)
	i, m, relative := nativeMountFor(t, base)
	count := func() int {
		rows, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal("native FD inventory unavailable")
		}
		return len(rows)
	}
	before := count()
	for range 80 {
		s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
		if err != nil {
			t.Fatal(err)
		}
		d, err := s.OpenDirectory(context.Background(), relative)
		if err != nil {
			s.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := d.ReadBatch(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled scan continued")
		}
		if _, err := s.OpenDirectory(context.Background(), relative+"/missing-owned-leaf"); !errors.Is(err, ErrPathUnavailable) {
			t.Fatal("missing leaf manufactured metadata")
		}
		d.Close()
		s.Close()
	}
	if after := count(); after != before {
		t.Fatalf("native descriptors leaked: before=%d after=%d", before, after)
	}
}

func TestHostScopeNativeBindBoundaryAndStaleMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root mount namespace test not executed; not native evidence")
	}
	// Never mount in the live server namespace. The outer invocation executes
	// only this exact test in a fresh namespace with private propagation.
	if os.Getenv("PANEL_DISK_SCOPE_TEST_NAMESPACE") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "--mount", "--propagation", "private", exe, "-test.run=^TestHostScopeNativeBindBoundaryAndStaleMount$", "-test.v")
		cmd.Env = append(os.Environ(), "PANEL_DISK_SCOPE_TEST_NAMESPACE=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatalf("native private mount namespace unavailable: %v", err)
		}
		return
	}
	self, e1 := os.Readlink("/proc/self/ns/mnt")
	init, e2 := os.Readlink("/proc/1/ns/mnt")
	if e1 != nil || e2 != nil || self == init {
		t.Fatal("refusing mount fixture in live/init namespace")
	}
	base := nativeHostFixture(t)
	source, target := filepath.Join(base, "source"), filepath.Join(base, "bind")
	if os.Mkdir(source, 0700) != nil || os.Mkdir(target, 0700) != nil {
		t.Fatal("owned bind directories failed")
	}
	nativeWrite(t, filepath.Join(source, "native-marker"), nil)
	if unix.Mount(source, target, "", unix.MS_BIND, "") != nil {
		t.Fatal("native bind mount failed")
	}
	mounted := 1
	defer func() {
		for mounted > 0 {
			if unix.Unmount(target, 0) != nil {
				t.Error("owned private bind fixture could not be unmounted")
				return
			}
			mounted--
		}
	}()
	s, d, parent := nativeScopeFor(t, base)
	rows := nativeAllEntries(t, d)
	if !errors.Is(rows["bind"].Error, ErrMountBoundary) {
		t.Fatal("same-device bind entry was statted/traversed")
	}
	_, _, relative := nativeMountFor(t, base)
	if _, err := s.OpenDirectory(context.Background(), relative+"/bind"); !errors.Is(err, ErrMountBoundary) {
		t.Fatal("same-device bind crossed in directory resolution")
	}
	d.Close()
	s.Close()
	i, original, _ := nativeMountFor(t, target)
	if original.ID == parent.ID || original.Major != parent.Major || original.Minor != parent.Minor {
		t.Fatal("real same-device different-mount prerequisite failed")
	}
	bs, err := i.OpenMount(context.Background(), original.ID, original.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := bs.OpenDirectory(context.Background(), ".")
	if err != nil {
		bs.Close()
		t.Fatal(err)
	}
	boundRows := nativeAllEntries(t, bd)
	if len(boundRows) != 1 || boundRows["native-marker"].Error != nil {
		t.Fatal("explicit selected bind mount did not scan its own scope")
	}
	bd.Close()
	bs.Close()
	if unix.Mount(source, target, "", unix.MS_BIND, "") != nil {
		t.Fatal("owned stacked bind fixture failed")
	}
	mounted++
	if opened, err := i.OpenMount(context.Background(), original.ID, original.BindingSHA); !errors.Is(err, ErrMountChanged) {
		if opened != nil {
			opened.Close()
		}
		t.Fatalf("stale covered mount selection accepted: %v", err)
	}
	current, newest, _ := nativeMountFor(t, target)
	if newest.ID == original.ID || !newest.Stacked {
		t.Fatal("stacked mount identities silently merged")
	}
	newScope, err := current.OpenMount(context.Background(), newest.ID, newest.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	newScope.Close()
}
