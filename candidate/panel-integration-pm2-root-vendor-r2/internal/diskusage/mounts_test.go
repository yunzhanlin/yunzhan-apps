package diskusage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const rootMountFixture = "37 1 8:1 / / rw,relatime - ext4 /dev/test rw\n"

func TestHostMountLocalLookupRefusesRemoteUnknownAndBrokenAncestors(t *testing.T) {
	for _, f := range []struct {
		parent  string
		allowed bool
	}{{"nfs4", false}, {"fuse.sshfs", false}, {"futurefs", false}, {"ext4", true}, {"devtmpfs", true}} {
		input := rootMountFixture + "41 37 0:8 / /ancestor rw - " + f.parent + " opaque rw\n" + "42 41 8:1 /data /ancestor/local rw - ext4 opaque rw\n"
		i, err := ParseMountInfo(strings.NewReader(input))
		if err != nil || i.LocalLookup("42") != f.allowed {
			t.Fatal("local selected mount lookup incorrectly traversed ancestor", f, err)
		}
		if f.parent != "ext4" && i.LocalLookup("41") {
			t.Fatal("nonlocal scope itself permitted")
		}
	}
	for _, parent := range []string{"99", "42"} {
		i, err := ParseMountInfo(strings.NewReader(rootMountFixture + "42 " + parent + " 8:1 /data /local rw - ext4 opaque rw\n"))
		if err != nil || i.LocalLookup("42") {
			t.Fatal("missing/cyclic nonroot ancestor permitted", err)
		}
	}
	i, _ := ParseMountInfo(strings.NewReader(rootMountFixture))
	if !i.LocalLookup("37") {
		t.Fatal("namespace-visible root needs no lookup outside its root")
	}
	i.MountListComplete = false
	if i.LocalLookup("37") {
		t.Fatal("incomplete inventory allowed lookup")
	}
}

func TestHostMountInventoryNamespaceRootIsInventoriedNeverAPath(t *testing.T) {
	for _, kind := range []string{"mnt", "net", "uts", "ipc", "pid", "user", "cgroup", "time"} {
		line := "41 37 0:8 " + kind + ":[4026531992] /run/namespaces/native rw - nsfs nsfs rw\n"
		i, err := ParseMountInfo(strings.NewReader(rootMountFixture + line))
		if err != nil || len(i.Mounts) != 2 || i.Mounts[1].Class != "kernel_virtual" || i.Mounts[1].Actionable || i.Mounts[1].Root != kind+":[4026531992]" || !i.MountListComplete {
			t.Fatalf("exact native nsfs d_dname not inventoried safely: %+v %v", i, err)
		}
		if _, err := ParseMountInfo(strings.NewReader(strings.Replace(line, " - nsfs ", " - ext4 ", 1))); !errors.Is(err, ErrMountInventory) {
			t.Fatal("namespace exception permitted a relative ordinary-filesystem root")
		}
	}
	for _, root := range []string{"net:[0]", "net:[04026531992]", "net:[4026531992]/child", "unknown:[4026531992]", "net:[18446744073709551616]", "relative", "../escape"} {
		line := "41 37 0:8 " + root + " /run/namespaces/native rw - nsfs nsfs rw\n"
		if _, err := ParseMountInfo(strings.NewReader(line)); !errors.Is(err, ErrMountInventory) {
			t.Fatal("noncanonical/unknown relative namespace root accepted")
		}
	}
}

func TestHostMountInventoryPreservesKernelIdentityWithoutOptionsOrSources(t *testing.T) {
	input := rootMountFixture + "52 37 8:1 /data /srv/data ro shared:9 master:8 - ext4 hidden-source ro,secret=do-not-export\n" + "59 37 0:31 / /var/lib/containers rw - overlay overlay rw,lowerdir=/private/password\n"
	i, err := ParseMountInfo(strings.NewReader(input))
	if err != nil || len(i.Mounts) != 3 || !i.MountListComplete || i.SnapshotConsistent || len(i.BindingSHA) != 64 {
		t.Fatal(i, err)
	}
	m := i.Mounts[1]
	if m.ID != "52" || m.ParentID != "37" || m.Major != 8 || m.Minor != 1 || m.Root != "/data" || m.Point != "/srv/data" || !m.ReadOnly || m.Class != "local" || !m.Actionable || m.Stacked || len(m.BindingSHA) != 64 {
		t.Fatal(m)
	}
	public, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"secret", "do-not-export", "hidden-source", "lowerdir", "password", "shared:9", "master:8", "/dev/test"} {
		if bytes.Contains(public, []byte(private)) {
			t.Fatalf("private mount metadata escaped: %q", private)
		}
	}
	changed := strings.ReplaceAll(strings.ReplaceAll(input, "do-not-export", "different-secret"), "hidden-source", "changed-source")
	other, err := ParseMountInfo(strings.NewReader(changed))
	if err != nil || i.BindingSHA != other.BindingSHA || i.Mounts[1].BindingSHA != other.Mounts[1].BindingSHA {
		t.Fatal("public binding must not be a dictionary oracle for mount credentials", err)
	}
}

func TestHostMountInventoryEscapesUnicodeAndUnsafePathClassification(t *testing.T) {
	input := rootMountFixture + "41 37 0:8 / /disk\\040one rw - tmpfs - rw\n" + "42 37 0:9 / /disk\\134one rw - tmpfs none rw\n" + "43 37 0:10 / /disk\\011one rw - tmpfs none rw\n" + "44 37 0:11 / /磁盘\u00a0空间 rw - tmpfs none rw\n" + "45 37 0:12 / /bad-" + string([]byte{255}) + " rw - tmpfs none rw\n"
	i, err := ParseMountInfo(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if i.Mounts[1].Point != "/disk one" || i.Mounts[2].Point != "/disk\\one" || !i.Mounts[2].Actionable || i.Mounts[3].Point != "/disk\tone" || i.Mounts[3].Actionable || i.Mounts[4].Point != "/磁盘\u00a0空间" || !i.Mounts[4].Actionable || i.Mounts[5].Actionable {
		t.Fatal(i.Mounts)
	}
	a, ok := mountUnescape(`/literal\134040`)
	if !ok || a != `/literal\040` {
		t.Fatal("escape was recursively decoded", a, ok)
	}
}

func TestHostMountInventoryStackedBindMountsDoNotMergeDistinctIDs(t *testing.T) {
	left := "41 37 8:1 /data /srv/data rw - ext4 /dev/test rw\n"
	right := "42 37 8:1 /data /srv/data rw - ext4 /dev/test rw\n"
	i, err := ParseMountInfo(strings.NewReader(rootMountFixture + left + right))
	if err != nil {
		t.Fatal(err)
	}
	if len(i.Mounts) != 3 || !i.Mounts[1].Stacked || !i.Mounts[2].Stacked || i.Mounts[1].BindingSHA == i.Mounts[2].BindingSHA {
		t.Fatal("stacked mount IDs must not silently collapse", i)
	}
	reordered, err := ParseMountInfo(strings.NewReader(right + rootMountFixture + left))
	if err != nil || reordered.BindingSHA != i.BindingSHA {
		t.Fatal("order alone changed authority", err)
	}
	for _, alter := range []string{strings.ReplaceAll(left, "41 37", "43 37"), strings.ReplaceAll(left, "/data /srv/data", "/other /srv/data"), strings.ReplaceAll(left, "8:1", "8:2"), strings.ReplaceAll(left, "/srv/data", "/srv/other"), strings.ReplaceAll(left, "rw - ext4", "ro - ext4")} {
		changed, e := ParseMountInfo(strings.NewReader(rootMountFixture + alter + right))
		if e != nil || changed.BindingSHA == i.BindingSHA {
			t.Fatal("identity change borrowed old binding", e)
		}
	}
}

func TestHostMountInventoryRejectsPartialMalformedAndExcessiveInput(t *testing.T) {
	for _, input := range []string{"", strings.TrimSuffix(rootMountFixture, "\n"), rootMountFixture + "\n", rootMountFixture + rootMountFixture, strings.Replace(rootMountFixture, "37 1", "037 1", 1), strings.Replace(rootMountFixture, "8:1", "8:01", 1), strings.Replace(rootMountFixture, "37 1", "0 1", 1), strings.Replace(rootMountFixture, "8:1", "8:4294967296", 1), strings.Replace(rootMountFixture, " / / ", " / ../bad ", 1), strings.Replace(rootMountFixture, "rw,relatime", "ro,rw", 1), strings.Replace(rootMountFixture, "rw,relatime", "rw,rw", 1), strings.Replace(rootMountFixture, "rw,relatime", "nosuid", 1), strings.Replace(rootMountFixture, " - ", "  - ", 1), strings.Replace(rootMountFixture, " / / ", ` / /bad\000 `, 1), strings.Replace(rootMountFixture, " / / ", ` / /bad\041 `, 1), strings.Replace(rootMountFixture, "ext4", "bad/type", 1), strings.Replace(rootMountFixture, "/dev/test", "/dev/test\x00", 1), strings.Repeat("x", MountInfoBytesMax+1), "1 2 0:1 / / rw - tmpfs none rw extra\n"} {
		if out, err := ParseMountInfo(strings.NewReader(input)); !errors.Is(err, ErrMountInventory) || len(out.Mounts) != 0 {
			t.Fatal("invalid or partial mount list accepted", out, err)
		}
	}
	var tooMany strings.Builder
	for n := 1; n <= MountCountMax+1; n++ {
		fmt.Fprintf(&tooMany, "%d 1 0:1 / /mount-%d rw - tmpfs none rw\n", n, n)
	}
	if _, err := ParseMountInfo(strings.NewReader(tooMany.String())); !errors.Is(err, ErrMountInventory) {
		t.Fatal(err)
	}
	if _, err := ParseMountInfo(io.MultiReader(strings.NewReader(rootMountFixture), failingMountReader{})); !errors.Is(err, ErrMountInventory) {
		t.Fatal("short failed read was certified complete", err)
	}
}

type failingMountReader struct{}

func (failingMountReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

func TestHostMountPathAndFilesystemPoliciesStayExplicit(t *testing.T) {
	for _, p := range []string{"/", "/etc", "/var/lib/panel", "/disk one", "/磁盘/数据", `/literal\name`} {
		if !ValidHostPath(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"", "relative", "/a/../etc", "/a/./b", "//etc", "/a//b", "/a/", "/bad\nname", "/bad\tname", "/bad\x00name", string([]byte{'/', 255}), "/" + strings.Repeat("a", 4096)} {
		if ValidHostPath(p) {
			t.Fatalf("unsafe host path accepted: %q", p)
		}
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs", "zfs", "overlay", "tmpfs"} {
		if filesystemClass(fs) != "local" {
			t.Fatal(fs)
		}
	}
	for _, fs := range []string{"proc", "sysfs", "devtmpfs", "autofs", "cgroup2", "nsfs"} {
		if filesystemClass(fs) != "kernel_virtual" {
			t.Fatal(fs)
		}
	}
	for _, fs := range []string{"nfs", "nfs4", "cifs", "9p", "virtiofs", "fuse.sshfs", "fuse.glusterfs"} {
		if filesystemClass(fs) != "remote_or_userspace" {
			t.Fatal(fs)
		}
	}
	if filesystemClass("future-fs") != "unknown" {
		t.Fatal("unknown FS implicitly promised safe automatic scan")
	}
}
