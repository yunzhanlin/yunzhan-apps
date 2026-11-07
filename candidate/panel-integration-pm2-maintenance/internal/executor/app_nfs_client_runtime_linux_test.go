//go:build linux

package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestNFSPrivateClientDependenciesExcludeServiceAndUnrelatedUtilities(t *testing.T) {
	for _, tirpc := range []string{"libtirpc3", "libtirpc3t64"} {
		raw := "libc6 (>= 2.38), libmount1 (>= 2.24.2), " + tirpc + " (>= 1.0.2), rpcbind, adduser, ucf, keyutils, python3:any, libnfsidmap1 (= 1:2.8.3-1), libcap2, libcom-err2, libdevmapper1.02.1, libevent-core-2.1-7t64, libgssapi-krb5-2, libk5crypto3, libkeyutils1, libkrb5-3, libwrap0, init-system-helpers"
		got, err := nfsClientDependencies(raw)
		if err != nil || !reflect.DeepEqual(got, []string{"libc6", "libmount1", tirpc}) {
			t.Fatal(got, err)
		}
	}
	for _, raw := range []string{"", "libc6, libtirpc3", "libc6, libmount1", "libc6, libmount1, libtirpc3, libtirpc3t64", "libc6, libmount1, libtirpc3 | rpcbind", "libc6, libmount1, libtirpc3, unreviewed-server", "libc6, libmount1, libtirpc3, rpcbind;id", "libc6, libmount1, libtirpc3,"} {
		if _, err := nfsClientDependencies(raw); err == nil {
			t.Fatal("unreviewed or incomplete dependency boundary accepted", raw)
		}
	}
}

func TestNFSPrivateClientInstallerLockIsAllowedExclusiveAndPrivate(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security-apps")})
	lock, err := s.lockNFSFile(nfsRuntimeInstallLock)
	if err != nil {
		t.Fatal("compiled installer lock is rejected", err)
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("installer lock is not private and ordinary", info, err)
	}
	if second, err := s.lockNFSFile(nfsRuntimeInstallLock); err == nil {
		second.Close()
		t.Fatal("concurrent runtime preparation was admitted")
	}
	for _, name := range []string{"foreign.lock", "../runtime-install.lock", "", "runtime-install.lock/other"} {
		if other, err := s.lockNFSFile(name); err == nil {
			other.Close()
			t.Fatal("unreviewed lock path accepted", name)
		}
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := s.lockNFSFile(nfsRuntimeInstallLock)
	if err != nil {
		t.Fatal("released original lock remained unavailable", err)
	}
	next.Close()
}

func TestNFSPrivateClientNativeCopyModesIndependentOfServiceUmask(t *testing.T) {
	const child = "PANEL_NFS_COPY_MODE_TEST_CHILD"
	if os.Getenv(child) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// A process umask is global; exercise real restricted masks in a
		// separate test process without changing parallel fixtures' masks.
		cmd := exec.Command(binary, "-test.run=^TestNFSPrivateClientNativeCopyModesIndependentOfServiceUmask$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("private native file modes failed: %v\n%s", err, out)
		}
		return
	}
	for _, mask := range []int{0027, 0077} {
		func() {
			previous := syscall.Umask(mask)
			defer syscall.Umask(previous)
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(root, "authenticated-original")
			payload := []byte("native-copy mode contract, not executed")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				name string
				mode os.FileMode
			}{{"bin/mount.nfs", 0755}, {"licenses/nfs-common.txt", 0644}} {
				target := filepath.Join(root, "candidate", item.name)
				if _, err := copyNFSVerifiedNative(source, target, item.mode, core.Hash(string(payload))); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(target)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != item.mode {
					t.Fatalf("umask %04o did not preserve %s exact mode %04o: %v %v", mask, item.name, item.mode, info, err)
				}
			}
		}()
	}
}

func TestNFSPrivateClientAuthenticatedPackageIdentity(t *testing.T) {
	meta := "Package: nfs-common\nVersion: 1:2.8.3-1\nArchitecture: arm64\nSize: 260144\nSHA256: " + strings.Repeat("a", 64) + "\nDepends: libc6, libmount1, libtirpc3t64, rpcbind, adduser, ucf, keyutils\n"
	got, err := parseNFSAPTMetadata("nfs-common", "1:2.8.3-1", "arm64", meta)
	if err != nil || got.Name != "nfs-common" || got.SHA256 != strings.Repeat("a", 64) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{strings.Replace(meta, "Architecture: arm64", "Architecture: amd64", 1), strings.Replace(meta, "Version: 1:2.8.3-1", "Version: 1:2.8.4-1", 1), strings.Replace(meta, strings.Repeat("a", 64), "unverified", 1), strings.Replace(meta, "Size: 260144", "Size: 999999999", 1), strings.Replace(meta, "libtirpc3t64", "unknown-client-library", 1)} {
		if _, err := parseNFSAPTMetadata("nfs-common", "1:2.8.3-1", "arm64", bad); err == nil {
			t.Fatal("wrong package cohort accepted", bad)
		}
	}
}

func TestNFSPrivateClientUpgradeDependenciesKeepOriginalServer(t *testing.T) {
	packages := []nfsAPTPackage{
		{Name: "nfs-ganesha", Depends: "libc6, libntirpc4, liburcu8, rpcbind, nfs-common, dbus"},
		{Name: "nfs-ganesha-vfs", Depends: "libacl1, nfs-ganesha (= 4.3-8ubuntu1)"},
		{Name: "nfs-common", Depends: "libc6, libmount1, libtirpc3t64, rpcbind, adduser, ucf, keyutils"},
	}
	upgrade, err := nfsGlobalDependencies(packages, true)
	if err != nil || !reflect.DeepEqual(upgrade, []string{"libc6", "libmount1", "libtirpc3t64"}) {
		t.Fatal("upgrade selected server libraries, tools or services", upgrade, err)
	}
	fresh, err := nfsGlobalDependencies(packages, false)
	if err != nil || !reflect.DeepEqual(fresh, []string{"build-essential", "libacl1", "libc6", "libmount1", "libntirpc4", "libtirpc3t64", "liburcu8"}) {
		t.Fatal("fresh runtime dependency boundary changed", fresh, err)
	}
	if _, err := nfsGlobalDependencies(packages[:2], true); err == nil {
		t.Fatal("missing client package accepted")
	}
	packages[2].Name = "rpcbind"
	if _, err := nfsGlobalDependencies(packages, true); err == nil {
		t.Fatal("service package substituted for client")
	}
}

func TestNFSPrivateClientServerCopyRequiresOriginalDigest(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "original-server")
	payload := []byte("original verified server bytes, never executed")
	if err := os.WriteFile(source, payload, 0755); err != nil {
		t.Fatal(err)
	}
	want := core.Hash(string(payload))
	target := filepath.Join(root, "new-runtime/bin/server")
	got, err := copyNFSVerifiedNative(source, target, 0755, want)
	if err != nil || got != want {
		t.Fatal("original server copy failed", got, err)
	}
	if _, err := copyNFSVerifiedNative(source, target, 0755, want); err == nil {
		t.Fatal("existing candidate silently overwritten")
	}
	if err := os.WriteFile(source, []byte("changed after original runtime validation"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := copyNFSVerifiedNative(source, filepath.Join(root, "changed-runtime/bin/server"), 0755, want); err == nil {
		t.Fatal("changed legacy server accepted during private-client update")
	}
	if b, err := os.ReadFile(target); err != nil || !reflect.DeepEqual(b, payload) {
		t.Fatal("previous verified copy changed", err)
	}
}

func TestNFSPrivateClientExtractionRejectsAmbiguousAndLinkedPaths(t *testing.T) {
	privateTemp := func() string {
		t.Helper()
		root := t.TempDir()
		// Match the installer's 0700 extraction root independently of the
		// test runner's login umask; broad directory permissions must fail.
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		return root
	}
	for _, relative := range []string{"sbin/mount.nfs", "usr/sbin/mount.nfs"} {
		root := privateTemp()
		name := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("ordinary source, not executed"), 0755); err != nil {
			t.Fatal(err)
		}
		if got, err := nfsExtractedClient(root); err != nil || got != name {
			t.Fatal(got, err)
		}
	}
	root := privateTemp()
	if _, err := nfsExtractedClient(root); err == nil {
		t.Fatal("missing helper accepted")
	}
	for _, relative := range []string{"sbin/mount.nfs", "usr/sbin/mount.nfs"} {
		name := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("two source files"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nfsExtractedClient(root); err == nil {
		t.Fatal("ambiguous helpers accepted")
	}
	linked := privateTemp()
	if err := os.Mkdir(filepath.Join(linked, "sbin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "sbin/mount.nfs"), filepath.Join(linked, "sbin/mount.nfs")); err != nil {
		t.Fatal(err)
	}
	if _, err := nfsExtractedClient(linked); err == nil {
		t.Fatal("linked helper accepted")
	}
	parentLink := privateTemp()
	if err := os.Symlink(filepath.Join(root, "sbin"), filepath.Join(parentLink, "sbin")); err != nil {
		t.Fatal(err)
	}
	if _, err := nfsExtractedClient(parentLink); err == nil {
		t.Fatal("linked parent accepted")
	}
}

func TestNFSPrivateClientCommandIsBoundToRuntimeAndMountIdentity(t *testing.T) {
	prefix := "apt-0123456789abcdef"
	v := nfsRuntimeSelection{Format: 2, Prefix: prefix, ClientBinary: filepath.Join(appNativeRoot, "nfs-manager", prefix, "bin/mount.nfs")}
	for _, fixture := range []struct {
		source, protocol, permission string
		port                         int
		ro                           bool
	}{
		{"127.0.0.1:/share-one", "tcp", "rw", 0, false},
		{"[::1]:/share-one", "tcp6", "ro", 24249, true},
		{"storage.example.test:/share-one", "tcp", "ro", 2049, true},
	} {
		m := nfsMount{ID: "client-one", Source: fixture.source, ReadOnly: fixture.ro, Port: fixture.port}
		command, args, err := nfsClientMountCommand(v, m)
		if err != nil || command != v.ClientBinary || len(args) != 5 || args[0] != fixture.source || args[1] != "/srv/panel/nfs/client-one" || args[2] != "-n" || args[3] != "-o" {
			t.Fatal(command, args, err)
		}
		for _, option := range []string{fixture.permission, "nosuid", "nodev", "noexec", "vers=4.2", "proto=" + fixture.protocol, "sec=sys"} {
			if !strings.Contains(","+args[4]+",", ","+option+",") {
				t.Fatal("lost mount security option", option, args)
			}
		}
	}
	m := nfsMount{ID: "client-one", Source: "127.0.0.1:/share-one", ReadOnly: true}
	for _, bad := range []nfsRuntimeSelection{{Format: 0}, {Format: 3}, {Format: 2, Prefix: prefix, ClientBinary: "/tmp/mount.nfs"}, {Format: 2, Prefix: "../../foreign", ClientBinary: v.ClientBinary}} {
		if _, _, err := nfsClientMountCommand(bad, m); err == nil {
			t.Fatal("unverified helper accepted", bad)
		}
	}
	for _, change := range []func(*nfsMount){func(m *nfsMount) { m.ID = "../foreign" }, func(m *nfsMount) { m.Source = "127.0.0.1:/share;id" }, func(m *nfsMount) { m.Port = -1 }, func(m *nfsMount) { m.Port = 65536 }} {
		bad := m
		change(&bad)
		if _, _, err := nfsClientMountCommand(v, bad); err == nil {
			t.Fatal("unbound mount accepted", bad)
		}
	}
	command, args, err := nfsClientMountCommand(nfsRuntimeSelection{Format: 1}, m)
	if err != nil || command != "/usr/bin/mount" || !reflect.DeepEqual(args, []string{"-t", "nfs", "-o", "ro,nosuid,nodev,noexec,vers=4.2,proto=tcp,port=2049,timeo=50,retrans=2", m.Source, "/srv/panel/nfs/client-one"}) {
		t.Fatal("legacy command changed", command, args, err)
	}
}
