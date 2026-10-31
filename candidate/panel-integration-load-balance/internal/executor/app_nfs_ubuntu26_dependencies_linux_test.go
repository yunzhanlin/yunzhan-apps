//go:build linux

package executor

import (
	"reflect"
	"testing"
)

// Minimal exact fields retained from the real Ubuntu26 ARM64 authenticated
// APT index observation. These are metadata fixtures, not a native install.
func TestNFSUbuntu26ReviewedDBusAlternativePreservesPrivateDependencyPlan(t *testing.T) {
	metadata := []struct{ name, version, control string }{
		{"nfs-ganesha", "6.5-8", `Package: nfs-ganesha
Version: 6.5-8
Architecture: arm64
SHA256: bf3e10ff8961ca6fba94d57290d791edef8f5b86a0520ba599e928049e417056
Size: 682768
Depends: default-dbus-system-bus | dbus-system-bus, nfs-common, rpcbind, libacl1 (>= 2.2.23), libblkid1 (>= 2.16), libc6 (>= 2.38), libcap2 (>= 1:2.10), libcom-err2 (>= 1.43.9), libdbus-1-3 (>= 1.10), libgssapi-krb5-2 (>= 1.17), libkrb5-3 (>= 1.6.dfsg.2), libnfsidmap1 (>= 1:2.8.4), libntirpc6.3 (>= 6.3), liburcu8t64 (>= 0.13.0), libuuid1 (>= 2.16), libwbclient0 (>= 2:4.0.3+dfsg1)
`},
		{"nfs-ganesha-vfs", "6.5-8", `Package: nfs-ganesha-vfs
Version: 6.5-8
Architecture: arm64
SHA256: cacaec9f1df5c6c5877fdf6b73ff5f4cc40b3d8ac56e5e942b632afc53229c7c
Size: 54346
Depends: nfs-ganesha (= 6.5-8), libacl1 (>= 2.2.23), libc6 (>= 2.34)
`},
		{"nfs-common", "1:2.8.5-1ubuntu1", `Package: nfs-common
Version: 1:2.8.5-1ubuntu1
Architecture: arm64
SHA256: d1362adc6df9086c2176db1c6859e768e96bfa24fb74fa422b55bff881ff21b2
Size: 242374
Depends: libc6 (>= 2.38), libcap2 (>= 1:2.10), libcom-err2 (>= 1.43.9), libevent-core-2.1-7t64 (>= 2.1.8-stable), libgssapi-krb5-2 (>= 1.17), libk5crypto3 (>= 1.6.dfsg.2), libkeyutils1 (>= 1.5.9), libkrb5-3 (>= 1.10+dfsg~alpha1), libmount1 (>= 2.24.2), libnfsidmap1 (= 1:2.8.5-1ubuntu1), libtirpc3t64 (>= 1.0.2), libwrap0 (>= 7.6-4~), rpcbind, adduser, ucf, keyutils
`},
	}
	packages := []nfsAPTPackage{}
	for _, m := range metadata {
		p, err := parseNFSAPTMetadata(m.name, m.version, "arm64", m.control)
		if err != nil {
			t.Fatalf("actual Ubuntu26 %s metadata refused: %v", m.name, err)
		}
		packages = append(packages, p)
	}
	got, err := nfsGlobalDependencies(packages, false)
	want := []string{"build-essential", "libacl1", "libblkid1", "libc6", "libcap2", "libcom-err2", "libdbus-1-3", "libgssapi-krb5-2", "libkrb5-3", "libmount1", "libnfsidmap1", "libntirpc6.3", "libtirpc3t64", "liburcu8t64", "libuuid1", "libwbclient0"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected fresh private plan: %v %v", got, err)
	}
	got, err = nfsGlobalDependencies(packages, true)
	if err != nil || !reflect.DeepEqual(got, []string{"libc6", "libmount1", "libtirpc3t64"}) {
		t.Fatalf("server reuse gained global dependencies: %v %v", got, err)
	}
}

func TestNFSDBusAlternativeRecognitionDoesNotAdmitOtherServiceChoices(t *testing.T) {
	for _, entry := range []string{
		"default-dbus-system-bus | dbus", "dbus-system-bus | default-dbus-system-bus",
		"default-dbus-system-bus | arbitrary-package", "arbitrary-package | dbus-system-bus",
		"default-dbus-system-bus | dbus-system-bus | another-package",
		"default-dbus-system-bus (>= 1) | dbus-system-bus", "default-dbus-system-bus | dbus-system-bus (>= 1)",
		"default-dbus-system-bus", "dbus-system-bus", "rpcbind | dbus-system-bus",
		"libc6 | default-dbus-system-bus", "default-dbus-system-bus | dbus-system-bus garbage",
	} {
		if _, err := nfsAllowedDependencies("libc6, " + entry); err == nil {
			t.Errorf("unreviewed server alternative admitted: %q", entry)
		}
	}
	accepted, err := nfsAllowedDependencies("libc6, \tdefault-dbus-system-bus  |\t dbus-system-bus ")
	if err != nil || !reflect.DeepEqual(accepted, []string{"libc6"}) {
		t.Fatalf("reviewed whitespace or exact plan lost: %v %v", accepted, err)
	}
	if _, err := nfsClientDependencies("libc6, libmount1, libtirpc3t64, default-dbus-system-bus | dbus-system-bus"); err == nil {
		t.Fatal("server-only alternative entered private client grammar")
	}
}
