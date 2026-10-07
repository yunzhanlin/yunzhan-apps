//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

func TestNFSDaemonDropsBootstrapPrivilegesWithoutLosingSquashIdentity(t *testing.T) {
	all := [2]unix.CapUserData{{Effective: ^uint32(0), Permitted: ^uint32(0), Inheritable: ^uint32(0)}, {Effective: ^uint32(0), Permitted: ^uint32(0), Inheritable: ^uint32(0)}}
	limited := nfsDaemonCapabilities(all)
	for _, capability := range nfsBootstrapOnlyCapabilities {
		word, bit := capability/32, uint32(1)<<(capability%32)
		if (limited[word].Effective|limited[word].Permitted|limited[word].Inheritable)&bit != 0 {
			t.Fatal("bootstrap capability survived", capability)
		}
	}
	for _, capability := range []uint{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_DAC_READ_SEARCH, unix.CAP_LEASE} {
		word, bit := capability/32, uint32(1)<<(capability%32)
		if limited[word].Effective&bit == 0 {
			t.Fatal("native VFS identity capability lost", capability)
		}
	}
}

func TestNFSNamespaceDetachesOnlyNFSChildrenBeforeParents(t *testing.T) {
	data := "71 45 0:40 / /srv/panel/nfs/client-one rw - nfs4 127.0.0.1:/share rw\n" +
		"72 71 0:41 / /srv/panel/nfs/client-one/nested rw - nfs storage:/nested rw\n" +
		"73 45 0:42 / /var/tmp/space\\040name rw - nfs4 remote:/share rw\n" +
		"74 45 0:43 / /srv/panel/sites rw - ext4 /dev/vda rw\n"
	paths, err := inheritedNFSClientPaths(data)
	if err != nil || !reflect.DeepEqual(paths, []string{"/srv/panel/nfs/client-one/nested", "/srv/panel/nfs/client-one", "/var/tmp/space name"}) {
		t.Fatal(paths, err)
	}
	for _, path := range []string{"/", "/srv/../private", "relative", `/srv/bad\012name`} {
		if _, err := inheritedNFSClientPaths("71 45 0:40 / " + path + " rw - nfs4 host:/share rw\n"); err == nil {
			t.Fatal("unsafe inherited mount accepted", path)
		}
	}
}

func TestNFSServerStrictBoundsAndAnonymousWebsiteIdentity(t *testing.T) {
	v := defaultNFSServerConfig()
	v.Revision = 1
	v.Exports = []nfsExport{{ID: "website-one", SiteID: core.ID(), Path: "assets", Clients: []string{"127.0.0.0/8", "::1"}, ReadOnly: true, ExportID: 1, UID: 1001, GID: 1001, Device: 1, Inode: 2}}
	text, e := renderNFSServer(v, appNativeRoot+"/nfs-manager/apt-0123456789abcdef/lib")
	if e != nil {
		t.Fatal(e)
	}
	for _, needed := range []string{"Protocols = 4", "Enable_UDP = false", "Access_Type = None", "all_squash", "Anonymous_uid = 1001", "Access_Type = RO", "Pseudo = /website-one"} {
		if !strings.Contains(text, needed) {
			t.Fatal("missing required export isolation", needed)
		}
	}
	for _, change := range []func(*nfsServerConfig){func(v *nfsServerConfig) { v.Port = 19100 }, func(v *nfsServerConfig) { v.BindAddress = "0.0.0.0" }, func(v *nfsServerConfig) { v.Exports[0].UID = 0 }, func(v *nfsServerConfig) { v.Exports[0].Path = "../private" }, func(v *nfsServerConfig) { v.Exports[0].Clients = []string{"localhost"} }, func(v *nfsServerConfig) { v.Exports[0].Clients = []string{"0.0.0.0/0"} }, func(v *nfsServerConfig) { v.Exports[0].Clients = []string{"127.0.0.1;id"} }, func(v *nfsServerConfig) { v.Exports[0].Inode = 0 }} {
		b, _ := json.Marshal(v)
		var next nfsServerConfig
		json.Unmarshal(b, &next)
		change(&next)
		if validateNFSServerConfig(next) == nil {
			t.Fatal("unsafe export accepted", next)
		}
	}
	if _, e := renderNFSServer(v, appNativeRoot+"/nfs-manager/../outside"); e == nil {
		t.Fatal("plugin path escape accepted")
	}
	clients, e := nfsClientNetworks([]string{"192.0.2.17/24", "192.0.2.0/24", "::1"})
	if e != nil || !reflect.DeepEqual(clients, []string{"192.0.2.0/24", "::1"}) {
		t.Fatal(clients, e)
	}
	for _, values := range [][]string{nil, {"fe80::1"}, {"::ffff:127.0.0.1"}, {"ff00::/8"}, {"::1%lo"}} {
		if _, e := nfsClientNetworks(values); e == nil {
			t.Fatal("unsafe client accepted", values)
		}
	}
}

func TestNFSClientSourceIPv6AndInjectionBounds(t *testing.T) {
	for _, source := range []string{"127.0.0.1:/website-one", "storage.example.test:/share", "[::1]:/website-one", "[2001:db8::1]:/nested/path"} {
		if !validNFSSource(source) {
			t.Fatal("valid explicit NFS source rejected", source)
		}
		transport := "tcp"
		if strings.HasPrefix(source, "[") {
			transport = "tcp6"
		}
		if nfsClientTransport(source) != transport {
			t.Fatal("NFS transport family does not match source", source)
		}
	}
	for _, source := range []string{"0.0.0.0:/share", "224.0.0.1:/share", "::1:/website-one", "[::]:/share", "[::ffff:127.0.0.1]:/share", "[::1]:/share:other", "[::1]:/../private", "[::1]:/share;id", "[::1]:/space name", "[::1]:/share\n", "[::1%lo]:/share", "host:/../../etc"} {
		if validNFSSource(source) {
			t.Fatal("unsafe/ambiguous NFS source accepted", source)
		}
	}
}

func TestNFSKernelMountActualIdentityNotUnitState(t *testing.T) {
	m := nfsMount{ID: "owned-one", Source: "127.0.0.1:/website-one", ReadOnly: true}
	good := "71 45 0:40 / /srv/panel/nfs/owned-one ro,nosuid,nodev,noexec,relatime - nfs4 127.0.0.1:/website-one ro,vers=4.2,proto=tcp\n"
	if found, err := nfsKernelMount(good, "/srv/panel/nfs/owned-one", m); !found || err != nil {
		t.Fatal("actual safe mount rejected", found, err)
	}
	if found, err := nfsKernelMount("", "/srv/panel/nfs/owned-one", m); found || err != nil {
		t.Fatal("nonexistent mount manufactured", found, err)
	}
	for _, data := range []string{good + good, strings.Replace(good, "- nfs4", "- ext4", 1), strings.Replace(good, "127.0.0.1:/website-one", "127.0.0.2:/foreign", 1), strings.Replace(good, ",noexec", "", 1), strings.ReplaceAll(good, "ro", "rw")} {
		if found, err := nfsKernelMount(data, "/srv/panel/nfs/owned-one", m); !found || err == nil {
			t.Fatal("foreign/unsafe mount accepted", found, err, data)
		}
	}
}

func TestNFSAuthenticatedMetadataSelectsCandidateNotOtherVersions(t *testing.T) {
	data := "Package: nfs-ganesha\nVersion: 9.14-1\nArchitecture: amd64\nSHA256: " + strings.Repeat("b", 64) + "\nSize: 8192\nDepends: libc6\n\nPackage: nfs-ganesha\nVersion: 6.5-5\nArchitecture: amd64\nSHA256: " + strings.Repeat("a", 64) + "\nSize: 728392\nDepends: libc6 (>= 2.38), libntirpc6.3, liburcu8t64, rpcbind, nfs-common, dbus\n"
	p, e := parseNFSAPTMetadata("nfs-ganesha", "6.5-5", "amd64", data)
	if e != nil || p.SHA256 != strings.Repeat("a", 64) || p.Size != 728392 {
		t.Fatal(p, e)
	}
	for _, bad := range []string{strings.Replace(data, "728392", "999999999", 1), strings.ReplaceAll(data, "Architecture: amd64", "Architecture: arm64"), strings.Replace(data, strings.Repeat("a", 64), "unverified", 1), strings.Replace(data, "libntirpc6.3", "unreviewed-server", 1)} {
		if _, e := parseNFSAPTMetadata("nfs-ganesha", "6.5-5", "amd64", bad); e == nil {
			t.Fatal("incomplete/unreviewed package metadata accepted")
		}
	}
	dependencies, e := nfsAllowedDependencies(p.Depends)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range dependencies {
		if name == "rpcbind" || name == "nfs-ganesha" || name == "dbus" {
			t.Fatal("server/service maintainer scripts permitted", name)
		}
	}
}

func nfsTransactionFixture(t *testing.T) (*Service, nfsServerConfig, []byte) {
	t.Helper()
	base := t.TempDir()
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security")})
	if e := os.MkdirAll(s.moduleDir("nfs-manager"), 0700); e != nil {
		t.Fatal(e)
	}
	v := defaultNFSServerConfig()
	v.Revision = 1
	b, _ := jsonMarshalNFSConfig(v)
	if e := atomicWrite(filepath.Join(s.moduleDir("nfs-manager"), "server.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "active", nil }
	return s, v, b
}

func TestNFSRecoveryRestoresCompleteConfigurationButNotExternalChanges(t *testing.T) {
	for _, phase := range []string{"old", "next", "external", "committed"} {
		t.Run(phase, func(t *testing.T) {
			s, v, old := nfsTransactionFixture(t)
			v.Revision++
			v.Port++
			next, _ := jsonMarshalNFSConfig(v)
			transaction := nfsServerTransaction{ID: core.ID(), State: "applying", Old: old, OldExists: true, NextSHA: core.Hash(string(next)), WasActive: true}
			if phase == "next" || phase == "committed" {
				atomicWrite(filepath.Join(s.moduleDir("nfs-manager"), "server.json"), next, 0600)
			}
			if phase == "external" {
				atomicWrite(filepath.Join(s.moduleDir("nfs-manager"), "server.json"), []byte("external"), 0600)
			}
			if phase == "committed" {
				transaction.State = "committed"
			}
			moduleWrite(filepath.Join(s.moduleDir("nfs-manager"), "pending-server.json"), transaction)
			_, e := s.recoverNFSServer()
			current, _ := os.ReadFile(filepath.Join(s.moduleDir("nfs-manager"), "server.json"))
			if phase == "external" {
				if e == nil || string(current) != "external" || !s.nfsPending() {
					t.Fatal("external configuration overwritten")
				}
				return
			}
			want := old
			if phase == "committed" {
				want = next
			}
			if e != nil || !reflect.DeepEqual(current, want) || s.nfsPending() {
				t.Fatal("recovery boundary incorrect", e)
			}
			info, e := os.Stat(filepath.Join(s.moduleDir("nfs-manager"), "server-transactions", transaction.ID+".json"))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private recovery exposed", e)
			}
		})
	}
}

func TestNFSOnlineCandidateHasLiveOwnerAndCompleteConfig(t *testing.T) {
	for _, phase := range []string{"live", "missing-owner", "unlocked", "external", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			s, _, b := nfsTransactionFixture(t)
			lock, e := s.lockNFSServer()
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Close()
			owner := ftpApplyOwnerFixture(t, s, lock)
			transaction := nfsServerTransaction{ID: core.ID(), State: "applying", NextSHA: core.Hash(string(b)), WasActive: true, ApplyOwner: owner}
			if phase == "missing-owner" {
				transaction.ApplyOwner = nil
			}
			if phase == "unlocked" {
				lock.Close()
			}
			if phase == "external" {
				atomicWrite(filepath.Join(s.moduleDir("nfs-manager"), "server.json"), []byte("outside"), 0600)
			}
			if phase == "stopped" {
				transaction.WasActive = false
			}
			moduleWrite(filepath.Join(s.moduleDir("nfs-manager"), "pending-server.json"), transaction)
			e = s.authorizeNFSStart(context.Background())
			if (phase == "live") != (e == nil) {
				t.Fatal("wrong candidate admission", phase, e)
			}
			if !s.nfsPending() {
				t.Fatal("startup consumed recovery journal")
			}
		})
	}
}

func TestNFSLiveApplyProbeFailureRollsBackAndStoppedStateRemainsStopped(t *testing.T) {
	s, v, old := nfsTransactionFixture(t)
	lock, e := s.lockNFSServer()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	restarts := 0
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "restart" {
			restarts++
			if restarts == 1 {
				return "", errors.New("controlled candidate failure")
			}
		}
		return "active", nil
	}
	v.Revision++
	v.Port++
	if e = s.applyNFSServer(context.Background(), v); e == nil {
		t.Fatal("candidate failure accepted")
	}
	current, _ := os.ReadFile(filepath.Join(s.moduleDir("nfs-manager"), "server.json"))
	if !reflect.DeepEqual(current, old) || restarts != 2 || s.nfsPending() {
		t.Fatal("old config/service not restored", restarts)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "inactive", nil }
	if e = s.applyNFSServer(context.Background(), v); e != nil {
		t.Fatal(e)
	}
	if restarts != 2 || s.nfsPending() {
		t.Fatal("stopped service started or incomplete commit")
	}
}
