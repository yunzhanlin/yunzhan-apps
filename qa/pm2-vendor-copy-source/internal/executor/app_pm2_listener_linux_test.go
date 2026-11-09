//go:build linux

package executor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestPM2ListenerNSSRequiresExactExistingSiteIdentity(t *testing.T) {
	site := strings.Repeat("a", 32)
	name := siteUser(site)
	passwd := name + ":x:991:992:panel-managed-" + site + ":/srv/panel/sites/" + site + ":/usr/sbin/nologin\n"
	group := name + ":x:992:\n"
	want := pm2ListenerAccount{991, 992}
	if got, err := decodePM2ListenerAccount(site, passwd, group); err != nil || got != want {
		t.Fatal(got, err)
	}
	for _, fault := range []struct{ site, p, g string }{
		{"", passwd, group}, {site, passwd + passwd, group}, {site, passwd, group + group},
		{site, strings.Replace(passwd, ":991:", ":0:", 1), group},
		{site, strings.Replace(passwd, ":992:", ":0:", 1), group},
		{site, strings.Replace(passwd, ":991:", ":0991:", 1), group},
		{site, strings.Replace(passwd, "panel-managed-", "foreign-", 1), group},
		{site, strings.Replace(passwd, "/usr/sbin/nologin", "/bin/bash", 1), group},
		{site, strings.Replace(passwd, "/srv/panel/sites/", "/foreign/", 1), group},
		{site, passwd, strings.Replace(group, ":992:", ":993:", 1)},
		{site, passwd, strings.Replace(group, name, "another-site", 1)},
		{site, strings.TrimSuffix(passwd, "\n"), group},
		{site, passwd + "\x00", group},
	} {
		if _, err := decodePM2ListenerAccount(fault.site, fault.p, fault.g); err == nil {
			t.Fatal("foreign or incomplete NSS identity accepted")
		}
	}
}

func TestPM2ListenerCensusCanonicalCompleteAndBounded(t *testing.T) {
	got, err := decodePM2CgroupPIDs([]byte("102\n101\n"))
	if err != nil || !reflect.DeepEqual(got, []int{101, 102}) {
		t.Fatal(got, err)
	}
	many := ""
	for n := 2; n < pm2ListenerMaxProcesses+3; n++ {
		many += strconv.Itoa(n) + "\n"
	}
	for _, raw := range []string{"", "101", "101\n101\n", "0\n", "1\n", "0101\n", "+101\n", "-1\n", "101 \n", "101\r\n", "101\n\n", many, strings.Repeat("x", 4097)} {
		if _, err := decodePM2CgroupPIDs([]byte(raw)); err == nil {
			t.Fatal("unknown or partial process census accepted")
		}
	}
}

const pm2ListenerFixtureTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func pm2ListenerFixtureSocket(port, uid int, inode, addr string) string {
	return fmt.Sprintf("0: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %d 0 %s 1 0000000000000000 100 0 0 10 0\n", addr, port, uid, inode)
}

func TestPM2ListenerSocketTableRejectsUIDOnlyWildcardAndAlias(t *testing.T) {
	row := pm2ListenerFixtureSocket(24431, 991, "700", "0100007F")
	good := map[string][]byte{"tcp": []byte(pm2ListenerFixtureTCPHeader + row), "tcp6": []byte(pm2ListenerFixtureTCPHeader)}
	got, err := pm2LoopbackListeners(good, 24431, 991)
	if err != nil || len(got) != 1 || got["700"].UID != 991 {
		t.Fatal(got, err)
	}
	for _, raw := range []string{
		pm2ListenerFixtureTCPHeader,
		pm2ListenerFixtureTCPHeader + row + row,
		strings.Replace(pm2ListenerFixtureTCPHeader+row, "0100007F", "00000000", 1),
		pm2ListenerFixtureTCPHeader + pm2ListenerFixtureSocket(24431, 0, "700", "0100007F"),
		pm2ListenerFixtureTCPHeader + pm2ListenerFixtureSocket(24431, 992, "700", "0100007F"),
		pm2ListenerFixtureTCPHeader + pm2ListenerFixtureSocket(24431, 991, "0", "0100007F"),
		strings.Replace(pm2ListenerFixtureTCPHeader+row, " 0A ", " 01 ", 1),
	} {
		if _, err := pm2LoopbackListeners(map[string][]byte{"tcp": []byte(raw)}, 24431, 991); err == nil {
			t.Fatal("unknown or foreign listener accepted")
		}
	}
	mixed := map[string][]byte{"tcp": good["tcp"], "tcp6": []byte(pm2ListenerFixtureTCPHeader + strings.Replace(row, "0100007F", "00000000000000000000000000000000", 1))}
	if _, err := pm2LoopbackListeners(mixed, 24431, 991); err == nil {
		t.Fatal("dual-stack wildcard at the probe port accepted")
	}
	// A separate exact address cannot receive the IPv4 loopback connect.
	separate := map[string][]byte{"tcp": []byte(pm2ListenerFixtureTCPHeader + row + pm2ListenerFixtureSocket(24431, 992, "701", "0200007F"))}
	if _, err := pm2LoopbackListeners(separate, 24431, 991); err != nil {
		t.Fatal("unrelated exact-address listener blocked the selected probe", err)
	}
}

type pm2OwnedListenerFixture struct {
	s                         *Service
	app                       pm2App
	root, unit, group, binary string
	listener                  net.Listener
}

func pm2OwnedListenerTestFixture(t *testing.T) *pm2OwnedListenerFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual root-owned fixture identities are exercised in the Root Linux suite")
	}
	s, app, path := pm2StateAppFixture(t)
	pm2FixtureRootVendor(t, s)
	root := s.Config.SystemRoot
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	app.Port = listener.Addr().(*net.TCPAddr).Port
	if err = moduleWrite(path, app); err != nil {
		t.Fatal(err)
	}
	f := &pm2OwnedListenerFixture{s: s, app: app, root: root, unit: "panel-pm2@" + app.ID + ".service", listener: listener}
	f.group = "/system.slice/system-panel\\x2dpm2.slice/" + f.unit
	put := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	private := filepath.Join(s.Config.SitesDir, app.SiteID, "private")
	if err = os.MkdirAll(private, 0700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		p        string
		uid, gid int
	}{{filepath.Join(s.Config.SitesDir, app.SiteID, "public"), 991, 33}, {private, 991, 992}} {
		if err = os.Chown(entry.p, entry.uid, entry.gid); err != nil {
			t.Fatal(err)
		}
	}
	f.binary = s.systemPath(pm2NodeBinaryOn(runtimecatalog.HostPlatform()))
	if _, err := os.Lstat(f.binary); os.IsNotExist(err) {
		put(f.binary, "fixture Node inode, never executed\n", 0755)
	} else if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{101, 102} {
		base := filepath.Join(root, "proc", strconv.Itoa(pid))
		fields := make([]string, 22)
		for n := range fields {
			fields[n] = "0"
		}
		fields[0] = "S"
		fields[1] = "1"
		fields[19] = strconv.Itoa(1000 + pid)
		if pid == 102 {
			fields[1] = "101"
		}
		put(filepath.Join(base, "stat"), strconv.Itoa(pid)+" (node (fixture)) "+strings.Join(fields, " ")+"\n", 0600)
		put(filepath.Join(base, "cgroup"), "0::"+f.group+"\n", 0600)
		put(filepath.Join(base, "status"), taskIdentityFixtureStatus("991")+"Gid:\t992 992 992 992\n", 0600)
		if err = os.Chown(base, 991, 992); err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(filepath.Join(base, "fd"), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(f.binary, filepath.Join(base, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink("socket:[700]", filepath.Join(root, "proc/102/fd/7")); err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(root, "sys/fs/cgroup", f.group, "cgroup.procs"), "101\n102\n", 0600)
	put(filepath.Join(root, "proc/net/tcp"), pm2ListenerFixtureTCPHeader+pm2ListenerFixtureSocket(app.Port, 991, "700", "0100007F"), 0600)
	put(filepath.Join(root, "proc/net/tcp6"), pm2ListenerFixtureTCPHeader, 0600)
	state := pm2TestState("active", "enabled")
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command == "/usr/bin/getent" && len(args) == 2 && args[1] == siteUser(app.SiteID) {
			if args[0] == "passwd" {
				return siteUser(app.SiteID) + ":x:991:992:panel-managed-" + app.SiteID + ":/srv/panel/sites/" + app.SiteID + ":/usr/sbin/nologin\n", nil
			}
			if args[0] == "group" {
				return siteUser(app.SiteID) + ":x:992:\n", nil
			}
		}
		if command == "/usr/bin/systemctl" && len(args) == 3 && args[0] == "show" && args[1] == f.unit {
			if args[2] == "--property=ControlGroup" {
				return "ControlGroup=" + f.group + "\n", nil
			}
			return pm2TestStateText(state), nil
		}
		return "", fmt.Errorf("unexpected fixture command %s %v", command, args)
	}
	return f
}

func TestPM2ListenerRequiresPositiveSocketOwnershipInsideExactProject(t *testing.T) {
	f := pm2OwnedListenerTestFixture(t)
	if err := f.s.verifyPM2OwnedLoopback(context.Background(), f.unit, f.app.Port); err != nil {
		t.Fatal("complete owned loopback witness rejected", err)
	}
	for _, fault := range []string{"no-owned-fd", "foreign-project-same-uid", "root-listener", "different-process-cgroup", "saved-root-gid", "retained-capability", "wrong-node-inode", "missing-supervisor", "delegated-cgroup"} {
		t.Run(fault, func(t *testing.T) {
			f := pm2OwnedListenerTestFixture(t)
			change := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(f.root, path), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "no-owned-fd", "foreign-project-same-uid":
				if err := os.Remove(filepath.Join(f.root, "proc/102/fd/7")); err != nil {
					t.Fatal(err)
				}
				if fault == "foreign-project-same-uid" {
					if err := os.MkdirAll(filepath.Join(f.root, "proc/999/fd"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("socket:[700]", filepath.Join(f.root, "proc/999/fd/9")); err != nil {
						t.Fatal(err)
					}
				}
			case "root-listener":
				change("proc/net/tcp", pm2ListenerFixtureTCPHeader+pm2ListenerFixtureSocket(f.app.Port, 0, "700", "0100007F"))
			case "different-process-cgroup":
				change("proc/102/cgroup", "0::/system.slice/panel-pm2@other-project.service\n")
			case "saved-root-gid":
				change("proc/102/status", taskIdentityFixtureStatus("991")+"Gid:\t992 992 0 992\n")
			case "retained-capability":
				change("proc/102/status", strings.Replace(taskIdentityFixtureStatus("991"), "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1)+"Gid:\t992 992 992 992\n")
			case "wrong-node-inode":
				if err := os.Remove(filepath.Join(f.root, "proc/101/exe")); err != nil {
					t.Fatal(err)
				}
				change("wrong-node", "unrelated executable")
				if err := os.Symlink(filepath.Join(f.root, "wrong-node"), filepath.Join(f.root, "proc/101/exe")); err != nil {
					t.Fatal(err)
				}
			case "missing-supervisor":
				change("sys/fs/cgroup"+f.group+"/cgroup.procs", "102\n")
			case "delegated-cgroup":
				f.group += "/delegated"
			}
			if err := f.s.verifyPM2OwnedLoopback(context.Background(), f.unit, f.app.Port); err == nil {
				t.Fatal("real connect and matching UID incorrectly proved project ownership", fault)
			}
		})
	}
}

func TestPM2ListenerWiredReadinessUsesBothOwnershipObservations(t *testing.T) {
	f := pm2OwnedListenerTestFixture(t)
	if err := f.s.pm2Ready(context.Background(), f.unit, f.app.Port); err != nil {
		t.Fatal("production readiness rejected complete project ownership", err)
	}
}

func TestPM2ListenerProcessGenerationChangeCannotReuseReadiness(t *testing.T) {
	f := pm2OwnedListenerTestFixture(t)
	original := f.s.Config.Run
	shows := 0
	f.s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/systemctl" && len(args) == 3 && args[2] != "--property=ControlGroup" {
			shows++
			if shows == 2 {
				path := filepath.Join(f.root, "proc/102/stat")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, []byte(strings.Replace(string(raw), " 1102 ", " 9999 ", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return original(ctx, name, args...)
	}
	if err := f.s.verifyPM2OwnedLoopback(context.Background(), f.unit, f.app.Port); err == nil {
		t.Fatal("PID number accepted after original process generation changed")
	}
}

func TestPM2ListenerFixtureCannotFallThroughToHostReader(t *testing.T) {
	identity := taskProcessIdentity{PID: os.Getpid(), UID: 991, SafeUser: true}
	if _, err := pm2SameUIDProcRead(context.Background(), t.TempDir(), identity, 992, "sockets"); err == nil {
		t.Fatal("fixture root invoked the live same-UID reader")
	}
}
