//go:build linux

package executor

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func redisPeerUnitFixture(id string) string {
	return "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=456\nInvocationID=" + strings.Repeat("a", 32) +
		"\nControlGroup=/system.slice/system-panel\\x2dredis.slice/" + redisUnit(id) +
		"\nExecMainStartTimestampMonotonic=123456\nUser=root\nGroup=panel-redis\n"
}

func TestRedisPeerUnitIdentityClosedAndInstanceBound(t *testing.T) {
	id := strings.Repeat("a", 32)
	raw := redisPeerUnitFixture(id)
	got, err := redisPeerUnitState(raw, id)
	if err != nil || got.PID != 456 || got.Invocation != strings.Repeat("a", 32) {
		t.Fatal("exact unit refused", err)
	}
	direct := strings.Replace(raw, "/system.slice/system-panel\\x2dredis.slice/", "/system.slice/", 1)
	if _, err := redisPeerUnitState(direct, id); err != nil {
		t.Fatal("explicit system.slice refused", err)
	}
	changes := map[string][2]string{
		"other-instance":   {redisUnit(id), redisUnit(strings.Repeat("b", 32))},
		"stopped":          {"ActiveState=active", "ActiveState=inactive"},
		"transition":       {"SubState=running", "SubState=start"},
		"not-loaded":       {"LoadState=loaded", "LoadState=not-found"},
		"root-pid":         {"MainPID=456", "MainPID=1"},
		"alias-pid":        {"MainPID=456", "MainPID=0456"},
		"empty-generation": {"InvocationID=" + strings.Repeat("a", 32), "InvocationID="},
		"alias-start":      {"Monotonic=123456", "Monotonic=0123456"},
		"wrong-group":      {"Group=panel-redis", "Group=root"},
		"wrong-user":       {"User=root", "User=panel-redis"},
		"delegated":        {"redis.slice/", "redis.slice/delegated/"},
	}
	for name, pair := range changes {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(raw, pair[0], pair[1], 1)
			if changed == raw {
				t.Fatal("invalid fixture")
			}
			if _, err := redisPeerUnitState(changed, id); err == nil {
				t.Fatal("foreign/transitional unit accepted")
			}
		})
	}
	for _, changed := range []string{raw + "MainPID=456\n", raw + "Unknown=value\n", strings.TrimSuffix(raw, "\n"), strings.Repeat("x", 8193)} {
		if _, err := redisPeerUnitState(changed, id); err == nil {
			t.Fatal("unclosed unit state")
		}
	}
}

func TestRedisPeerCgroupV1V2AndHybridUseActualSystemdDomain(t *testing.T) {
	expected := "/system.slice/" + redisUnit(strings.Repeat("a", 32))
	for _, raw := range []string{"0::" + expected + "\n", "1:name=systemd:" + expected + "\n2:cpu,cpuacct:" + expected + "\n", "0::/\n1:name=systemd:" + expected + "\n2:memory:/\n"} {
		if !redisPeerCgroup(raw, expected) {
			t.Fatal("legitimate hierarchy refused", raw)
		}
	}
	for _, raw := range []string{
		"0::" + expected + "/delegated\n", "0::/\n", "2:memory:" + expected + "\n",
		"0::" + expected + "\n0::" + expected + "\n", "01:name=systemd:" + expected + "\n",
		"0::" + expected + "\n1:name=systemd:/foreign\n", "1:name=systemd,cpu:" + expected + "\n",
		"1:name=systemd:" + expected, "1:name=systemd:/system.slice/../foreign\n",
	} {
		if redisPeerCgroup(raw, expected) {
			t.Fatal("wrong hierarchy authorized", raw)
		}
	}
}

func TestRedisPeerKernelStatusRequiresAllNonRootIDsNoSavedCapabilities(t *testing.T) {
	account := redisServiceAccount{UID: 1234, GID: 2345}
	raw := "Uid:\t1234\t1234\t1234\t1234\nGid:\t2345\t2345\t2345\t2345\nGroups:\t2345\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nCapBnd:\t000001ffffffffff\n"
	if !redisPeerProcessStatus(raw, account) {
		t.Fatal("exact nonroot status refused")
	}
	for name, pair := range map[string][2]string{
		"saved-root":         {"1234\t1234\t1234\t1234", "1234\t1234\t0\t1234"},
		"saved-root-group":   {"2345\t2345\t2345\t2345", "2345\t2345\t0\t2345"},
		"supplementary-root": {"Groups:\t2345", "Groups:\t2345 0"},
		"no-nnp":             {"NoNewPrivs:\t1", "NoNewPrivs:\t0"},
		"effective-cap":      {"CapEff:\t0000000000000000", "CapEff:\t0000000000000001"},
		"permitted-cap":      {"CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001"},
	} {
		t.Run(name, func(t *testing.T) {
			if redisPeerProcessStatus(strings.Replace(raw, pair[0], pair[1], 1), account) {
				t.Fatal("unsafe process accepted")
			}
		})
	}
	if redisPeerProcessStatus(raw+"Gid:\t2345\t2345\t2345\t2345\n", account) ||
		redisPeerProcessStatus(raw, redisServiceAccount{UID: 0, GID: 2345}) {
		t.Fatal("duplicate/root status")
	}
}

type redisPeerDirectoryModel struct {
	mode     os.FileMode
	uid, gid uint32
}

func (f redisPeerDirectoryModel) Name() string       { return "private-model" }
func (f redisPeerDirectoryModel) Size() int64        { return 0 }
func (f redisPeerDirectoryModel) Mode() os.FileMode  { return f.mode }
func (f redisPeerDirectoryModel) ModTime() time.Time { return time.Unix(1, 0) }
func (f redisPeerDirectoryModel) IsDir() bool        { return f.mode.IsDir() }
func (f redisPeerDirectoryModel) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid} }

func TestRedisPeerDirectoryIsRootOwnedGroupPrivateNotAWorldSocketClaim(t *testing.T) {
	a := redisServiceAccount{UID: 1234, GID: 2345}
	positive := redisPeerDirectoryModel{os.ModeDir | 0770, 0, 2345}
	if !redisRuntimeDirectoryInfo(positive, a) {
		t.Fatal("Root0770 private group refused")
	}
	for _, v := range []redisPeerDirectoryModel{
		{os.ModeDir | 0777, 0, 2345}, {os.ModeDir | 0755, 0, 2345}, {os.ModeDir | 0700, 0, 2345},
		{os.ModeDir | 0770, 1234, 2345}, {os.ModeDir | 0770, 0, 0}, {os.ModeDir | 0770 | os.ModeSetgid, 0, 2345},
		{os.ModeSymlink | 0770, 0, 2345}, {0770, 0, 2345},
	} {
		if redisRuntimeDirectoryInfo(v, a) {
			t.Fatal("unsafe runtime directory accepted", v)
		}
	}
}

func TestRedisPeerRootAccountRejectedBeforeAnyFileOrConnection(t *testing.T) {
	for _, a := range []redisServiceAccount{{0, 2345}, {1234, 0}} {
		conn, dir, pidfd, err := dialRedisVerifiedAt(context.Background(), "/must-not-open", a, func(context.Context) (redisPeerIdentity, error) {
			t.Fatal("unexpected observer")
			return redisPeerIdentity{}, nil
		})
		if err == nil || conn != nil || dir != nil || pidfd != -1 {
			t.Fatal("root account accepted")
		}
	}
}

func TestRedisPeerLegacyACLNeverDialsOrFallsBack(t *testing.T) {
	instance, _ := redisACLFixture()
	instance.AuthMode = "acl-password-v1"
	var listener *net.TCPListener
	for port := 16379; port <= 16999; port++ {
		v, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			listener = v.(*net.TCPListener)
			instance.Port = port
			break
		}
	}
	if listener == nil {
		t.Fatal("no isolated fixture port within actual contract")
	}
	defer listener.Close()
	if _, err := redisInfoText(context.Background(), instance, "PING"); err == nil || !strings.Contains(err.Error(), "迁移") {
		t.Fatal("legacy ACL did not fail closed before transport", err)
	}
	listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("legacy ACL contacted TCP")
	}
	timeout, ok := err.(net.Error)
	if !ok || !timeout.Timeout() {
		t.Fatal("unexpected listener observation", err)
	}
}
