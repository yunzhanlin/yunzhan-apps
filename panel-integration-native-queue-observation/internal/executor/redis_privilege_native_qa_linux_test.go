//go:build linux && panel_redis_privilege_native_qa

package executor

// Explicit actual-kernel handover acceptance. No normal Redis configuration,
// runtime or instance is created, read, rewritten or removed by this test.
// The private PID1 controller supplies ONLY its new readonly own probe file.
import (
	"flag"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"testing"
)

var redisPrivilegeNativeProbe = flag.String("redis-privilege-native-probe", "", "exact newly owned readonly native identity probe")

func TestRedisPrivilegeNativeExecHandover(t *testing.T) {
	probe := *redisPrivilegeNativeProbe
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/run/panel-qa-redis-privilege24bkxx-(arm64|amd64)-[a-f0-9]{16}/probe[.]py$`).MatchString(probe) {
		t.Fatal("explicit Root native handover/probe required")
	}
	u, err := user.Lookup("panel-redis")
	if err != nil || u.Username != "panel-redis" {
		t.Fatal("fixed service account", err)
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 {
		t.Fatal("fixed non-root account")
	}
	// This deliberately replaces ONLY this new test process with the owned
	// Python identity observer. It uses the exact PRODUCTION locked-thread,
	// all-thread credential drop, capset, verification and exec implementation.
	if err := redisExecUnprivileged("/usr/bin/python3", probe, uid, gid); err != nil {
		t.Fatal("actual production handover", err)
	}
	t.Fatal("exec unexpectedly returned")
}
