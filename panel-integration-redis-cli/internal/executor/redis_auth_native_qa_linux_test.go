//go:build linux && panel_redis_native_qa

package executor

// Explicit opt-in actual-engine acceptance, never a default mock/skip. Requires
// the genuine normal-store Redis8.2.10 prefix. The controller supplies one new,
// Root-owned private case and a PID1 PrivateNetwork sandbox; no installed user
// instance, normal configuration or runtime binary may be changed.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"local/panel/internal/core"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var redisACLNativeCase = flag.String("redis-acl-native-case", "", "exact newly owned Redis ACL engine QA case")
var redisACLNativeBinarySHA = flag.String("redis-acl-native-binary-sha256", "", "genuine normal-store redis-server SHA256")
var redisACLNativeRuntimeAlias = flag.String("redis-acl-native-runtime-alias", "", "private PID1 bind mount for the unprivileged test child")

func TestRedisACLNativeEngineAuthenticationAndPersistence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("actual engine acceptance requires Root sandbox")
	}
	root := *redisACLNativeCase
	if !regexp.MustCompile("^/var/lib/panel-executor/redis-peer-engine24bktu-amd64[.][a-f0-9]{32}$").MatchString(root) {
		t.Fatal("unbound private native case")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0750 {
		t.Fatal("native case ownership/mode")
	}
	meta, ok := info.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != 0 {
		t.Fatal("case is not Root owned")
	}
	alias := *redisACLNativeRuntimeAlias
	visible, aliasErr := os.Stat(alias)
	if alias != "/run/panel-qa-redis-peer-engine24bktu-amd64" || aliasErr != nil || !os.SameFile(info, visible) {
		t.Fatal("private runtime alias is not the exact owned case bind mount")
	}
	if !regexp.MustCompile("^[a-f0-9]{64}$").MatchString(*redisACLNativeBinarySHA) {
		t.Fatal("unbound native ELF")
	}
	use, err := runtimeUseLock()
	if err != nil {
		t.Fatal("original read-only shared runtime interlock", err)
	}
	defer use.Close()
	runtime, err := LoadRuntime("redis-8.2.10")
	if err != nil || runtime.Release.Version != "8.2.10" || runtime.Release.SHA256 != "d33935732f7fc15476295fe05f5ce740927bc14847798e47b3f67b4f27b8b478" {
		t.Fatal("genuine normal-store runtime unavailable", err)
	}
	binary := "/opt/panel/runtimes/redis/8.2.10/bin/redis-server"
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	raw = nil
	if hex.EncodeToString(digest[:]) != *redisACLNativeBinarySHA {
		t.Fatal("genuine redis-server bytes changed")
	}
	account, err := user.Lookup("panel-redis")
	if err != nil {
		t.Fatal("real panel-redis system account missing", err)
	}
	uid, e1 := strconv.Atoi(account.Uid)
	gid, e2 := strconv.Atoi(account.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 || meta.Gid != uint32(gid) {
		t.Fatal("unsafe private native account")
	}
	data := filepath.Join(root, "data")
	visibleData := filepath.Join(alias, "data")
	if err = os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(data, uid, gid); err != nil {
		t.Fatal(err)
	}
	management := filepath.Join(root, "run")
	visibleManagement := filepath.Join(alias, "run")
	if os.Mkdir(management, 0700) != nil || os.Chown(management, 0, gid) != nil || os.Chmod(management, 0770) != nil {
		t.Fatal("NEW private Root-owned management directory")
	}
	instance := core.RedisInstance{ID: core.ID(), Name: "private native ACL engine", ReleaseID: "redis-8.2.10", Port: 16379, MaxMemoryMB: 32, CreatedAt: core.Now(), AuthMode: core.RedisACLAuthMode}
	secret, err := newRedisAuthSecret(instance)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { secret.AdminPassword = ""; secret.AppPassword = "" }()
	if err = writeRedisAuthSecret(root, secret); err != nil {
		t.Fatal(err)
	}
	config := redisInstanceConfig(instance, secret)
	// ONLY the private data/pid/socket paths differ from the production renderer;
	// the three actual ACL definitions, hashes and closed command roles do not.
	for _, pair := range [][2]string{{"dir " + redisData(instance.ID) + "\n", "dir " + visibleData + "\n"}, {"pidfile /run/panel-redis-" + instance.ID + "/redis.pid\n", "pidfile " + filepath.Join(visibleManagement, "redis.pid") + "\n"}, {"unixsocket " + redisRunDirectory(instance.ID) + "/admin.sock\n", "unixsocket " + filepath.Join(visibleManagement, "admin.sock") + "\n"}} {
		if strings.Count(config, pair[0]) != 1 {
			t.Fatal("production configuration binding drift")
		}
		config = strings.Replace(config, pair[0], pair[1], 1)
	}
	configFile := filepath.Join(root, "redis.conf")
	file, err := os.OpenFile(configFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0640)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Chown(0, gid); err == nil {
		err = file.Chmod(0640) // NEW hashed-only fixture config; preserve access under strict umask.
	}
	if err == nil {
		_, err = file.WriteString(config)
	}
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	var running *exec.Cmd
	var done chan error
	stop := func() error {
		if running == nil {
			return nil
		}
		process := running
		wait := done
		running = nil
		done = nil
		if err := process.Process.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("owned engine stop: %w", err)
		}
		select {
		case err := <-wait:
			return err
		case <-time.After(10 * time.Second):
			// The exact child belongs ONLY to this new private test; never a name kill.
			_ = process.Process.Kill()
			<-wait
			return fmt.Errorf("owned private engine required forced termination")
		}
	}
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dial := func() net.Conn {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "127.0.0.1:16379")
		if err != nil {
			t.Fatal("private native connection", err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn
	}
	run := func(username, password string, command ...string) (any, error) {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "127.0.0.1:16379")
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return redisAuthenticatedCommand(ctx, conn, username, password, 0, command...)
	}
	start := func(number int) {
		log, err := os.OpenFile(filepath.Join(root, fmt.Sprintf("engine-%d.log", number)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		running = exec.CommandContext(ctx, binary, filepath.Join(alias, "redis.conf"))
		running.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
		running.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
		running.Stdout = log
		running.Stderr = log
		if err = running.Start(); err != nil {
			log.Close()
			t.Fatal("start owned unprivileged engine", err)
		}
		done = make(chan error, 1)
		child := running
		completed := done
		go func() { err := child.Wait(); log.Close(); completed <- err }()
		deadline := time.Now().Add(10 * time.Second)
		for {
			value, err := run("panel-admin", secret.AdminPassword, "PING")
			if err == nil && value == "PONG" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("actual Redis did not admit production ACL configuration; inspect retained own engine log")
			}
			time.Sleep(50 * time.Millisecond)
		}
		actual, err := os.ReadFile("/proc/" + strconv.Itoa(running.Process.Pid) + "/exe")
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(actual) != digest {
			t.Fatal("actual running engine is not the normal-store binary")
		}
		status, err := os.ReadFile("/proc/" + strconv.Itoa(running.Process.Pid) + "/status")
		if err != nil || !strings.Contains(string(status), fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid)) || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
			t.Fatal("actual engine did not retain unprivileged UID and NoNewPrivileges", err)
		}
		for _, name := range []string{"cmdline", "environ"} {
			value, err := os.ReadFile("/proc/" + strconv.Itoa(running.Process.Pid) + "/" + name)
			if err != nil || strings.Contains(string(value), secret.AdminPassword) || strings.Contains(string(value), secret.AppPassword) {
				t.Fatal("private credential entered actual process arguments/environment", err)
			}
		}
		// Exercise the production descriptor/proc verifier against this genuine
		// unprivileged Redis ELF and real kernel cgroup/argv/environment. The
		// enclosing unit belongs to this private fixture, not a normal managed
		// instance: this is deliberately NOT default PID1/API acceptance.
		groupRaw, err := os.ReadFile("/proc/" + strconv.Itoa(running.Process.Pid) + "/cgroup")
		if err != nil {
			t.Fatal("actual private engine cgroup", err)
		}
		group := ""
		for _, line := range strings.Split(string(groupRaw), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && (parts[1] == "name=systemd" || parts[0] == "0" && group == "") {
				group = parts[2]
			}
		}
		if group == "" {
			t.Fatal("actual private systemd domain missing")
		}
		unit := redisPeerUnit{PID: running.Process.Pid, Cgroup: group, Invocation: strings.Repeat("a", 32), Started: "1"}
		serviceAccount := redisServiceAccount{UID: uint32(uid), GID: uint32(gid)}
		observe := func(ctx context.Context) (redisPeerIdentity, error) {
			return redisPeerProcessAt(ctx, "/proc", binary, filepath.Join(alias, "redis.conf"), serviceAccount, unit)
		}
		conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, management, serviceAccount, observe)
		if err != nil {
			t.Fatal("actual engine kernel identity was not verified before AUTH", err)
		}
		value, authErr := redisAuthenticatedCommand(ctx, conn, "panel-admin", secret.AdminPassword, 0, "PING")
		conn.Close()
		directory.Close()
		unix.Close(pidfd)
		if authErr != nil || value != "PONG" {
			t.Fatal("genuine verified Unix peer AUTH/PING", authErr)
		}
	}
	start(1)
	anonymous := dial()
	_, err = redisRESPRoundTrip(anonymous, newRedisRESPReader(anonymous), []string{"PING"})
	anonymous.Close()
	if err == nil || !strings.Contains(err.Error(), "NOAUTH") {
		t.Fatal("anonymous PING was not refused")
	}
	if _, err = run("app-"+instance.ID[:12], strings.Repeat("ef", 32), "PING"); err == nil {
		t.Fatal("wrong real app password admitted")
	}
	app := "app-" + instance.ID[:12]
	for _, command := range [][]string{{"ACL", "LIST"}, {"CONFIG", "GET", "*"}, {"FLUSHALL"}, {"MODULE", "LIST"}} {
		conn := dial()
		reader := newRedisRESPReader(conn)
		value, err := redisRESPRoundTrip(conn, reader, []string{"AUTH", app, secret.AppPassword})
		if err != nil || value != "OK" {
			conn.Close()
			t.Fatal("actual app AUTH refused")
		}
		_, err = redisRESPRoundTrip(conn, reader, command)
		conn.Close()
		if err == nil {
			t.Fatal("actual app ACL admitted administrative/dangerous command", command[0])
		}
		if command[0] != "CONFIG" && !strings.Contains(err.Error(), "NOPERM") {
			t.Fatal("actual server did not demonstrate the expected ACL refusal", command[0], err)
		}
	}
	expected := map[string]string{"unicode": "云栈😀", "plain": "retained-before-stop", "transaction": "original"}
	for key, value := range expected {
		result, err := run(app, secret.AppPassword, "EVAL", "return redis.call('SET',KEYS[1],ARGV[1])", "1", key, value)
		if err != nil || result != "OK" {
			t.Fatal("real application write failed", err)
		}
	}
	mutation, _ := json.Marshal(map[string]string{"old": "wrong", "value": "must-not-write"})
	value, err := run("panel-admin", secret.AdminPassword, "EVAL", redisTextUpdateScript, "1", "transaction", string(mutation))
	if err != nil || value != "changed" {
		t.Fatal("real compare-and-swap did not refuse stale edit", err)
	}
	if err = stop(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(data, "appendonlydir"))
	if err != nil || len(entries) == 0 {
		t.Fatal("real AOF files missing", err)
	}
	start(2)
	// Strict read-only validation. No SET, CREATE, UPSERT or data reconstruction.
	for key, expectedValue := range expected {
		value, err := run(app, secret.AppPassword, "EVAL", "return redis.call('GET',KEYS[1])", "1", key)
		if err != nil || value != expectedValue {
			t.Fatal("real AOF restart lost original data", key, err)
		}
	}
	if err = stop(); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"ok": true, "scope": "real private unprivileged Redis engine,not normal panel instance API or programme installation", "redis_server_sha256": *redisACLNativeBinarySHA, "version": "8.2.10", "default_anonymous_refused": true, "wrong_password_refused": true, "app_admin_and_dangerous_commands_refused": true, "production_ACL_render_and_RESP_AUTH_used": true, "real_proc_ELF_argv_environment_and_Unix_peer_verified_before_AUTH_both_starts": true, "real_app_utf8mb4_writes_and_stale_CAS_refusal": true, "AOF_stop_restart_READONLY_original_values_retained": true, "only_owned_private_engine_stopped_data_retained": true, "credentials_not_in_argv_environment_or_logs": true, "all50_commercial": false}
	for _, name := range []string{"engine-1.log", "engine-2.log"} {
		value, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || strings.Contains(string(value), secret.AdminPassword) || strings.Contains(string(value), secret.AppPassword) {
			t.Fatal("private credential entered actual engine log", err)
		}
	}
	out, _ := json.Marshal(result)
	if err = os.WriteFile(filepath.Join(root, "native-engine-result.json"), append(out, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
