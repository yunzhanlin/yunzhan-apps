//go:build linux && panel_memcached_unix_native_qa

package executor

// Explicit private native qualification, NOT an installed application or a
// substitute for signed normal-store/Core authority. Only one NEW nonce-bound
// container and private bind are used. No image pull, original container
// mutation, global flush or existing software removal is permitted.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

var memcachedUnixNativeCase = flag.String("memcached-unix-native-case", "", "exact NEW sealed Memcached Unix qualification case")

func TestMemcachedUnixNativeEngineIsolationAndVolatileLifecycle(t *testing.T) {
	root := *memcachedUnixNativeCase
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/mcu24bkvg-amd64\.[a-f0-9]{32}$`).MatchString(root) {
		t.Fatal("unbound Root native case")
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("native case owner/mode")
	}
	var in struct {
		ProjectID     string `json:"project_id"`
		ContainerName string `json:"container_name"`
		SourceInputs  string `json:"source_inputs"`
		ImageID       string `json:"image_id"`
	}
	raw, e := os.ReadFile(filepath.Join(root, "intent.json"))
	if e != nil || json.Unmarshal(raw, &in) != nil || !core.ValidID(in.ProjectID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.SourceInputs) || in.ContainerName != "panel-qa-mcu-"+filepath.Base(root)[len("mcu24bkvg-amd64."):][:16] || in.ImageID != "sha256:cc3f45e091e88b03ec5a7365defcc1153365adefba32a94161d6faccc029383a" {
		t.Fatal("original private native intent")
	}
	account := memcachedUnixAccount{65534, 65534} // private fixture only; never a production NSS default
	dir := filepath.Join(root, "s")
	di, e := os.Lstat(dir)
	if e != nil || !memcachedUnixDirectoryInfo(di, account) {
		t.Fatal("new private bind owner/mode")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("no adoption of prior socket/data")
	}
	if e = memcachedUnixHostAvailable(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	acquire, done := context.WithTimeout(ctx, 3*time.Second)
	lease, e := productionDockerMutationStore().begin(acquire)
	done()
	if e != nil {
		t.Fatal("original complete Docker/runtime interlock", e)
	}
	defer lease.Close()
	ctx = context.WithValue(ctx, dockerMutationContextKey{}, lease)
	m := composeMetadata{ID: in.ProjectID, Name: in.ContainerName, Engine: "panel_" + in.ProjectID[:12], TemplateID: "memcached-cache", Services: 1, CreatedAt: core.Now()}
	read := func(c context.Context, p string) ([]byte, error) {
		return dockerRequest(c, http.MethodGet, p, nil, nil, 256<<10)
	}
	image, e := read(ctx, "/images/"+url.PathEscape(appcatalog.MemcachedDigestImage)+"/json")
	var imageInfo struct {
		ID string `json:"Id"`
	}
	if e != nil || json.Unmarshal(image, &imageInfo) != nil || imageInfo.ID != in.ImageID {
		t.Fatal("genuine pre-existing OCI image changed; no pull allowed")
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	list, e := read(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)))
	var prior []json.RawMessage
	if e != nil || json.Unmarshal(list, &prior) != nil || len(prior) != 0 {
		t.Fatal("new project is not empty")
	}
	var owned string
	stopped, complete := false, false
	events := map[string]any{"ok": false, "source_inputs": in.SourceInputs, "project_id": in.ProjectID, "private_engine_NOT_normal_Core_store_or_account_acceptance": true, "all50_commercial": false}
	defer func() {
		if owned != "" && !stopped {
			cleanup, close := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			current, err := read(cleanup, "/containers/"+owned+"/json")
			var v struct {
				ID, Name string
				Config   struct {
					Image  string
					Labels map[string]string
				}
				State struct {
					Running bool
					Pid     int
				}
			}
			if err == nil && json.Unmarshal(current, &v) == nil && v.ID == owned && v.Name == "/"+in.ContainerName && v.Config.Image == appcatalog.MemcachedDigestImage && v.Config.Labels["io.yunzhan.qa-case"] == root {
				if v.State.Running {
					_, err = dockerRequest(cleanup, http.MethodPost, "/containers/"+owned+"/stop?t=10", nil, nil, 16384)
				}
				if err == nil {
					stopped = true
				}
			}
			close()
			if !stopped {
				t.Error("owned container cleanup not confirmed; retain exact case and ID")
			}
		}
		events["container_id"], events["owned_container_stopped_and_retained"], events["ok"] = owned, stopped, complete && stopped && !t.Failed()
		f, err := os.OpenFile(filepath.Join(root, "native-engine-result.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			t.Error("original native result exists or cannot persist")
			return
		}
		defer f.Close()
		if json.NewEncoder(f).Encode(events) != nil || f.Sync() != nil {
			t.Error("native result not durable")
		}
	}()
	command := []string{"-s", "/run/memcached/cache.sock", "-a", "666", "-m", "128", "-I", "4m", "-U", "0", "-c", "256", "-t", "2"}
	spec := map[string]any{
		"Image": appcatalog.MemcachedDigestImage, "User": "65534:65534", "Entrypoint": []string{"memcached"}, "Cmd": command,
		"Labels":      map[string]string{"com.docker.compose.project": m.Engine, "com.docker.compose.service": "memcached", "com.docker.compose.oneoff": "False", "io.yunzhan.memcached.site-id": "", "io.yunzhan.qa-case": root},
		"Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", core.MemcachedUnixLiveness}, "Interval": int64(10 * time.Second), "Timeout": int64(3 * time.Second), "Retries": 12},
		"HostConfig":  map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "Memory": 192 << 20, "MemorySwap": 192 << 20, "NanoCpus": 1_000_000_000, "PidsLimit": 32, "Ulimits": []any{map[string]any{"Name": "nofile", "Soft": 1024, "Hard": 1024}}, "RestartPolicy": map[string]any{"Name": "unless-stopped"}, "LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "3"}}, "Mounts": []any{map[string]any{"Type": "bind", "Source": dir, "Target": "/run/memcached", "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}}}},
	}
	var made struct {
		ID string `json:"Id"`
	}
	if _, e = dockerRequest(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(in.ContainerName), spec, &made, 16384); e != nil {
		t.Fatal("once-only private container creation", e)
	}
	if len(made.ID) != 64 || !dockerObjectPattern.MatchString(made.ID) {
		t.Fatal("unknown new container identity; never recreate")
	}
	owned = made.ID
	if _, e = dockerRequest(ctx, http.MethodPost, "/containers/"+owned+"/start", nil, nil, 16384); e != nil {
		t.Fatal("once-only owned container start", e)
	}
	ready := func() int {
		t.Helper()
		until := time.Now().Add(20 * time.Second)
		for time.Now().Before(until) {
			state, err := read(ctx, "/containers/"+owned+"/json")
			if err != nil {
				t.Fatal(err)
			}
			id, pid, _, err := memcachedUnixRuntimeAt(ctx, state, m, "", dir, account, read)
			if err != nil || id != owned {
				t.Fatal("actual daemon contract not verified", err)
			}
			if memcachedUnixKernel(ctx, pid, owned, account, memcachedUnixReadFile) != nil {
				// Retain actual failed observations before stopping ONLY this
				// owned engine. These bounded proc/cgroup files contain no
				// cache data, credentials or environment. They grant no waiver.
				diagnostic := map[string]any{"pid": pid, "container_id": owned, "observations_after_refusal_not_reconstructed_original": true}
				paths := []string{"/proc/self/status"}
				for _, leaf := range []string{"stat", "status", "cgroup", "limits", "mountinfo"} {
					paths = append(paths, filepath.Join("/proc", strconv.Itoa(pid), leaf))
				}
				groups, groupErr := memcachedUnixReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"), 8192)
				if groupErr == nil && strings.HasPrefix(string(groups), "0::/") && strings.Count(string(groups), "\n") == 1 {
					cg := strings.TrimSuffix(strings.TrimPrefix(string(groups), "0::"), "\n")
					if cg == "/system.slice/docker-"+owned+".scope" || cg == "/docker/"+owned {
						for _, leaf := range []string{"memory.max", "memory.swap.max", "pids.max", "cpu.max"} {
							paths = append(paths, filepath.Join("/sys/fs/cgroup", cg, leaf))
						}
					}
				}
				for _, path := range paths {
					limit := int64(16384)
					if strings.HasSuffix(path, "/mountinfo") {
						limit = 256 << 10
					}
					readActual := func() ([]byte, error) {
						f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
						if err != nil {
							return nil, err
						}
						defer f.Close()
						info, err := f.Stat()
						if err != nil {
							return nil, err
						}
						if !info.Mode().IsRegular() {
							return nil, fmt.Errorf("diagnostic target is not ordinary")
						}
						raw, err := io.ReadAll(io.LimitReader(f, limit+1))
						if err != nil {
							return nil, err
						}
						if int64(len(raw)) > limit {
							return nil, fmt.Errorf("original diagnostic read bound exceeded")
						}
						return raw, nil
					}
					raw, err := readActual()
					if err != nil {
						diagnostic[path] = map[string]any{"read_error": err.Error()}
					} else {
						diagnostic[path] = map[string]any{"bytes": len(raw), "text": string(raw)}
					}
				}
				file, err := os.OpenFile(filepath.Join(root, "native-kernel-diagnostic.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
				if err != nil {
					t.Fatal("failed native observation cannot be retained")
				}
				err = json.NewEncoder(file).Encode(diagnostic)
				syncErr := file.Sync()
				file.Close()
				if err != nil || syncErr != nil {
					t.Fatal("failed native observation not durable")
				}
				t.Fatal("actual kernel limits/process not verified")
			}
			if _, err = os.Lstat(filepath.Join(dir, "cache.sock")); os.IsNotExist(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if err = memcachedUnixReadyAt(ctx, filepath.Join(dir, "cache.sock"), pid, account); err != nil {
				// A restart may leave the old socket inode visible until the
				// NEW process binds/listens. Only a failed connect (zero protocol
				// bytes) may wait; peer, inode, credential and protocol refusals
				// still fail immediately. Reinspect the full daemon and kernel
				// contract on the next pass, never repeat the restart POST.
				if errors.Is(err, syscall.ECONNREFUSED) {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				details := map[string]any{"pid": pid, "error": err.Error(), "observations_after_refusal_not_reconstructed_original": true}
				for _, path := range []string{filepath.Join("/proc", strconv.Itoa(pid)), dir, filepath.Join(dir, "cache.sock")} {
					info, e := os.Lstat(path)
					if e != nil {
						details[path] = e.Error()
						continue
					}
					s := info.Sys().(*syscall.Stat_t)
					details[path] = map[string]any{"device": uint64(s.Dev), "inode": s.Ino, "mode": uint32(s.Mode), "uid": s.Uid, "gid": s.Gid, "nlink": uint64(s.Nlink)}
				}
				file, e := os.OpenFile(filepath.Join(root, "native-peer-diagnostic.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
				if e != nil {
					t.Fatal("peer failure diagnostic cannot be retained")
				}
				e = json.NewEncoder(file).Encode(details)
				syncErr := file.Sync()
				file.Close()
				if e != nil || syncErr != nil {
					t.Fatal("peer failure diagnostic not durable")
				}
				t.Fatal("real Unix peer/version refused", err)
			}
			return pid
		}
		t.Fatal("bounded private engine readiness expired")
		return 0
	}
	pid := ready()
	events["first_pid"] = pid
	exchange := func(frame, want string) {
		t.Helper()
		c, err := dialMemcachedUnixVerifiedAt(ctx, filepath.Join(dir, "cache.sock"), pid, account)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = io.WriteString(c, frame); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(want))
		if _, err = io.ReadFull(c, reply); err != nil || string(reply) != want || c.bound.Err() != nil {
			t.Fatal("bounded nonce-owned cache exchange differs")
		}
	}
	key := "qa_" + in.ProjectID
	value := "云栈-缓存验收-🙂"
	exchange(fmt.Sprintf("set %s 0 0 %d\r\n%s\r\n", key, len(value), value), "STORED\r\n")
	exchange("get "+key+"\r\n", fmt.Sprintf("VALUE %s 0 %d\r\n%s\r\nEND\r\n", key, len(value), value))
	cas := func() uint64 {
		c, err := dialMemcachedUnixVerifiedAt(ctx, filepath.Join(dir, "cache.sock"), pid, account)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = io.WriteString(c, "gets "+key+"\r\n"); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReaderSize(c, 4096)
		line, err := r.ReadString('\n')
		fields := strings.Fields(line)
		if err != nil || len(line) > 4096 || len(fields) != 5 || fields[0] != "VALUE" || fields[1] != key || fields[2] != "0" || fields[3] != strconv.Itoa(len(value)) {
			t.Fatal("private CAS header")
		}
		v, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil || v == 0 {
			t.Fatal("private CAS identity")
		}
		tail := make([]byte, len(value)+7)
		if _, err = io.ReadFull(r, tail); err != nil || string(tail) != value+"\r\nEND\r\n" {
			t.Fatal("private CAS original bytes")
		}
		return v
	}
	version := cas()
	exchange(fmt.Sprintf("cas %s 0 0 %d %d\r\n%s\r\n", key, len(value), version+1, value), "EXISTS\r\n")
	changed := value + "-new"
	exchange(fmt.Sprintf("cas %s 0 0 %d %d\r\n%s\r\n", key, len(changed), version, changed), "STORED\r\n")
	value = changed
	exchange("get "+key+"\r\n", fmt.Sprintf("VALUE %s 0 %d\r\n%s\r\nEND\r\n", key, len(value), value))
	expiring := key + "_ttl"
	exchange("set "+expiring+" 0 1 1\r\nx\r\n", "STORED\r\n")
	time.Sleep(2100 * time.Millisecond)
	exchange("get "+expiring+"\r\n", "END\r\n")
	memcachedUnixNativeConsoleProtocol(t, ctx, dir, pid, account, in.ProjectID)
	events["real_meta_console_binary_keys_values_flags_TTL_add_CAS_update_and_atomic_CAS_delete"] = true
	events["real_meta_editor_limit_is_explicit_no_native_value_truncation"] = true
	memcachedUnixNativeForeignPeerControl(t, ctx, root, dir, pid, account)
	events["actual_same_UID_foreign_PID_received_zero_protocol_bytes"] = true
	if _, e = dockerRequest(ctx, http.MethodPost, "/containers/"+owned+"/restart?t=10", nil, nil, 16384); e != nil {
		t.Fatal("once-only owned restart", e)
	}
	oldPID := pid
	pid = ready()
	if pid == oldPID {
		t.Fatal("restart did not produce a new real engine process")
	}
	exchange("get "+key+"\r\n", "END\r\n")
	if _, e = dockerRequest(ctx, http.MethodPost, "/containers/"+owned+"/stop?t=10", nil, nil, 16384); e != nil {
		t.Fatal("once-only owned stop", e)
	}
	final, e := read(ctx, "/containers/"+owned+"/json")
	var state struct {
		State struct {
			Running bool
			Pid     int
		}
	}
	if e != nil || json.Unmarshal(final, &state) != nil || state.State.Running || state.State.Pid != 0 {
		t.Fatal("owned native container not actually stopped")
	}
	stopped = true
	for _, field := range []string{"pinned_native_image_no_pull", "network_none_no_TCP_or_UDP_publication", "real_cgroup_limits_no_active_or_bounding_capabilities", "verified_same_connection_UTF8_and_stale_CAS", "actual_TTL_expiration", "restart_cache_loss_is_explicit_not_persistence", "only_new_owned_container_changed"} {
		events[field] = true
	}
	events["restart_pid"] = pid
	complete = true
}

// PID1 runs a real unprivileged foreign listener in a separate private /run
// tmpfs. Its bind is only the NEW owned socket directory. The actual Memcached
// process stays alive; replacement of the pathname must not send it any byte.
func memcachedUnixNativeForeignPeerControl(t *testing.T, ctx context.Context, root, dir string, pid int, account memcachedUnixAccount) {
	t.Helper()
	unit := "panel-qa-mcu-peer24bkvw-" + filepath.Base(root)[len("mcu24bkvg-amd64."):][:16]
	socketPath := filepath.Join(dir, "cache.sock")
	original := filepath.Join(root, "original-engine.sock")
	if _, e := os.Lstat(original); !os.IsNotExist(e) {
		t.Fatal("own original socket destination exists")
	}
	before, e := os.Lstat(socketPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(socketPath, original); e != nil {
		t.Fatal("only owned socket relocation", e)
	}
	restored := false
	defer func() {
		// Only this newly named fixture unit may be stopped on failure. Never
		// signal the genuine daemon or another installed service directly.
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		_ = exec.CommandContext(stop, "/usr/bin/systemctl", "stop", unit+".service").Run()
		done()
		if !restored {
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				if err = os.Rename(original, socketPath); err != nil {
					t.Error("own socket restoration unresolved; retain case")
				}
			} else {
				t.Error("foreign fixture socket retained; do not overwrite an unknown inode")
			}
		}
	}()
	logPath := filepath.Join(root, "foreign-peer.jsonl")
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		f.Close()
		t.Fatal(e)
	}
	f.Close()
	code := `import os,socket,json,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10)
s.bind('/run/cache/cache.sock');os.chmod('/run/cache/cache.sock',0o666);s.listen(1)
i=os.lstat('/run/cache/cache.sock')
print(json.dumps({'ready':True,'pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid(),'device':i.st_dev,'inode':i.st_ino}),flush=True)
received=0;connections=0
try:
 c,_=s.accept();connections=1;c.settimeout(5)
 with c:
  while True:
   b=c.recv(4096)
   if not b:break
   received+=len(b);b=b''
   if received>16384:break
finally:s.close()
print(json.dumps({'complete':True,'connections':connections,'protocol_bytes':received}),flush=True)
sys.exit(0 if connections==1 and received==0 else 1)
`
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--no-block", "--collect", "--unit="+unit, "--property=Type=oneshot", "--property=User=65534", "--property=Group=65534", "--property=SupplementaryGroups=", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=", "--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=TemporaryFileSystem=/run:rw,mode=0755", "--property=BindPaths="+dir+":/run/cache", "--property=MemoryMax=32M", "--property=MemorySwapMax=0", "--property=TasksMax=8", "--property=CPUQuota=25%", "--property=TimeoutStartSec=20", "--property=StandardOutput=append:"+logPath, "--property=StandardError=inherit", "/usr/bin/python3", "-I", "-B", "-c", code)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("new unprivileged foreign listener did not start", err, string(out))
	}
	readLines := func() []string {
		raw, err := os.ReadFile(logPath)
		if err != nil || len(raw) > 8192 {
			t.Fatal("bounded foreign peer result")
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	var ready struct {
		Ready         bool
		PID           int
		UID, GID      uint32
		Device, Inode uint64
	}
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		lines := readLines()
		if lines[0] != "" && json.Unmarshal([]byte(lines[0]), &ready) == nil && ready.Ready {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready.Ready || ready.PID < 2 || ready.PID == pid || ready.UID != account.UID || ready.GID != account.GID {
		t.Fatal("foreign process did not preserve same UID/GID with distinct PID")
	}
	if e = memcachedUnixNativeConsoleForeignRequest(ctx, socketPath, pid, account); e == nil || !strings.Contains(e.Error(), "actual peer credentials") {
		t.Fatal("foreign process was not refused at actual SO_PEERCRED boundary", e)
	}
	var done struct {
		Complete    bool `json:"complete"`
		Connections int  `json:"connections"`
		Bytes       int  `json:"protocol_bytes"`
	}
	until = time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		lines := readLines()
		if len(lines) == 2 && json.Unmarshal([]byte(lines[1]), &done) == nil && done.Complete {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !done.Complete || done.Connections != 1 || done.Bytes != 0 {
		t.Fatal("foreign listener did not prove one connection and zero protocol bytes")
	}
	current, e := os.Lstat(socketPath)
	if e != nil {
		t.Fatal(e)
	}
	s := current.Sys().(*syscall.Stat_t)
	if uint64(s.Dev) != ready.Device || s.Ino != ready.Inode || s.Uid != ready.UID || s.Gid != ready.GID || current.Mode()&os.ModeSocket == 0 || s.Nlink != 1 {
		t.Fatal("foreign cleanup inode differs; retain exact socket")
	}
	if e = os.Remove(socketPath); e != nil {
		t.Fatal(e)
	}
	old, e := os.Lstat(original)
	if e != nil || !os.SameFile(before, old) {
		t.Fatal("own original listener inode changed")
	}
	if e = os.Rename(original, socketPath); e != nil {
		t.Fatal(e)
	}
	restored = true
	if e = memcachedUnixReadyAt(ctx, socketPath, pid, account); e != nil {
		t.Fatal("genuine engine peer did not recover after its original inode was restored", e)
	}
}
