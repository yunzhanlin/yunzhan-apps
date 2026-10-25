//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func memcachedUnixRuntimeFixture(t *testing.T) (composeMetadata, map[string]any, map[string]any, memcachedUnixDockerRead) {
	t.Helper()
	m, v, _ := memcachedInspectionFixture(t)
	m.HostPort = 0
	c, h, s, n := v["Config"].(map[string]any), v["HostConfig"].(map[string]any), v["State"].(map[string]any), v["NetworkSettings"].(map[string]any)
	c["Image"], c["User"], c["Entrypoint"], c["Cmd"] = appcatalog.MemcachedDigestImage, "11211:11211", []string{"memcached"}, []string{"-s", "/run/memcached/cache.sock", "-a", "666", "-m", "128", "-I", "4m", "-U", "0", "-c", "256", "-t", "2"}
	c["Healthcheck"].(map[string]any)["Test"] = []string{"CMD-SHELL", core.MemcachedUnixLiveness}
	c["Labels"].(map[string]any)["io.yunzhan.memcached.site-id"] = ""
	s["Pid"] = 42
	h["ReadonlyRootfs"], h["CapDrop"], h["SecurityOpt"] = true, []string{"ALL"}, []string{"no-new-privileges:true"}
	h["Memory"], h["MemorySwap"], h["NanoCpus"], h["PidsLimit"] = 192<<20, 192<<20, 1_000_000_000, 32
	h["Ulimits"] = []any{map[string]any{"Name": "nofile", "Soft": 1024, "Hard": 1024}}
	h["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]any{"max-size": "10m", "max-file": "3"}}
	dir, _ := core.MemcachedUnixDirectory(m.ID, "")
	h["NetworkMode"], h["PortBindings"] = "none", map[string]any{}
	h["Mounts"] = []any{map[string]any{"Type": "bind", "Source": dir, "Target": "/run/memcached", "ReadOnly": false, "BindOptions": map[string]any{"Propagation": "rprivate", "CreateMountpoint": false}}}
	v["Mounts"] = []any{map[string]any{"Type": "bind", "Source": dir, "Destination": "/run/memcached", "RW": true, "Propagation": "rprivate"}}
	n["Ports"], n["Networks"] = map[string]any{"11211/tcp": nil}, map[string]any{"none": map[string]any{"IPAddress": "", "GlobalIPv6Address": "", "Gateway": "", "IPv6Gateway": ""}}
	_, digest, _ := strings.Cut(appcatalog.MemcachedDigestImage, "@")
	image := map[string]any{"Id": v["Image"], "Os": "linux", "Architecture": runtime.GOARCH, "RepoDigests": []string{"memcached@" + digest}, "Config": map[string]any{"User": "memcache", "Env": c["Env"], "WorkingDir": ""}}
	read := func(ctx context.Context, p string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if p != "/images/"+url.PathEscape(v["Image"].(string))+"/json" {
			return nil, errors.New("unexpected daemon read")
		}
		return json.Marshal(image)
	}
	return m, v, image, read
}

func TestMemcachedUnixRuntimeAcceptsOnlyUnpublishedNetworkAndBoundMount(t *testing.T) {
	m, v, _, read := memcachedUnixRuntimeFixture(t)
	for _, health := range []string{"starting", "healthy"} {
		v["State"].(map[string]any)["Health"].(map[string]any)["Status"] = health
		raw, _ := json.Marshal(v)
		id, pid, status, e := memcachedUnixRuntime(context.Background(), raw, m, "", memcachedUnixAccount{11211, 11211}, read)
		if e != nil || id != v["Id"] || pid != 42 || status != health {
			t.Fatal("exact actual contract refused", e)
		}
	}
}

func TestMemcachedUnixStoppedStateKeepsOriginalRawPIDAndSecurityContract(t *testing.T) {
	for _, kind := range []string{"stopped", "live", "nonzero-pid", "unknown-health", "unsafe-memory", "public-port"} {
		t.Run(kind, func(t *testing.T) {
			m, v, _, read := memcachedUnixRuntimeFixture(t)
			state := v["State"].(map[string]any)
			state["Running"], state["Pid"] = false, 0
			state["Health"].(map[string]any)["Status"] = "unhealthy"
			switch kind {
			case "live":
				state["Running"] = true
			case "nonzero-pid":
				state["Pid"] = 42
			case "unknown-health":
				state["Health"].(map[string]any)["Status"] = "unknown"
			case "unsafe-memory":
				v["HostConfig"].(map[string]any)["Memory"] = 0
			case "public-port":
				m.HostPort = 11211
			}
			raw, _ := json.Marshal(v)
			id, err := memcachedUnixStoppedRuntime(context.Background(), raw, m, "", memcachedUnixAccount{11211, 11211}, read)
			if (err == nil) != (kind == "stopped") || kind == "stopped" && id != v["Id"] {
				t.Fatal("stopped raw state/security misclassified", kind, err)
			}
			if _, _, _, err := memcachedUnixRuntime(context.Background(), raw, m, "", memcachedUnixAccount{11211, 11211}, read); err == nil {
				t.Fatal("stopped/current raw evidence became live readiness")
			}
		})
	}
}

func TestMemcachedUnixRuntimeRejectsDaemonResourceMountImageAndNetworkDrift(t *testing.T) {
	for _, kind := range []string{"profile-port", "root", "foreign-user", "command", "entrypoint", "tag", "site-label", "missing-site-label", "image-id", "image-arch", "image-env", "image-digest", "stopped", "unhealthy", "pid", "privileged", "writable-root", "cap", "nnp", "host-pid", "host-ipc", "host-network", "bridge-network", "userns", "memory-missing", "memory-unlimited", "swap", "cpu", "pids", "ulimit", "logs", "publish", "binding", "extra-network", "address", "mount-source", "mount-target", "mount-create", "mount-propagation", "mount-extra", "live-source", "live-target", "live-readonly", "live-propagation", "device", "duplicate-key", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			m, v, image, read := memcachedUnixRuntimeFixture(t)
			c, h, s, n := v["Config"].(map[string]any), v["HostConfig"].(map[string]any), v["State"].(map[string]any), v["NetworkSettings"].(map[string]any)
			desired := h["Mounts"].([]any)[0].(map[string]any)
			live := v["Mounts"].([]any)[0].(map[string]any)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "profile-port":
				m.HostPort = 21211
			case "root":
				c["User"] = "0:0"
			case "foreign-user":
				c["User"] = "11212:11211"
			case "command":
				c["Cmd"] = []string{"-l", "0.0.0.0"}
			case "entrypoint":
				c["Entrypoint"] = []string{"sh"}
			case "tag":
				c["Image"] = "memcached:1.6.45-alpine"
			case "site-label":
				c["Labels"].(map[string]any)["io.yunzhan.memcached.site-id"] = core.ID()
			case "missing-site-label":
				delete(c["Labels"].(map[string]any), "io.yunzhan.memcached.site-id")
			case "image-id":
				image["Id"] = "sha256:" + strings.Repeat("e", 64)
			case "image-arch":
				image["Architecture"] = "other"
			case "image-env":
				image["Config"].(map[string]any)["Env"] = []string{"UNBOUND=1"}
			case "image-digest":
				image["RepoDigests"] = []string{}
			case "stopped":
				s["Running"] = false
			case "unhealthy":
				s["Health"].(map[string]any)["Status"] = "unhealthy"
			case "pid":
				s["Pid"] = 0
			case "privileged":
				h["Privileged"] = true
			case "writable-root":
				h["ReadonlyRootfs"] = false
			case "cap":
				h["CapAdd"] = []string{"SYS_ADMIN"}
			case "nnp":
				h["SecurityOpt"] = []string{}
			case "host-pid":
				h["PidMode"] = "host"
			case "host-ipc":
				h["IpcMode"] = "host"
			case "host-network":
				h["NetworkMode"] = "host"
			case "bridge-network":
				h["NetworkMode"] = m.Engine + "_default"
			case "userns":
				h["UsernsMode"] = "host"
			case "memory-missing":
				delete(h, "Memory")
			case "memory-unlimited":
				h["Memory"] = 0
			case "swap":
				h["MemorySwap"] = 384 << 20
			case "cpu":
				h["NanoCpus"] = 0
			case "pids":
				h["PidsLimit"] = -1
			case "ulimit":
				h["Ulimits"] = []any{}
			case "logs":
				h["LogConfig"] = map[string]any{"Type": "json-file"}
			case "publish":
				h["PortBindings"] = map[string]any{"11211/tcp": []any{map[string]any{"HostIp": "127.0.0.1", "HostPort": "21211"}}}
			case "binding":
				n["Ports"] = map[string]any{"11211/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "21211"}}}
			case "extra-network":
				n["Networks"].(map[string]any)["bridge"] = map[string]any{}
			case "address":
				n["Networks"].(map[string]any)["none"].(map[string]any)["IPAddress"] = "172.18.0.2"
			case "mount-source":
				desired["Source"] = "/run/docker.sock"
			case "mount-target":
				desired["Target"] = "/host"
			case "mount-create":
				desired["BindOptions"].(map[string]any)["CreateMountpoint"] = true
			case "mount-propagation":
				desired["BindOptions"].(map[string]any)["Propagation"] = "shared"
			case "mount-extra":
				h["Mounts"] = append(h["Mounts"].([]any), desired)
			case "live-source":
				live["Source"] = "/run/docker.sock"
			case "live-target":
				live["Destination"] = "/host"
			case "live-readonly":
				live["RW"] = false
			case "live-propagation":
				live["Propagation"] = "shared"
			case "device":
				h["Devices"] = []any{map[string]any{}}
			case "cancelled":
				cancel()
			}
			raw, _ := json.Marshal(v)
			if kind == "duplicate-key" {
				raw = append([]byte(`{"Id":"duplicate",`), raw[1:]...)
			}
			id, pid, health, e := memcachedUnixRuntime(ctx, raw, m, "", memcachedUnixAccount{11211, 11211}, read)
			if e == nil || id != "" || pid != 0 || health != "" {
				t.Fatal("unsafe daemon contract accepted", kind)
			}
		})
	}
}
