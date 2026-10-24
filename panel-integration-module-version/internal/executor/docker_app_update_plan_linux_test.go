//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func memcachedInspectionFixture(t *testing.T) (composeMetadata, map[string]any, func(string, any) error) {
	t.Helper()
	id := strings.Repeat("a", 32)
	m := composeMetadata{ID: id, Name: "memcached-test", Engine: "panel_" + id[:12], TemplateID: "memcached-cache", HostPort: 21212, Services: 1, CreatedAt: "2026-10-15T00:00:00Z"}
	ports := func() map[string]any {
		return map[string]any{"11211/tcp": []any{map[string]any{"HostIp": "127.0.0.1", "HostPort": "21212"}}}
	}
	env := []string{"PATH=/usr/bin:/bin", "FIXTURE_PRIVATE=do-not-reflect"}
	v := map[string]any{"Id": strings.Repeat("b", 64), "Image": "sha256:" + strings.Repeat("c", 64),
		"Config":          map[string]any{"Image": "memcached:1.6.45-alpine", "User": "memcache", "WorkingDir": "", "Cmd": []string{"memcached", "-m", "128", "-I", "4m"}, "Entrypoint": []string{"docker-entrypoint.sh"}, "Env": env, "Labels": map[string]any{"com.docker.compose.project": m.Engine, "com.docker.compose.service": "memcached", "com.docker.compose.oneoff": "False"}, "Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", core.MemcachedHealthCommand}, "Interval": int64(10 * time.Second), "Timeout": int64(3 * time.Second), "StartPeriod": 0, "Retries": 12}},
		"State":           map[string]any{"Running": true, "Health": map[string]any{"Status": "healthy", "Log": []any{map[string]any{"End": "changing-observation-only"}}}},
		"HostConfig":      map[string]any{"Privileged": false, "ReadonlyRootfs": false, "IpcMode": "private", "NetworkMode": m.Engine + "_default", "PortBindings": ports(), "RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0}},
		"NetworkSettings": map[string]any{"Ports": ports(), "Networks": map[string]any{m.Engine + "_default": map[string]any{"NetworkID": "static-network-identity"}}}, "Mounts": []any{},
	}
	read := func(id string, out any) error {
		if id != "sha256:"+strings.Repeat("c", 64) {
			return errors.New("unknown image")
		}
		raw, _ := json.Marshal(map[string]any{"Id": id, "Config": map[string]any{"Env": env, "User": "memcache", "Entrypoint": []string{"docker-entrypoint.sh"}, "WorkingDir": ""}})
		return json.Unmarshal(raw, out)
	}
	return m, v, read
}

func TestMemcachedUpdateRuntimeUsesActualOpaqueIdentityWithoutExposingPrivateSettings(t *testing.T) {
	m, v, read := memcachedInspectionFixture(t)
	raw, _ := json.Marshal(v)
	p, hash, err := memcachedUpdateRuntime(raw, m, read)
	if err != nil || p.ID != strings.Repeat("b", 64) || len(hash) != 64 || strings.Contains(hash, "do-not-reflect") {
		t.Fatal("closed runtime fixture rejected", err)
	}
	v["State"].(map[string]any)["Health"].(map[string]any)["Log"] = []string{"new health observation"}
	raw, _ = json.Marshal(v)
	_, same, err := memcachedUpdateRuntime(raw, m, read)
	if err != nil || same != hash {
		t.Fatal("observation-only health log changed stable identity", err)
	}
	v["HostConfig"].(map[string]any)["OomScoreAdj"] = 17
	raw, _ = json.Marshal(v)
	_, changed, err := memcachedUpdateRuntime(raw, m, read)
	if err != nil || changed == hash {
		t.Fatal("an opaque static Docker setting escaped the precondition", err)
	}
}

func TestMemcachedUpdateRuntimeRejectsLiveDriftBeforeAnyImageOrConfigurationMutation(t *testing.T) {
	for _, scenario := range []string{"missing-config", "missing-running", "stopped", "missing-health", "unhealthy", "wrong-project", "wrong-service", "oneoff", "root-user", "command", "entrypoint", "env", "privileged", "missing-privileged", "readonly-change", "host-pid", "host-ipc", "host-network", "host-userns", "host-uts", "capability", "security-option", "bind", "device", "sysctl", "mount", "extra-network", "public-port", "different-port", "extra-port", "restart", "health-command", "health-timeout", "health-retries", "bad-image", "image-inspection-failure"} {
		t.Run(scenario, func(t *testing.T) {
			m, v, read := memcachedInspectionFixture(t)
			c := v["Config"].(map[string]any)
			s := v["State"].(map[string]any)
			h := v["HostConfig"].(map[string]any)
			n := v["NetworkSettings"].(map[string]any)
			switch scenario {
			case "missing-config":
				delete(v, "Config")
			case "missing-running":
				delete(s, "Running")
			case "stopped":
				s["Running"] = false
			case "missing-health":
				delete(s, "Health")
			case "unhealthy":
				s["Health"].(map[string]any)["Status"] = "unhealthy"
			case "wrong-project":
				c["Labels"].(map[string]any)["com.docker.compose.project"] = "foreign"
			case "wrong-service":
				c["Labels"].(map[string]any)["com.docker.compose.service"] = "database"
			case "oneoff":
				c["Labels"].(map[string]any)["com.docker.compose.oneoff"] = "True"
			case "root-user":
				c["User"] = "root"
			case "command":
				c["Cmd"] = []string{"memcached", "-m", "256"}
			case "entrypoint":
				c["Entrypoint"] = []string{"sh"}
			case "env":
				c["Env"] = []string{"PRIVATE=do-not-reflect"}
			case "privileged":
				h["Privileged"] = true
			case "missing-privileged":
				delete(h, "Privileged")
			case "readonly-change":
				h["ReadonlyRootfs"] = true
			case "host-pid":
				h["PidMode"] = "host"
			case "host-ipc":
				h["IpcMode"] = "host"
			case "host-network":
				h["NetworkMode"] = "host"
			case "host-userns":
				h["UsernsMode"] = "host"
			case "host-uts":
				h["UTSMode"] = "host"
			case "capability":
				h["CapAdd"] = []string{"SYS_ADMIN"}
			case "security-option":
				h["SecurityOpt"] = []string{"seccomp=unconfined"}
			case "bind":
				h["Binds"] = []string{"/:/host"}
			case "device":
				h["Devices"] = []any{map[string]any{"PathOnHost": "/dev/sda"}}
			case "sysctl":
				h["Sysctls"] = map[string]any{"kernel.foo": "1"}
			case "mount":
				v["Mounts"] = []any{map[string]any{"Type": "volume"}}
			case "extra-network":
				n["Networks"].(map[string]any)["foreign"] = map[string]any{}
			case "public-port":
				h["PortBindings"].(map[string]any)["11211/tcp"].([]any)[0].(map[string]any)["HostIp"] = "0.0.0.0"
			case "different-port":
				n["Ports"].(map[string]any)["11211/tcp"].([]any)[0].(map[string]any)["HostPort"] = "21213"
			case "extra-port":
				n["Ports"].(map[string]any)["11211/udp"] = []any{}
			case "restart":
				h["RestartPolicy"].(map[string]any)["Name"] = "always"
			case "health-command":
				c["Healthcheck"].(map[string]any)["Test"] = []string{"CMD", "true"}
			case "health-timeout":
				c["Healthcheck"].(map[string]any)["Timeout"] = 0
			case "health-retries":
				c["Healthcheck"].(map[string]any)["Retries"] = 1
			case "bad-image":
				v["Image"] = "memcached:latest"
			case "image-inspection-failure":
				read = func(string, any) error { return errors.New("private do-not-reflect error") }
			}
			raw, _ := json.Marshal(v)
			_, hash, err := memcachedUpdateRuntime(raw, m, read)
			if err == nil || hash != "" || strings.Contains(err.Error(), "do-not-reflect") {
				t.Fatal("live drift admitted or private details reflected", scenario, err)
			}
		})
	}
}

func TestMemcachedUpdateMetadataIsExactClosedExistingProjectIdentity(t *testing.T) {
	m, _, _ := memcachedInspectionFixture(t)
	raw, _ := json.Marshal(m)
	if _, err := decodeComposeUpdateMetadata(raw, m.ID); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{"unknown": strings.Replace(string(raw), "{", "{\"unknown\":true,", 1), "duplicate": strings.Replace(string(raw), "{", "{\"id\":\""+m.ID+"\",", 1), "escaped-duplicate": strings.Replace(string(raw), "{", "{\"\\u0069d\":\""+m.ID+"\",", 1), "alias": strings.Replace(string(raw), "\"id\"", "\"ID\"", 1), "missing": strings.Replace(string(raw), "\"services\":1,", "", 1), "two-services": strings.Replace(string(raw), "\"services\":1", "\"services\":2", 1), "other-template": strings.Replace(string(raw), "memcached-cache", "redis-cache", 1), "different-project": strings.Replace(string(raw), m.ID, strings.Repeat("d", 32), 1), "bad-time": strings.Replace(string(raw), m.CreatedAt, "not-a-time", 1), "trailing": string(raw) + " {}", "array": "[]", "null": "null"} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeComposeUpdateMetadata([]byte(changed), m.ID); err == nil {
				t.Fatal("ambiguous metadata admitted")
			}
		})
	}
}

func TestMemcachedUpdatePlanRejectsMovedOldImageReferenceWithoutChangingOriginalProject(t *testing.T) {
	const legacy = "services:\n  memcached:\n    image: memcached:1.6.45-alpine\n    restart: unless-stopped\n    command: [\"memcached\", \"-m\", \"128\", \"-I\", \"4m\"]\n    ports:\n      - \"127.0.0.1:21212:11211\"\n    healthcheck:\n      test: [\"CMD-SHELL\", \"printf 'version\\r\\n' | nc -w 2 127.0.0.1 11211 | grep -q '^VERSION'\"]\n      interval: 10s\n      timeout: 3s\n      retries: 12\n"
	if core.Hash(legacy) != "297589552b027e123ab1c309c89fa9a53e37ca0446c509ca344171563e4abb6d" {
		t.Fatal("fixture does not match independently observed original template")
	}
	for _, scenario := range []string{"matching", "already-pinned", "moved-tag", "missing-tag", "empty-tag", "malformed-tag", "null-tag-id", "duplicate-tag-id", "case-tag-id", "tag-not-image-id", "cancel-after-tag"} {
		t.Run(scenario, func(t *testing.T) {
			base, id := memcachedPlanFileFixture(t)
			metadata, container, readImage := memcachedInspectionFixture(t)
			if metadata.ID != id {
				t.Fatal("fixture project identity")
			}
			compose := []byte(legacy)
			image := "memcached:1.6.45-alpine"
			if scenario == "already-pinned" {
				compose = []byte(strings.ReplaceAll(legacy, image, appcatalog.MemcachedDigestImage))
				image = appcatalog.MemcachedDigestImage
				container["Config"].(map[string]any)["Image"] = image
			}
			originalMetadata, _ := json.Marshal(metadata)
			for name, raw := range map[string][]byte{"metadata.json": originalMetadata, "compose.yaml": compose} {
				if err := os.WriteFile(filepath.Join(base, id, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			read := func(_ context.Context, path string, out any) error {
				calls++
				switch {
				case strings.HasPrefix(path, "/containers/json?"):
					return json.Unmarshal([]byte("[{\"Id\":\""+container["Id"].(string)+"\"}]"), out)
				case path == "/containers/"+container["Id"].(string)+"/json":
					raw, _ := json.Marshal(container)
					return json.Unmarshal(raw, out)
				case path == "/images/"+url.PathEscape(container["Image"].(string))+"/json":
					return readImage(container["Image"].(string), out)
				case path == "/images/"+url.PathEscape(image)+"/json":
					raw := "{\"Id\":\"" + container["Image"].(string) + "\"}"
					switch scenario {
					case "moved-tag":
						raw = "{\"Id\":\"sha256:" + strings.Repeat("d", 64) + "\"}"
					case "missing-tag":
						return errors.New("private-do-not-reflect 404")
					case "empty-tag":
						return nil
					case "malformed-tag":
						raw = "{}"
					case "null-tag-id":
						raw = "{\"Id\":null}"
					case "duplicate-tag-id":
						raw = strings.Replace(raw, "{", "{\"Id\":\"other\",", 1)
					case "case-tag-id":
						raw = strings.Replace(raw, "\"Id\"", "\"ID\"", 1)
					case "tag-not-image-id":
						raw = "{\"Id\":\"" + image + "\"}"
					case "cancel-after-tag":
						cancel()
					}
					return json.Unmarshal([]byte(raw), out)
				default:
					t.Fatal("unexpected Docker read", path)
					return errors.New("unexpected read")
				}
			}
			plan, err := memcachedAppUpdatePlanAt(ctx, base, id, read)
			accepted := scenario == "matching" || scenario == "already-pinned"
			if calls != 4 || accepted != (err == nil) || !accepted && plan != (core.MemcachedUpdatePlan{}) || err != nil && strings.Contains(err.Error(), "private-do-not-reflect") {
				t.Fatal("moved/unknown old reference admitted or private data leaked", calls, plan, err)
			}
			if accepted && (plan.RuntimeImageID != container["Image"] || plan.AlreadyPinned != (scenario == "already-pinned")) {
				t.Fatal("opaque current image or pinned identity changed", plan)
			}
			for name, expected := range map[string][]byte{"metadata.json": originalMetadata, "compose.yaml": compose} {
				actual, err := os.ReadFile(filepath.Join(base, id, name))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("readonly plan rewrote original project", name, err)
				}
			}
		})
	}
}
