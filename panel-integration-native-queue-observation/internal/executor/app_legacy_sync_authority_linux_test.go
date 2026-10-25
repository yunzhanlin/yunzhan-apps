//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// These are closed daemon/FS models, not real Docker/store installation.
func legacySyncRuntimeFixture() (composeMetadata, map[string]any, map[string]any) {
	m := composeMetadata{ID: strings.Repeat("a", 32), Name: "legacy-qa", Engine: "panel_" + strings.Repeat("a", 12), TemplateID: "php-legacy-52", HostPort: 23000, Services: 2, CreatedAt: "2026-10-21T00:00:00Z"}
	labels := func(service string) map[string]string {
		return map[string]string{"com.docker.compose.project": m.Engine, "com.docker.compose.service": service, "com.docker.compose.oneoff": "False"}
	}
	id, image, network, volume := strings.Repeat("a", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("c", 64), m.Engine+"_site-data"
	actual := map[string]any{
		"Id": id, "Image": image,
		"Config":          map[string]any{"Image": core.LegacyPHPImages[m.TemplateID], "User": "", "WorkingDir": "/shared/httpd", "Cmd": []string{core.LegacyPHPBootstrap}, "Entrypoint": []string{"/bin/sh", "-c"}, "Env": []string{"PATH=/usr/bin:/bin", "PHP_INI_SCAN_DIR=/tmp/cloudstack-ini"}, "Labels": labels("php"), "Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", "fixed probe"}}},
		"State":           map[string]any{"Running": true, "Health": map[string]any{"Status": "healthy"}},
		"HostConfig":      map[string]any{"Privileged": false, "ReadonlyRootfs": true, "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "", "NetworkMode": m.Engine + "_default", "SecurityOpt": []string{"no-new-privileges:true"}, "Tmpfs": map[string]string{"/tmp": "", "/var/run": ""}, "RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0}, "Binds": []string{volume + ":/var/www/html:rw"}, "Memory": 256 << 20, "PidsLimit": 96},
		"NetworkSettings": map[string]any{"Ports": map[string]any{"9000/tcp": nil}, "Networks": map[string]any{m.Engine + "_default": map[string]any{"NetworkID": network}}},
		"Mounts":          []any{map[string]any{"Type": "volume", "Name": volume, "Source": "/var/lib/docker/volumes/" + volume + "/_data", "Destination": "/var/www/html", "Driver": "local", "Mode": "rw", "RW": true, "Propagation": ""}},
	}
	objects := map[string]any{
		"containers":                  []any{map[string]any{"Id": id, "Labels": labels("php")}, map[string]any{"Id": strings.Repeat("b", 64), "Labels": labels("web")}},
		"/containers/" + id + "/json": actual,
		"/images/" + core.LegacyPHPImages[m.TemplateID] + "/json": map[string]any{"Id": image, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{"User": "", "WorkingDir": "/shared/httpd", "Env": []string{"PATH=/usr/bin:/bin"}}},
		"/volumes/" + volume:   map[string]any{"Name": volume, "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/" + volume + "/_data", "Scope": "local", "Options": nil, "Labels": map[string]string{"com.docker.compose.project": m.Engine, "com.docker.compose.volume": "site-data"}},
		"/networks/" + network: map[string]any{"Id": network, "Name": m.Engine + "_default", "Driver": "bridge", "Scope": "local", "Internal": true, "Labels": map[string]string{"com.docker.compose.project": m.Engine, "com.docker.compose.network": "default"}},
	}
	return m, actual, objects
}

func legacySyncFixtureReader(objects map[string]any) composeUpdateDockerRead {
	return func(ctx context.Context, path string, out any) error {
		if strings.HasPrefix(path, "/containers/json?all=1&filters=") {
			path = "containers"
		}
		path, _ = url.PathUnescape(path)
		v, ok := objects[path]
		if !ok || ctx.Err() != nil {
			return errors.New("fixture missing")
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, out)
	}
}

func TestLegacySyncRuntimeBindsActualImageVolumeNetworkAndExactStaticConfiguration(t *testing.T) {
	cases := []string{"normal", "unknown-static-field", "wrong-image-reference", "wrong-opaque-image", "wrong-architecture", "wrong-OS", "unknown-user", "changed-environment", "duplicate-environment", "changed-command", "changed-entrypoint", "privileged", "writable-root", "host-pid", "host-ipc", "host-network", "public-port", "network-not-internal", "extra-network", "wrong-network-id", "network-owner", "bind-mount", "foreign-volume", "readonly-volume", "volume-driver-bind", "volume-owner", "extra-mount", "different-volume-source", "missing-no-new-privileges", "added-capability", "changed-memory", "changed-pids", "tmpfs-options", "unhealthy", "not-running", "foreign-project", "oneoff", "extra-container", "short-container-id", "duplicate-service", "missing-privileged", "missing-config-image", "alias-config-image", "duplicate-json-key", "cancelled-context"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			m, a, o := legacySyncRuntimeFixture()
			c := a["Config"].(map[string]any)
			h := a["HostConfig"].(map[string]any)
			n := a["NetworkSettings"].(map[string]any)
			mount := a["Mounts"].([]any)[0].(map[string]any)
			volume := o["/volumes/"+m.Engine+"_site-data"].(map[string]any)
			network := o["/networks/"+strings.Repeat("c", 64)].(map[string]any)
			image := o["/images/"+core.LegacyPHPImages[m.TemplateID]+"/json"].(map[string]any)
			switch name {
			case "unknown-static-field":
				h["FutureDaemonOption"] = map[string]any{"value": "preserved in fingerprint"}
			case "wrong-image-reference":
				c["Image"] = "devilbox/php-fpm:latest"
			case "wrong-opaque-image":
				image["Id"] = "sha256:" + strings.Repeat("e", 64)
			case "wrong-architecture":
				image["Architecture"] = "arm64"
			case "wrong-OS":
				image["Os"] = "windows"
			case "unknown-user":
				c["User"] = "foreign"
			case "changed-environment":
				c["Env"] = []string{"PATH=/usr/bin:/bin", "PHP_INI_SCAN_DIR=/unknown"}
			case "duplicate-environment":
				c["Env"] = []string{"PATH=/usr/bin:/bin", "PATH=/usr/bin:/bin"}
			case "changed-command":
				c["Cmd"] = []string{"sleep 999"}
			case "changed-entrypoint":
				c["Entrypoint"] = []string{"/bin/bash", "-c"}
			case "privileged":
				h["Privileged"] = true
			case "writable-root":
				h["ReadonlyRootfs"] = false
			case "host-pid":
				h["PidMode"] = "host"
			case "host-ipc":
				h["IpcMode"] = "host"
			case "host-network":
				h["NetworkMode"] = "host"
			case "public-port":
				h["PortBindings"] = map[string]any{"9000/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "9000"}}}
			case "network-not-internal":
				network["Internal"] = false
			case "extra-network":
				n["Networks"].(map[string]any)["extra"] = map[string]any{"NetworkID": strings.Repeat("c", 64)}
			case "wrong-network-id":
				network["Id"] = strings.Repeat("b", 64)
			case "network-owner":
				network["Labels"] = map[string]string{"com.docker.compose.project": "foreign"}
			case "bind-mount":
				mount["Type"] = "bind"
			case "foreign-volume":
				mount["Name"] = "foreign"
			case "readonly-volume":
				mount["RW"] = false
			case "volume-driver-bind":
				volume["Options"] = map[string]string{"device": "/etc", "type": "none", "o": "bind"}
			case "volume-owner":
				volume["Labels"] = map[string]string{"com.docker.compose.project": "foreign"}
			case "extra-mount":
				a["Mounts"] = append(a["Mounts"].([]any), mount)
			case "different-volume-source":
				mount["Source"] = "/etc"
			case "missing-no-new-privileges":
				h["SecurityOpt"] = []string{}
			case "added-capability":
				h["CapAdd"] = []string{"SYS_ADMIN"}
			case "changed-memory":
				h["Memory"] = 0
			case "changed-pids":
				h["PidsLimit"] = -1
			case "tmpfs-options":
				h["Tmpfs"] = map[string]string{"/tmp": "rw,size=8g", "/var/run": ""}
			case "unhealthy":
				a["State"].(map[string]any)["Health"] = map[string]any{"Status": "unhealthy"}
			case "not-running":
				a["State"].(map[string]any)["Running"] = false
			case "foreign-project":
				c["Labels"].(map[string]string)["com.docker.compose.project"] = "foreign"
			case "oneoff":
				c["Labels"].(map[string]string)["com.docker.compose.oneoff"] = "True"
			case "extra-container":
				o["containers"] = append(o["containers"].([]any), map[string]any{"Id": strings.Repeat("f", 64)})
			case "short-container-id":
				o["containers"].([]any)[0].(map[string]any)["Id"] = strings.Repeat("a", 12)
			case "duplicate-service":
				o["containers"].([]any)[1].(map[string]any)["Labels"] = o["containers"].([]any)[0].(map[string]any)["Labels"]
			case "missing-privileged":
				delete(h, "Privileged")
			case "missing-config-image":
				delete(c, "Image")
			case "alias-config-image":
				c["image"] = c["Image"]
				delete(c, "Image")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancelled-context" {
				cancel()
			}
			read := legacySyncFixtureReader(o)
			if name == "duplicate-json-key" {
				original := read
				read = func(ctx context.Context, p string, out any) error {
					if p == "/containers/"+strings.Repeat("a", 64)+"/json" {
						v := out.(*json.RawMessage)
						*v = json.RawMessage(`{"Id":"first","Id":"second"}`)
						return nil
					}
					return original(ctx, p, out)
				}
			}
			id, digest, err := legacySyncRuntime(ctx, m, read)
			if name == "normal" || name == "unknown-static-field" {
				if err != nil || id != strings.Repeat("a", 64) || len(digest) != 64 {
					t.Fatal("exact bounded fixture rejected", err)
				}
			} else if err == nil || id != "" || digest != "" {
				t.Fatal("drifted actual authority accepted")
			}
		})
	}
}

func legacySyncSourceFixture(t *testing.T) (string, string) {
	t.Helper()
	base, id := memcachedPlanFileFixture(t)
	m, _, _ := legacySyncRuntimeFixture()
	m.ID = id
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	source, err := core.LegacyPHPTemplate(m.TemplateID, m.HostPort)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(base, id, "metadata.json"), raw, 0600) != nil || os.WriteFile(filepath.Join(base, id, "compose.yaml"), []byte(source), 0600) != nil {
		t.Fatal("fixture write")
	}
	return base, id
}

func TestLegacySyncTrustedSourceCannotBeSubstitutedOrRepaired(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		if a, err := openLegacySyncAuthority("/not-accessed", strings.Repeat("a", 32)); err == nil || a != nil {
			t.Fatal("foreign architecture opened legacy target")
		}
		return
	}
	for _, name := range []string{"normal", "shared-project", "shared-file", "source-hardlink", "source-fifo", "source-symlink", "changed-template", "metadata-duplicate", "metadata-alias", "metadata-extra", "replaced-source", "detached-parent", "unknown-runtime-static-change"} {
		t.Run(name, func(t *testing.T) {
			base, id := legacySyncSourceFixture(t)
			project := filepath.Join(base, id)
			source := filepath.Join(project, "compose.yaml")
			metadata := filepath.Join(project, "metadata.json")
			switch name {
			case "shared-project":
				if os.Chmod(project, 0755) != nil {
					t.Fatal("chmod")
				}
			case "shared-file":
				if os.Chmod(source, 0644) != nil {
					t.Fatal("chmod")
				}
			case "source-hardlink":
				if os.Link(source, source+".other") != nil {
					t.Fatal("link")
				}
			case "source-fifo":
				if os.Remove(source) != nil || unix.Mkfifo(source, 0600) != nil {
					t.Fatal("FIFO")
				}
			case "source-symlink":
				if os.Rename(source, source+".original") != nil || os.Symlink("compose.yaml.original", source) != nil {
					t.Fatal("symlink")
				}
			case "changed-template":
				if os.WriteFile(source, []byte("services: {}\n"), 0600) != nil {
					t.Fatal("replace")
				}
			case "metadata-duplicate", "metadata-alias", "metadata-extra":
				raw, err := os.ReadFile(metadata)
				if err != nil {
					t.Fatal(err)
				}
				prefix := `{"id":"x",`
				if name == "metadata-alias" {
					prefix = `{"ID":"x",`
				}
				if name == "metadata-extra" {
					prefix = `{"unknown":"x",`
				}
				if os.WriteFile(metadata, append([]byte(prefix), raw[1:]...), 0600) != nil {
					t.Fatal("metadata")
				}
			}
			a, err := openLegacySyncAuthority(base, id)
			allowed := name == "normal" || name == "replaced-source" || name == "detached-parent" || name == "unknown-runtime-static-change"
			if !allowed {
				if err == nil {
					a.directory.Close()
					t.Fatal("unsafe original source accepted")
				}
				if name == "shared-file" {
					s, _ := os.Lstat(source)
					if s.Mode().Perm() != 0644 {
						t.Fatal("repaired original file")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer a.directory.Close()
			if !a.current() {
				t.Fatal("fresh named source missing")
			}
			if name == "replaced-source" {
				raw, _ := os.ReadFile(source)
				if os.Rename(source, source+".old") != nil || os.WriteFile(source, raw, 0600) != nil {
					t.Fatal("replacement")
				}
				if a.current() {
					t.Fatal("same bytes on different inode adopted")
				}
			}
			if name == "detached-parent" {
				if os.Rename(base, base+".old") != nil || os.Mkdir(base, 0700) != nil {
					t.Fatal("detach")
				}
				if a.current() {
					t.Fatal("detached ancestor adopted")
				}
			}
			if name == "unknown-runtime-static-change" {
				_, actual, objects := legacySyncRuntimeFixture()
				h := actual["HostConfig"].(map[string]any)
				h["FutureDaemonOption"] = "original"
				reader := legacySyncFixtureReader(objects)
				if a.check(context.Background(), reader) != nil {
					t.Fatal("original not bound")
				}
				h["FutureDaemonOption"] = "changed"
				if a.check(context.Background(), reader) == nil {
					t.Fatal("uninterpreted static runtime field change ignored")
				}
			}
		})
	}
}

func TestLegacySyncWriteReceiptNeverPromotesUnknownOrWrongResult(t *testing.T) {
	expected := strings.Repeat("a", 64)
	for _, raw := range []string{"", `null`, `{}`, `{"SHA256":"` + expected + `"}`, `{"sha256":"` + strings.Repeat("b", 64) + `"}`, `{"sha256":"` + expected + `","extra":true}`, `{"sha256":"` + expected + `","sha256":"` + expected + `"}`, `{"sha256":"` + expected + `"} {}`, strings.Repeat(" ", 257)} {
		if legacySyncWriteReceipt([]byte(raw), expected) == nil {
			t.Fatal("unverified reply was treated as a completed copy")
		}
	}
	if err := legacySyncWriteReceipt([]byte(`{"sha256":"`+expected+`"}`), expected); err != nil {
		t.Fatal("exact actual receipt rejected", err)
	}
}
