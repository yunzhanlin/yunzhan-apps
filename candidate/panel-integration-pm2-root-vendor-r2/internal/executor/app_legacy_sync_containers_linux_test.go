//go:build linux

package executor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Opt-in real cached-image qualification of native authority + fixed PHP copy
// programs. NOT a signed-store installation, full module HTTP workflow, or EOL
// security support. Only its exact new containers/networks may be removed;
// all named volumes, source/config and raw failure evidence are retained.
func TestIsolatedLegacySyncActualContainers(t *testing.T) {
	scope := os.Getenv("PANEL_QA_LEGACY_SYNC_CONTAINERS")
	if scope == "" {
		t.Skip("explicit owned native legacy-sync container scope required")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" || !regexp.MustCompile(`^/var/lib/panel-executor/legacy-sync-containers24biqu-amd64\.[a-f0-9]{32}$`).MatchString(scope) {
		t.Fatal("unqualified actual legacy-sync scope")
	}
	for p := scope; ; p = filepath.Dir(p) {
		s, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		owner, ok := s.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || p == scope && s.Mode().Perm() != 0700 {
			t.Fatal("untrusted native scope")
		}
		if p == "/" {
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	bound, unlock, err := composeLock(ctx)
	if err != nil {
		t.Fatal("existing native mutation/lifecycle lease unavailable", err)
	}
	defer unlock()
	config := filepath.Join(scope, "docker-client")
	projects := filepath.Join(scope, "compose")
	if os.Mkdir(config, 0700) != nil || os.Mkdir(projects, 0700) != nil {
		t.Fatal("own private roots")
	}
	docker := func(limit time.Duration, args ...string) ([]byte, error) {
		cctx, stop := context.WithTimeout(bound, limit)
		defer stop()
		cmd := exec.CommandContext(cctx, "/usr/bin/docker", append([]string{"--config", config}, args...)...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DOCKER_HOST=unix:///var/run/docker.sock"}
		return cmd.CombinedOutput()
	}
	before, err := docker(10*time.Second, "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		t.Fatal("existing Docker inventory", err)
	}
	defer func() {
		after, e := docker(10*time.Second, "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
		if e != nil {
			t.Error("final Docker inventory unavailable")
			return
		}
		oldIDs := strings.Fields(string(before))
		newIDs := strings.Fields(string(after))
		sort.Strings(oldIDs)
		sort.Strings(newIDs)
		if strings.Join(oldIDs, "\n") != strings.Join(newIDs, "\n") {
			t.Error("original container set changed or an owned test cleanup is incomplete; inspect retained case")
		}
	}()
	ids := make([]string, 0, len(core.LegacyPHPImages))
	for id := range core.LegacyPHPImages {
		if os.Getenv("PANEL_QA_LEGACY_SYNC_ONLY52") != "1" || id == "php-legacy-52" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	passed := 0
	for _, template := range ids {
		t.Run(template, func(t *testing.T) {
			nonce := make([]byte, 16)
			if _, e := rand.Read(nonce); e != nil {
				t.Fatal(e)
			}
			id := hex.EncodeToString(nonce)
			engine := "panel_" + id[:12]
			project := filepath.Join(projects, id)
			if e := os.Mkdir(project, 0700); e != nil {
				t.Fatal(e)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			if port < 1024 || port > 65535 {
				t.Fatal("nonprivileged own port unavailable")
			}
			source, e := core.LegacyPHPTemplate(template, port)
			if e != nil {
				t.Fatal(e)
			}
			// Every image must already be present at its exact reviewed digest. No
			// pull, mutable tag substitution, daemon start or production edit.
			refs := regexp.MustCompile(`(?m)^    image: ([^\s]+)$`).FindAllStringSubmatch(source, -1)
			if len(refs) != 2 {
				t.Fatal("factory image inventory")
			}
			for _, ref := range refs {
				raw, e := docker(10*time.Second, "image", "inspect", ref[1], "--format", "{{.Os}}:{{.Architecture}}")
				if e != nil || strings.TrimSpace(string(raw)) != "linux:amd64" {
					t.Fatal("required pinned cached image unavailable or foreign architecture", ref[1], e)
				}
			}
			m := composeMetadata{ID: id, Name: "legacy-sync-qa", Engine: engine, TemplateID: template, HostPort: port, Services: 2, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
			meta, _ := json.Marshal(m)
			file := filepath.Join(project, "compose.yaml")
			if os.WriteFile(file, []byte(source), 0600) != nil || os.WriteFile(filepath.Join(project, "metadata.json"), meta, 0600) != nil {
				t.Fatal("own factory files")
			}
			compose := func(limit time.Duration, args ...string) ([]byte, error) {
				return docker(limit, append([]string{"compose", "--project-name", engine, "--file", file}, args...)...)
			}
			defer func() {
				raw, e := compose(15*time.Second, "ps", "--all", "--quiet")
				if e != nil {
					t.Error("own container cleanup inventory unavailable")
					return
				}
				for _, cid := range strings.Fields(string(raw)) {
					if len(cid) != 64 || !dockerObjectPattern.MatchString(cid) {
						t.Error("refuse unbound cleanup ID")
						return
					}
					labels, e := docker(10*time.Second, "inspect", "--format", `{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}`, cid)
					if e != nil || strings.TrimSpace(string(labels)) != engine+"|"+project+"|"+file {
						t.Error("refuse cleanup of foreign container")
						return
					}
				}
				out, e := compose(40*time.Second, "down")
				if os.WriteFile(filepath.Join(project, "cleanup.log"), out, 0600) != nil {
					t.Error("cleanup log unavailable")
				}
				if e != nil {
					t.Error("own cleanup incomplete; retain original case", e)
				}
			}()
			out, e := compose(90*time.Second, "up", "--detach", "--pull", "never", "--wait", "--wait-timeout", "80")
			if os.WriteFile(filepath.Join(project, "start.log"), out, 0600) != nil {
				t.Fatal("start log")
			}
			if e != nil {
				t.Fatal("own exact cached project failed", e)
			}
			a, e := openLegacySyncAuthority(projects, id)
			if e != nil {
				t.Fatal("actual owned factory source refused", e)
			}
			defer a.directory.Close()
			if e = a.check(bound, legacySyncDockerRead); e != nil {
				cid, _ := compose(5*time.Second, "ps", "--quiet", "php")
				cidText := strings.TrimSpace(string(cid))
				if len(cidText) == 64 && dockerObjectPattern.MatchString(cidText) {
					raw, _ := docker(10*time.Second, "inspect", cidText)
					if len(raw) < 256<<10 {
						_ = os.WriteFile(filepath.Join(project, "original-own-php-inspect.json"), raw, 0600)
					}
				}
				t.Fatal("actual runtime does not satisfy new native sync authority", e)
			}
			inventory, e := legacyExec(bound, a.container, legacyInventoryPHP, nil)
			if e != nil {
				t.Fatal("actual UID1000 inventory", e)
			}
			var old map[string]moduleFile
			if json.Unmarshal(inventory, &old) != nil {
				t.Fatal("actual inventory format")
			}
			name := "nested/qa.php"
			marker := "legacy-sync-native-" + id
			data := []byte("<?php header('Content-Type: text/plain'); echo '" + marker + "'; ?>")
			payload, _ := json.Marshal(map[string]any{"path": name, "data": base64.StdEncoding.EncodeToString(data), "expected": old[name].SHA, "expected_mode": old[name].Mode, "expected_size": old[name].Size, "mode": 0644, "sha256": core.Hash(string(data))})
			if e = a.check(bound, legacySyncDockerRead); e != nil {
				t.Fatal(e)
			}
			result, e := legacyExec(bound, a.container, legacyWritePHP, payload)
			if e != nil || legacySyncWriteReceipt(result, core.Hash(string(data))) != nil {
				t.Fatal("actual fixed copy/receipt failed", e)
			}
			// The exact old absent-file CAS can never overwrite this new file.
			if _, e = legacyExec(bound, a.container, legacyWritePHP, payload); e == nil {
				t.Fatal("stale absent-file CAS overwrote a completed copy")
			}
			inventory, e = legacyExec(bound, a.container, legacyInventoryPHP, nil)
			var copied map[string]moduleFile
			if e != nil || json.Unmarshal(inventory, &copied) != nil || copied[name].SHA != core.Hash(string(data)) || copied[name].Size != int64(len(data)) || copied[name].Mode != 0644 {
				t.Fatal("actual copied bytes/mode/size differ", e)
			}
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			defer client.CloseIdleConnections()
			response, e := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/" + name)
			if e != nil {
				t.Fatal("actual PHP HTTP", e)
			}
			body, e := io.ReadAll(io.LimitReader(response.Body, 4097))
			response.Body.Close()
			if e != nil || response.StatusCode != 200 || string(body) != marker {
				t.Fatal("actual PHP did not serve copied content", response.StatusCode, e)
			}
			// A live change to ONLY this owned test container is rejected. Restore
			// exactly its original resource bound before checking original identity.
			if _, e = docker(10*time.Second, "update", "--memory", "512m", a.container); e != nil {
				t.Fatal("own resource drift setup", e)
			}
			if e = a.check(bound, legacySyncDockerRead); e == nil {
				t.Fatal("actual changed resource bound accepted")
			}
			if _, e = docker(10*time.Second, "update", "--memory", "256m", a.container); e != nil {
				t.Fatal("own resource restoration", e)
			}
			if e = a.check(bound, legacySyncDockerRead); e != nil {
				t.Fatal("exact restored original identity unavailable", e)
			}
			passed++
			t.Logf("LEGACY_SYNC_REAL id=%s source_sha256=%s fixed_copy_UID1000=true stale_CAS_refused=true actual_HTTP=true actual_resource_drift_refused=true original_identity_restored=true retained_volume=%s_site-data signed_store_acceptance=false", template, core.Hash(source), engine)
		})
	}
	if passed != len(ids) {
		t.Errorf("actual native sync matrix incomplete: %d/%d", passed, len(ids))
	}
	t.Log(fmt.Sprintf("LEGACY_SYNC_MATRIX passed=%d expected=%d original_other_containers_preserved=true own_volumes_retained=true installed_application_acceptance=false", passed, len(ids)))
}
