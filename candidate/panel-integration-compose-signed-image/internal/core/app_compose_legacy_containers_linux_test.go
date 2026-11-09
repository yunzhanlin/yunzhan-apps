//go:build linux

package core

import (
	"context"
	"encoding/base64"
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
)

// Explicit isolated real-image qualification. This does not install an app
// through the signed panel store and must never be reported as that acceptance.
// Never pull images, change existing Compose projects, or delete test volumes.
func TestIsolatedLegacyPHPActualContainers(t *testing.T) {
	scope := os.Getenv("PANEL_QA_LEGACY_PHP_CONTAINERS")
	if scope == "" {
		t.Skip("explicit private AMD64 actual-container scope required")
	}
	pattern := regexp.MustCompile(`^/var/lib/panel-executor/legacy-php-containers24bipb-amd64\.([a-f0-9]{32})$`)
	match := pattern.FindStringSubmatch(scope)
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" || match == nil {
		t.Fatal("unqualified legacy container scope")
	}
	for path := scope; ; path = filepath.Dir(path) {
		s, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		owner, ok := s.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || path == scope && s.Mode().Perm() != 0700 {
			t.Fatal("actual-container scope has an untrusted ancestor")
		}
		if path == "/" {
			break
		}
	}
	state, err := exec.Command("/usr/bin/systemctl", "is-active", "docker.service").Output()
	if err != nil || strings.TrimSpace(string(state)) != "active" {
		t.Fatal("must not activate an absent Docker daemon", err)
	}
	config := filepath.Join(scope, "docker-client")
	if err := os.Mkdir(config, 0700); err != nil {
		t.Fatal(err)
	}
	docker := func(timeout time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/docker", args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DOCKER_HOST=unix:///var/run/docker.sock", "DOCKER_CONFIG=" + config}
		out, err := cmd.CombinedOutput()
		if len(out) > 128<<10 {
			return nil, fmt.Errorf("owned Docker observation exceeded 128 KiB")
		}
		return out, err
	}
	ids := make([]string, 0, len(LegacyPHPImages))
	for id := range LegacyPHPImages {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) != 12 {
		t.Fatal("real legacy image inventory changed")
	}
	// A new explicit52-only fixture can finish its historical SAPI check without
	// replacing the original failed whole-matrix receipt or retesting old jobs.
	if selection := os.Getenv("PANEL_QA_LEGACY_PHP_CONTAINER_SELECTION"); selection != "" {
		if selection != "php-legacy-52" {
			t.Fatal("unsupported isolated selection")
		}
		ids = []string{selection}
	}
	expectedVersions := map[string]string{"52": "5.2.17", "53": "5.3.29", "54": "5.4.45", "55": "5.5.38", "56": "5.6.40", "70": "7.0.33", "71": "7.1.33", "72": "7.2.34", "73": "7.3.33", "74": "7.4.33", "80": "8.0.27", "81": "8.1.15"}
	containerID := regexp.MustCompile(`^[a-f0-9]{64}$`)
	passed := 0
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			minor := strings.TrimPrefix(id, "php-legacy-")
			project := "qa_php24bipb_" + minor + "_" + match[1][:16]
			dir := filepath.Join(scope, id)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, image := range []string{LegacyPHPImages[id], legacyNginxImage} {
				out, err := docker(10*time.Second, "image", "inspect", image, "--format", `{{.Os}}:{{.Architecture}}:{{json .RepoDigests}}`)
				digest := strings.Split(image, "@")[1]
				if err != nil || !strings.HasPrefix(string(out), "linux:amd64:") || !strings.Contains(string(out), digest) {
					t.Fatal("fixed image not already verified in cache; no download attempted", image, err)
				}
			}
			for _, resource := range []string{"container", "network", "volume"} {
				args := []string{resource, "ls", "-q", "--filter", "label=com.docker.compose.project=" + project}
				if resource == "container" {
					args = []string{"container", "ls", "-a", "-q", "--filter", "label=com.docker.compose.project=" + project}
				}
				out, err := docker(10*time.Second, args...)
				if err != nil || len(strings.TrimSpace(string(out))) != 0 {
					t.Fatal("refuse existing resources for supposedly new owned project", resource, err)
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			compose, err := dockerTemplate(id, port)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "compose.yaml")
			if err := os.WriteFile(file, []byte(compose), 0600); err != nil {
				t.Fatal(err)
			}
			composeArgs := []string{"compose", "--project-name", project, "--project-directory", dir, "--file", file}
			run := func(timeout time.Duration, args ...string) ([]byte, error) {
				return docker(timeout, append(append([]string{}, composeArgs...), args...)...)
			}
			// Remove only containers/networks belonging to this exact new project.
			// Named volumes remain available for inspecting actual retained bytes.
			t.Cleanup(func() {
				out, err := run(10*time.Second, "ps", "--all", "--quiet")
				if err != nil {
					t.Error("own cleanup inventory unknown; no deletion", err)
					return
				}
				members := strings.Fields(string(out))
				if len(members) > 2 {
					t.Error("own cleanup inventory exceeded expected two members; no deletion")
					return
				}
				for _, cid := range members {
					if !containerID.MatchString(cid) {
						t.Error("unknown own cleanup container identity; no deletion")
						return
					}
					out, err := docker(10*time.Second, "inspect", "--format", `{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}`, cid)
					if err != nil || strings.TrimSpace(string(out)) != project+"|"+dir+"|"+file {
						t.Error("own cleanup label/file ownership mismatch; no deletion", err)
						return
					}
				}
				out, err = run(30*time.Second, "down", "--timeout", "10")
				if e := os.WriteFile(filepath.Join(dir, "cleanup.log"), out, 0600); e != nil {
					t.Error(e)
				}
				if err != nil {
					t.Error("own cleanup incomplete; preserve exact original project for inspection", err)
				}
			})
			out, err := run(210*time.Second, "up", "--detach", "--pull", "never", "--no-build", "--wait", "--wait-timeout", "180")
			if e := os.WriteFile(filepath.Join(dir, "start.log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			if err != nil {
				t.Fatal("actual unchanged Compose template did not become healthy; private original start log retained", err)
			}
			php, err := run(10*time.Second, "ps", "--quiet", "php")
			cid := strings.TrimSpace(string(php))
			if err != nil || !containerID.MatchString(cid) {
				t.Fatal("own actual PHP container identity unknown", err)
			}
			marker := "legacy-" + minor + "-" + match[1]
			files := map[string]string{
				"qa.php":                  "<?php header('Content-Type: text/plain'); echo '" + marker + "'; ?>",
				"readme.txt":              marker,
				".env.php":                "<?php file_put_contents('/var/www/html/hidden-executed', 'bad'); echo 'bad'; ?>",
				".git/private.php":        "<?php file_put_contents('/var/www/html/hidden-executed', 'bad'); echo 'bad'; ?>",
				"dir/.private/secret.php": "<?php file_put_contents('/var/www/html/hidden-executed', 'bad'); echo 'bad'; ?>",
			}
			program := ""
			for name, data := range files {
				parent := filepath.Dir("/var/www/html/" + name)
				program += "if(!is_dir('" + parent + "'))mkdir('" + parent + "',0755,true);file_put_contents('/var/www/html/" + name + "',base64_decode('" + base64.StdEncoding.EncodeToString([]byte(data)) + "'));"
			}
			out, err = docker(15*time.Second, "exec", "--user", "1000:1000", cid, "php", "-r", program)
			if err != nil || len(out) != 0 {
				t.Fatal("actual unprivileged deployment into owned named volume failed", err, string(out))
			}
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			defer client.CloseIdleConnections()
			get := func(path string, status int) string {
				t.Helper()
				response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
				if err != nil {
					t.Fatal("actual private container HTTP failed", path, err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
				response.Body.Close()
				if err != nil || len(body) > 4096 || response.StatusCode != status {
					t.Fatal("actual private container HTTP differs", path, response.StatusCode, status, err)
				}
				return string(body)
			}
			var probe struct {
				Version string `json:"version"`
				SAPI    string `json:"sapi"`
			}
			expectedSAPI := "fpm-fcgi"
			if id == "php-legacy-52" {
				expectedSAPI = "cgi-fcgi"
			}
			// PHP5.2 predates the in-tree FPM SAPI. Its exact pinned patched
			// FPM image reports cgi-fcgi; do not accept CLI or this alias elsewhere.
			// https://github.com/devilbox/docker-php-fpm-5.2
			if err := json.Unmarshal([]byte(get("/", 200)), &probe); err != nil || probe.Version != expectedVersions[minor] || probe.SAPI != expectedSAPI {
				t.Fatal("real PHP/FPM identity differs from published compatibility version", probe, err)
			}
			for _, path := range []string{"/qa.php", "/readme.txt"} {
				if get(path, 200) != marker {
					t.Fatal("actual deployed file bytes not served", path)
				}
			}
			for _, path := range []string{"/.env.php", "/.git/private.php", "/%2egit/private.php", "/dir/.private/secret.php"} {
				get(path, 403)
			}
			get("/missing.php", 404)
			out, err = docker(10*time.Second, "exec", "--user", "1000:1000", cid, "php", "-r", "exit(file_exists('/var/www/html/hidden-executed')?1:0);")
			if err != nil || len(out) != 0 {
				t.Fatal("hidden PHP actually executed despite denial", err)
			}
			out, err = run(40*time.Second, "restart", "--timeout", "10")
			if err != nil {
				t.Fatal("owned actual container restart failed", err)
			}
			if e := os.WriteFile(filepath.Join(dir, "restart.log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			ready := false
			for n := 0; n < 100; n++ {
				response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/.__cloudstack_health")
				if err == nil {
					io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
					response.Body.Close()
					if response.StatusCode == 200 {
						ready = true
						break
					}
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !ready || get("/qa.php", 200) != marker {
				t.Fatal("actual named-volume deployment not preserved across own restart")
			}
			passed++
			t.Logf("LEGACY_PHP_REAL_CONTAINER id=%s version=%s sapi=%s image=%s compose_sha256=%s actual_deploy_hidden_denial_restart=true signed_store_install_acceptance=false retained_volume=%s_site-data", id, probe.Version, probe.SAPI, LegacyPHPImages[id], Hash(compose), project)
		})
	}
	if passed != len(ids) {
		t.Errorf("real image matrix incomplete: %d/%d", passed, len(ids))
	}
	t.Logf("LEGACY_PHP_REAL_MATRIX passed=%d expected=%d original_projects_not_modified=true named_volumes_retained=true signed_store_install_acceptance=false", passed, len(ids))
}
