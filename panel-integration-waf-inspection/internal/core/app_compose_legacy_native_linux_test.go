//go:build linux

package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Actual isolated Nginx routing with an EXPLICIT synthetic FastCGI responder.
// This proves regex order and non-dispatch of hidden PHP requests, NOT real
// PHP/image installation, container privileges or complete legacy-PHP support.
func TestIsolatedLegacyPHPHiddenRoutingNativeTraffic(t *testing.T) {
	scope := os.Getenv("PANEL_QA_LEGACY_PHP_TRAFFIC")
	if scope == "" {
		t.Skip("explicit owned isolated native Nginx traffic scope required")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/legacy-php-traffic24bioa-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(scope) {
		t.Fatal("unqualified isolated legacy Nginx scope")
	}
	for path := scope; ; path = filepath.Dir(path) {
		s, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		owner, ok := s.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || path == scope && s.Mode().Perm() != 0700 {
			t.Fatal("native scope has an untrusted ancestor")
		}
		if path == "/" {
			break
		}
	}
	raw, err := exec.Command("/usr/bin/systemctl", "show", "nginx.service", "--property=MainPID", "--value").Output()
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || perr != nil || pid < 2 {
		t.Fatal("installed Nginx process cannot be bound", err)
	}
	nginx := "/proc/" + strconv.Itoa(pid) + "/exe"
	www := filepath.Join(scope, "site")
	for _, name := range []string{"public.php", "readme.txt", ".env", ".env.php", ".git/config.php", "dir/.private/settings.php"} {
		file := filepath.Join(www, name)
		if os.MkdirAll(filepath.Dir(file), 0700) != nil || os.WriteFile(file, []byte("private fixture bytes"), 0600) != nil {
			t.Fatal("could not initialize own private routing fixture")
		}
	}
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	var calls atomic.Int32
	go func() {
		_ = fcgi.Serve(upstream, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "explicit synthetic FastCGI responder")
		}))
	}()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	requests := 0
	config := legacyPHPRenderedNginx(t, "php-legacy-52")
	for _, phase := range []string{"old", "fixed"} {
		source := config
		if phase == "old" {
			source = strings.Replace(source, "  location ~ /\\. { deny all; }\n", "", 1)
			source = strings.Replace(source, "\n }\n}\n", "\n  location ~ /\\. { deny all; }\n }\n}\n", 1)
			if Hash(source) != "541d3277fdd8b61431fa02a21f2421a0e5cd2ed68d8e796873f9aeead4758e8c" {
				t.Fatal("original bootstrap config bytes changed")
			}
		}
		dir := filepath.Join(scope, phase)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		if strings.Count(source, "listen 8080;") != 1 || strings.Count(source, "root /var/www/html;") != 1 || strings.Count(source, "fastcgi_pass php:9000;") != 2 {
			t.Fatal("unexpected original routing membership")
		}
		// Only fixed filesystem/log/temp prefixes, the listen/upstream and
		// process mode are relocated for this OWNED routing-only fixture.
		source = strings.ReplaceAll(source, "/tmp/", dir+"/")
		source = strings.ReplaceAll(source, "root /var/www/html;", "root "+www+";")
		source = strings.ReplaceAll(source, "listen 8080;", fmt.Sprintf("listen 127.0.0.1:%d;", port))
		source = strings.ReplaceAll(source, "fastcgi_pass php:9000;", "fastcgi_pass "+upstream.Addr().String()+";")
		source = strings.ReplaceAll(source, "error_log /dev/stderr warn;", "error_log "+dir+"/error.log warn;")
		source = strings.ReplaceAll(source, "access_log /dev/stdout;", "access_log off;")
		source = "daemon off;\nmaster_process off;\n" + source
		file := filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		out, err := exec.CommandContext(ctx, nginx, "-t", "-p", dir+"/", "-c", file, "-e", dir+"/startup.log").CombinedOutput()
		if err != nil {
			cancel()
			t.Fatal("isolated actual Nginx config rejected", err, string(out))
		}
		output, err := os.OpenFile(filepath.Join(dir, "process.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, nginx, "-p", dir+"/", "-c", file, "-e", dir+"/startup.log")
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, output, time.Second
		if err := cmd.Start(); err != nil {
			cancel()
			output.Close()
			t.Fatal(err)
		}
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()
		done := false
		stop := func() {
			if done {
				return
			}
			done = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-wait:
			case <-time.After(2 * time.Second):
				cancel()
				<-wait
			}
			cancel()
			output.Close()
		}
		t.Cleanup(stop)
		ready := false
		for n := 0; n < 100; n++ {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 30*time.Millisecond)
			if err == nil {
				c.Close()
				ready = true
				break
			}
			select {
			case err := <-wait:
				done = true
				cancel()
				output.Close()
				t.Fatal("own isolated Nginx exited before listener", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			stop()
			t.Fatal("own isolated Nginx did not become ready")
		}
		cases := []struct {
			path   string
			status int
		}{{"/public.php", 200}, {"/readme.txt", 200}, {"/.env", 403}, {"/.env.php", 403}, {"/.git/config.php", 403}}
		if phase == "old" {
			cases[3].status, cases[4].status = 200, 200
		} else {
			cases = append(cases, struct {
				path   string
				status int
			}{"/%2egit/config.php", 403}, struct {
				path   string
				status int
			}{"/dir/.private/settings.php", 403}, struct {
				path   string
				status int
			}{"/.__cloudstack_health", 200}, struct {
				path   string
				status int
			}{"/missing.php", 404})
		}
		before := calls.Load()
		for _, item := range cases {
			res, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + item.path)
			if err != nil {
				t.Fatal(phase, item.path, err)
			}
			body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
			res.Body.Close()
			if err != nil || res.StatusCode != item.status || len(body) >= 4096 {
				t.Fatal("actual routing result differs", phase, item.path, res.StatusCode, item.status, err)
			}
			requests++
		}
		want := int32(2)
		if phase == "old" {
			want = 3
		}
		if calls.Load()-before != want {
			t.Fatal("hidden routing dispatched a different number of FastCGI requests", phase, calls.Load()-before, want)
		}
		stop()
	}
	if requests != 14 {
		t.Fatal("native routing matrix incomplete", requests)
	}
	t.Logf("LEGACY_PHP_NATIVE_ROUTING requests=%d old_hidden_dispatch_reproduced=true fixed_hidden_requests_denied_before_fastcgi=true actual_php_container_acceptance=false", requests)
}
