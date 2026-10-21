//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

// Explicit native compiler+traffic qualification only. It does not create a
// production install/job/receipt, publish a runtime, or change an active gateway.
// The real existing compiler supervisor must accept this dedicated unit; no
// unit/pidfd/capability/collection guard is replaced by a fixture or override.
func TestNginxSecuritySourceNativeBuildAndTraffic(t *testing.T) {
	scope := os.Getenv("PANEL_QA_NGINX_SECURITY_NATIVE")
	if scope == "" {
		t.Skip("explicit private dedicated native compiler unit required")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/nginx-security-native24bish-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(scope) || !strings.Contains(scope, "-"+runtime.GOARCH+".") {
		t.Fatal("unqualified native source scope")
	}
	for p := scope; ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			t.Fatal(e)
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || p == scope && s.Mode().Perm() != 0700 {
			t.Fatal("untrusted native source ancestry")
		}
		if p == "/" {
			break
		}
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("actual compiler supervisor confinement differs", identity)
	}
	r, ok := runtimecatalog.Find("nginx-1.30.6")
	if !ok || r.Family != "nginx" || r.SHA256 != "3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8" {
		t.Fatal("fixed independently authenticated source missing")
	}
	archive := filepath.Join(scope, "nginx-1.30.6.tar.gz")
	s, e := os.Lstat(archive)
	if e != nil || !runtimeBuildPrivateFile(s) || s.Size() < 1 || s.Size() > 8<<20 {
		t.Fatal("private source archive identity")
	}
	raw, e := os.ReadFile(archive)
	if e != nil || core.Hash(string(raw)) != r.SHA256 {
		t.Fatal("original source digest mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	lock, e := acquireRuntimeNativeBuildSerialization(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	id := core.ID()
	base, e := prepareRuntimeBuildDirectory(id)
	if e != nil {
		t.Fatal(e)
	}
	work, e := prepareRuntimeBuildWork(base)
	if e != nil {
		t.Fatal(e)
	}
	if e = extractSource(archive, work); e != nil {
		t.Fatal("production safe archive extractor rejected source", e)
	}
	builder, e := user.Lookup("panel-build")
	if e != nil || builder.Uid == "0" {
		t.Fatal("actual non-root builder missing", e)
	}
	uid, e := strconv.Atoi(builder.Uid)
	if e != nil {
		t.Fatal(e)
	}
	gid, e := strconv.Atoi(builder.Gid)
	if e != nil {
		t.Fatal(e)
	}
	if e = filepath.WalkDir(work, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(work, "nginx-1.30.6")
	prefix := filepath.Join(work, "private-prefix")
	binary := filepath.Join(prefix, "sbin/nginx")
	log := filepath.Join(base, "build.log")
	flags := []string{"--prefix=" + prefix, "--sbin-path=" + binary, "--conf-path=" + filepath.Join(prefix, "conf/nginx.conf"), "--pid-path=" + filepath.Join(prefix, "run/nginx.pid"), "--error-log-path=" + filepath.Join(prefix, "logs/error.log"), "--http-log-path=" + filepath.Join(prefix, "logs/access.log"), "--user=www-data", "--group=www-data", "--with-compat", "--with-http_ssl_module", "--with-http_v2_module", "--with-http_stub_status_module", "--with-http_realip_module", "--with-http_gzip_static_module", "--with-threads", "--with-stream", "--with-stream_ssl_module"}
	for _, step := range []struct {
		program string
		args    []string
	}{{filepath.Join(source, "configure"), flags}, {"/usr/bin/make", []string{"-j" + strconv.Itoa(runtimeBuildJobs())}}, {"/usr/bin/make", []string{"install"}}} {
		if e = buildCommand(ctx, source, log, step.program, step.args...); e != nil {
			t.Fatal("actual supervised nonprivileged source build failed", e)
		}
	}
	if e = buildCommand(ctx, work, log, binary, "-v"); e != nil {
		t.Fatal("compiled version probe", e)
	}
	logBytes, e := os.ReadFile(log)
	if e != nil || !strings.Contains(string(logBytes), "nginx version: nginx/1.30.6") {
		t.Fatal("actual built binary version not verified")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	if port < 1024 || port > 65535 {
		t.Fatal("private HTTP port")
	}
	marker := "native-nginx-1.30.6-" + id
	config := fmt.Sprintf("pid %s;\nerror_log %s;\nevents { worker_connections 32; }\nhttp { access_log off; server { listen 127.0.0.1:%d; server_name localhost; location / { default_type text/plain; return 200 '%s'; } } }\n", filepath.Join(work, "http.pid"), filepath.Join(work, "http-error.log"), port, marker)
	conf := filepath.Join(work, "native-http.conf")
	// The confined supervisor deliberately lacks CAP_DAC_OVERRIDE. The work
	// directory belongs to panel-build: fixtures must use that same real
	// unprivileged writer, not widen the supervisor or repair its permissions.
	writeFixture := "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644); data=sys.argv[2].encode(); assert os.write(f,data)==len(data); os.fsync(f); os.close(f)"
	if e = buildCommand(ctx, work, log, "/usr/bin/python3", "-c", writeFixture, conf, config); e != nil {
		t.Fatal(e)
	}
	if e = buildCommand(ctx, work, log, binary, "-t", "-p", prefix, "-c", conf); e != nil {
		t.Fatal("actual private configuration check", e)
	}
	invalid := filepath.Join(work, "invalid-http.conf")
	if e = buildCommand(ctx, work, log, "/usr/bin/python3", "-c", writeFixture, invalid, "not_an_nginx_directive;\n"); e != nil {
		t.Fatal(e)
	}
	if e = buildCommand(ctx, work, log, binary, "-t", "-p", prefix, "-c", invalid); e == nil {
		t.Fatal("actual bad configuration was accepted")
	}
	serveCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	collected := false
	go func() {
		done <- buildCommand(serveCtx, work, log, binary, "-p", prefix, "-c", conf, "-g", "daemon off;")
	}()
	defer func() {
		stop()
		if collected {
			return
		}
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Error("native server collection not observed; preserve exact unit")
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/probe")
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			response.Body.Close()
			if readErr == nil && response.StatusCode == 200 && string(body) == marker {
				ready = true
				break
			}
		}
		select {
		case err := <-done:
			collected = true
			t.Fatal("native server exited before HTTP readiness", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("actual private HTTP response missing")
	}
	stop()
	select {
	case err := <-done:
		collected = true
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatal("expected supervised foreground cancellation was not proved", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("actual runtime compiler failed to collect its own HTTP workers")
	}
	artifact, e := os.Lstat(binary)
	if e != nil || !artifact.Mode().IsRegular() || artifact.Size() < 1 || artifact.Size() > 64<<20 || artifact.Sys().(*syscall.Stat_t).Uid != uint32(uid) || artifact.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("compiled artifact identity or capacity differs")
	}
	file, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("NGINX_SECURITY_NATIVE version=1.30.6 arch=%s source_sha256=%s binary_sha256=%s nonroot_compiler=true private_config_test=true invalid_config_refused=true actual_loopback_HTTP=true own_children_collected=true runtime_installed=false gateway_changed=false retained_build=%s", runtime.GOARCH, r.SHA256, core.Hash(string(file)), id)
}
