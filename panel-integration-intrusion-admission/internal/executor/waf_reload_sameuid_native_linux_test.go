//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestWAFSameUIDNativeActualGracefulReload(t *testing.T) {
	if os.Getenv("PANEL_QA_WAF_SAMEUID_NATIVE") != "1" {
		t.Skip("requires exact owned private namespace and genuine producer")
	}
	id := os.Getenv("PANEL_WAF_ENGINE_QA_JOB")
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || strings.TrimSpace(string(host)) != map[string]string{"arm64": "lima-panel-ids24hj-clean-ubuntu24", "amd64": "lima-panel-analytics23t-unit-debian13"}[runtime.GOARCH] {
		t.Fatal("not an authorized owned fixture")
	}
	if err := verifyNginxNativeWorkerCapabilities(); err != nil {
		t.Fatal("exact root EB / NNP boundary required", err)
	}
	var marker struct {
		Format  int    `json:"format"`
		Mount   string `json:"init_mount_namespace"`
		Network string `json:"init_network_namespace"`
		Job     string `json:"job_id"`
	}
	if err := readAnalyticsHTMLPrivateJSON("/etc/panel/.native-waf-http-fixture.json", 2048, &marker); err != nil || marker.Format != 1 || marker.Job != id {
		t.Fatal("private canonical namespace witness", err)
	}
	for name, init := range map[string]string{"mnt": marker.Mount, "net": marker.Network} {
		self, e := os.Readlink("/proc/self/ns/" + name)
		if e != nil || !regexp.MustCompile("^"+name+`:\[[1-9][0-9]{0,19}\]$`).MatchString(init) || self == init {
			t.Fatal("refuse original namespaces")
		}
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("genuine producer verification", err)
	}
	record, err := readWAFBuildRecord(id)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "/run/panel-waf-produced-http24apg"
	if err := ownedRuntimePath(fixture, true); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(fixture, "reload-probe-")
	if err != nil || os.Chmod(base, 0755) != nil {
		t.Fatal("owned reload scratch", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/long" {
			io.WriteString(w, "before-reload\n")
			w.(http.Flusher).Flush()
			select {
			case <-release:
				io.WriteString(w, "after-reload\n")
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, "ordinary\n")
	}))
	t.Cleanup(upstream.Close)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf("user www-data;\ndaemon off;\nmaster_process on;\nworker_processes 2;\npid %s/nginx.pid;\nerror_log %s/nginx-error.log notice;\nevents { worker_connections 32; }\nhttp { access_log off; server { listen %s; add_header X-QA-Worker $pid always; location / { proxy_buffering off; proxy_pass %s; } } }\n", base, base, address, upstream.URL)
	conf := filepath.Join(base, "nginx.conf")
	if err := atomicWrite(conf, []byte(configuration), 0644); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(base, "process.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// The constrained fixture supervisor has ambient EB for its setup work;
	// a normal Nginx service has no such ambient/inherited grants. Clear them
	// before starting the owned master, keeping EB and all worker C0 checks.
	command := exec.Command("/usr/bin/setpriv", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--", record.NginxBinary, "-e", "stderr", "-c", conf)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdout, command.Stderr = log, log
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		log.Close()
	})
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	ready := false
	for attempts := 0; attempts < 100; attempts++ {
		response, err := client.Get("http://" + address + "/")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("actual private Nginx did not serve")
	}
	verifyWAFProducedHTTPWorkers(t, command.Process.Pid, record.NginxBinary, 33)
	generation, err := captureWAFReloadGeneration(ctx, "/proc", record.NginxBinary, command.Process.Pid)
	if err != nil || len(generation.Workers) != 2 {
		t.Fatal("real root EB capture failed", err)
	}
	for _, worker := range generation.Workers {
		if _, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", worker.PID)); !errors.Is(err, os.ErrPermission) {
			t.Fatal("fixture does not reproduce real cross-UID exe denial", err)
		}
		if _, err := wafProcessSockets(ctx, "/proc", worker.PID); !errors.Is(err, os.ErrPermission) {
			t.Fatal("fixture does not reproduce real cross-UID socket denial", err)
		}
	}
	worker := generation.Workers[0]
	wrongStart, wrongParent := worker, worker
	wrongStart.Start++
	wrongParent.Parent++
	for _, invalid := range []struct {
		process   wafReloadProcess
		binary    string
		operation string
	}{
		{wrongStart, record.NginxBinary, "exe"},
		{wrongParent, record.NginxBinary, "sockets"},
		{worker, "/usr/bin/false", "exe"},
		{worker, "/usr/bin/false", "sockets"},
		{worker, record.NginxBinary, "environ"},
	} {
		if _, err := wafSameUIDWorkerRead(ctx, "/proc", invalid.binary, invalid.process, invalid.operation); err == nil {
			t.Fatal("real reader accepted wrong process/program/operation identity")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := wafSameUIDWorkerRead(canceled, "/proc", record.NginxBinary, worker, "sockets"); err == nil {
		t.Fatal("canceled real reader succeeded")
	}
	if drained, err := generation.drained(ctx); err != nil || drained {
		t.Fatal("still-serving listeners were accepted as drained", drained, err)
	}
	response, err := client.Get("http://" + address + "/long")
	if err != nil || response.StatusCode != 200 {
		t.Fatal("actual existing long response", err)
	}
	defer response.Body.Close()
	first := make([]byte, len("before-reload\n"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "before-reload\n" {
		t.Fatal("long response did not begin", err)
	}
	oldPID, err := strconv.Atoi(response.Header.Get("X-QA-Worker"))
	if err != nil {
		t.Fatal("long response worker identity")
	}
	var old wafReloadProcess
	for _, worker := range generation.Workers {
		if worker.PID == oldPID {
			old = worker
		}
	}
	if old.PID == 0 || syscall.Kill(command.Process.Pid, syscall.SIGHUP) != nil {
		t.Fatal("owned reload identity/signal")
	}
	if err := waitWAFReloadGeneration(ctx, generation); err != nil {
		t.Fatal("actual listener-close barrier", err)
	}
	current, err := readWAFReloadProcess("/proc", oldPID)
	if err != nil || current.Start != old.Start || current.Parent != command.Process.Pid || current.State == "Z" || current.State == "X" {
		t.Fatal("listener barrier waited for or killed existing long response", err)
	}
	finish()
	last, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil || string(last) != "after-reload\n" {
		t.Fatal("graceful reload interrupted existing request", err)
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("read-only reload test changed genuine engine", err)
	}
	if err := moduleWrite(filepath.Join(base, "acceptance.json"), map[string]any{"passed": true, "genuine_job_id": id, "root_eb_nnp_no_ptrace": true, "actual_cross_uid_executable_and_socket_permission_denied": true, "stable_pidfd_same_uid_numeric_reader": true, "wrong_start_parent_program_operation_and_cancellation_refused": true, "two_actual_workers_zero_active_privilege": true, "still_listening_workers_refused_before_reload": true, "actual_old_listener_closure_verified": true, "existing_long_request_completed_without_forced_disconnect": true, "source_build_verified_before_after": true, "application_installed": false, "site_activated": false, "browser_accepted": false}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS genuine source Nginx root EB / C0 same-UID numeric reader / stable pidfd / real listener-close barrier / existing long response preserved; no original service signaled")
}
