//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Native source preflight in a coordinator-owned mount and network namespace.
// The command adapter addresses ONLY the private Nginx process; this is not a
// signed panel installation or the production systemd reload API.
func lbActiveNativeGuard(t *testing.T) {
	t.Helper()
	host, err := os.Hostname()
	if err != nil || os.Geteuid() != 0 || (host != "lima-panel-analytics23t-unit-debian13" && host != "lima-panel-ids24hj-clean-ubuntu24") {
		t.Fatal("unknown or privileged native fixture")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v, err := strconv.ParseUint(values[k], 16, 64)
		if err != nil || v != 0x800c5 {
			t.Fatal("native fixture is not the exact CHOWN/DAC_READ_SEARCH/SETUID/SETGID/SYS_PTRACE profile", k)
		}
	}
	if values["NoNewPrivs"] != "1" || os.Getenv("TMPDIR") != "/var/lib/panel-executor" {
		t.Fatal("missing isolated native coordinator")
	}
	// The coordinator overlays this directory; never inherit a live selection.
	if names, err := os.ReadDir("/etc/panel"); err != nil || len(names) != 0 {
		t.Fatal("native fixture inherited live panel configuration", err)
	}
}

func lbActiveNativePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 16; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if p >= 20000 && p <= 60000 {
			return p
		}
	}
	t.Fatal("no bounded private ephemeral port")
	return 0
}

func lbActiveNativeService(stage string, run Command) *Service {
	return New(Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", SecurityDir: filepath.Join(stage, "security"), ConfDir: filepath.Join(stage, "config"), StateDir: filepath.Join(stage, "state"), NginxConf: filepath.Join(stage, "nginx.conf"), NginxBin: "/usr/sbin/nginx", Run: run})
}

func TestLoadBalanceActivePrivateNativeQA(t *testing.T) {
	if os.Getenv("PANEL_LB_ACTIVE_PRIVATE_NATIVE_QA") != "1" {
		t.Skip("explicit isolated native coordinator required")
	}
	lbActiveNativeGuard(t)
	if os.Getenv("PANEL_LB_ACTIVE_KILL_CHILD") != "" {
		lbActiveNativeKillChild(t)
		return
	}
	for _, encrypted := range []bool{false, true} {
		name := "http"
		if encrypted {
			name = "https"
		}
		t.Run(name, func(t *testing.T) { lbActiveNativeScenario(t, encrypted) })
	}
}

func lbActiveNativeScenario(t *testing.T, encrypted bool) {
	stage, err := os.MkdirTemp(os.TempDir(), "load-active-native-")
	if err != nil {
		t.Fatal(err)
	}
	// Retain all files on success AND failure. Cleanup only owned processes.
	proof := map[string]any{"passed": false, "signed_release_acceptance": false, "all_fifty_commercial": false, "private_command_adapter": true, "https_backend": encrypted, "stage": stage}
	defer func() {
		proof["passed"] = !t.Failed()
		if err := moduleWrite(filepath.Join(stage, "proof.json"), proof); err != nil {
			t.Error(err)
		}
		t.Log("native active-routing evidence " + filepath.Join(stage, "proof.json"))
	}()
	for _, dir := range []string{"security", "config", "state"} {
		if err = os.Mkdir(filepath.Join(stage, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	domain := "active-native.example.test"
	var badA, badB atomic.Bool
	certificate, ca := lbTLSCertificate(t, domain, false)
	backendPort := lbActiveNativePort(t)
	start := func(ip, label string, bad *atomic.Bool) *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ready" {
				if bad.Load() {
					w.WriteHeader(503)
				}
				fmt.Fprint(w, "READY")
				return
			}
			if encrypted && (r.TLS == nil || r.TLS.ServerName != domain || r.Host != domain) {
				t.Error("business TLS identity lost")
			}
			// A failed readiness endpoint still serves business. Exclusion must
			// come from the active policy, not passive 503 failover.
			fmt.Fprint(w, label)
		})
		server := httptest.NewUnstartedServer(handler)
		server.Listener.Close()
		server.Listener, err = net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(backendPort)))
		if err != nil {
			t.Fatal(err)
		}
		if encrypted {
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
		} else {
			server.Start()
		}
		t.Cleanup(server.Close)
		return server
	}
	a, b := start("127.0.0.1", "A", &badA), start("127.0.0.2", "B", &badB)
	port, bootstrap := lbActiveNativePort(t), lbActiveNativePort(t)
	config := fmt.Sprintf("user nobody nogroup;\nworker_processes 1;\npid %s;\nerror_log %s notice;\nevents { worker_connections 128; }\nhttp { access_log off; client_body_temp_path %s; proxy_temp_path %s; fastcgi_temp_path %s; uwsgi_temp_path %s; scgi_temp_path %s; server { listen 127.0.0.1:%d; return 200 'private-bootstrap'; } include %s/*.conf; }\n", filepath.Join(stage, "nginx.pid"), filepath.Join(stage, "error.log"), filepath.Join(stage, "client"), filepath.Join(stage, "proxy"), filepath.Join(stage, "fastcgi"), filepath.Join(stage, "uwsgi"), filepath.Join(stage, "scgi"), bootstrap, filepath.Join(stage, "config"))
	if err = atomicWrite(filepath.Join(stage, "nginx.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(filepath.Join(stage, "nginx-process.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	command := exec.Command("/usr/sbin/nginx", "-p", stage+"/", "-c", filepath.Join(stage, "nginx.conf"), "-g", "daemon off;")
	command.Stdout, command.Stderr = output, output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	proof["native_master_initial_pid"] = command.Process.Pid
	done := make(chan error, 1)
	go func(c *exec.Cmd, out chan error) { out <- c.Wait() }(command, done)
	masterAlive := true
	defer func() {
		if !masterAlive {
			return
		}
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("private Nginx did not stop")
		}
	}()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request := func(p int, path string) (int, string, error) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", p, path), nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = domain
		res, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		data, err := io.ReadAll(io.LimitReader(res.Body, 4097))
		return res.StatusCode, string(data), err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body, err := request(bootstrap, "/")
		if err == nil && code == 200 && body == "private-bootstrap" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private Nginx not ready", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var checks, reloads atomic.Int32
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/sbin/nginx" && len(args) == 3 && args[0] == "-t" && args[1] == "-c" && args[2] == filepath.Join(stage, "nginx.conf") {
			checks.Add(1)
			return RunCommand(ctx, name, args...)
		}
		if name == "/usr/bin/systemctl" && strings.Join(args, " ") == "show nginx --property=ActiveState,MainPID" {
			return fmt.Sprintf("ActiveState=active\nMainPID=%d\n", command.Process.Pid), nil
		}
		if name == "/usr/bin/systemctl" && strings.Join(args, " ") == "reload nginx" {
			reloads.Add(1)
			return "", command.Process.Signal(syscall.SIGHUP)
		}
		return "", errors.New("private command adapter rejected unrelated command")
	}
	s := lbActiveNativeService(stage, run)
	lbRoutingInstalled(t, s, "1.7.0") // Fixture identity, not a claimed signed install.
	policy := lbHTTPPolicy()
	policy.Path = "/ready"
	on := true
	policy.AutoTraffic = &on
	if encrypted {
		policy.Scheme = "https"
		policy.CheckPort = backendPort
		policy.CAPEM = ca
	}
	scheme := "http"
	if encrypted {
		scheme = "https"
	}
	in := core.AppModuleInput{Domain: domain, Port: port, Nodes: []core.AppUpstream{{Address: strings.TrimPrefix(a.URL, scheme+"://"), Weight: 1}, {Address: strings.TrimPrefix(b.URL, scheme+"://"), Weight: 3}}, HealthCheck: policy, Confirm: "ENABLE HEALTH ROUTING " + domain}
	if encrypted {
		in.BackendTLS = &core.LoadBalanceBackendTLS{ServerName: domain, CAPEM: ca}
	}
	lbSave(t, s, in)
	in.ExpectedRevision = 1
	results := []map[string]any{}
	get := func(label string, expected int) string {
		code, body, err := request(port, "/business")
		results = append(results, map[string]any{"phase": label, "status": code, "body": body})
		if err != nil || code != expected {
			t.Fatal("native business", label, code, body, err)
		}
		return body
	}
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		counts[get("initial-weighted", 200)]++
	}
	if counts["A"] != 10 || counts["B"] != 30 {
		t.Fatal("native weight routing", counts)
	}
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	unchanged := reloads.Load()
	badA.Store(true)
	lbHTTPCheck(t, s, in)
	if reloads.Load() != unchanged {
		t.Fatal("first failure reloaded")
	}
	lbHTTPCheck(t, s, in)
	v, _, err := s.readLoadBalanceEntry(domain)
	if err != nil || v.Routing.Sequence != 1 || len(v.Routing.Down) != 1 || v.Revision != 1 {
		t.Fatal(v, err)
	}
	for i := 0; i < 12; i++ {
		if get("A-readiness-failed-still-business-ready", 200) != "B" {
			t.Fatal("excluded A received actual traffic")
		}
	}
	unchanged = reloads.Load()
	lbHTTPCheck(t, s, in)
	if reloads.Load() != unchanged {
		t.Fatal("unchanged failed state reloaded")
	}
	badB.Store(true)
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	v, _, err = s.readLoadBalanceEntry(domain)
	if err != nil || len(v.Routing.Down) != 2 || v.Routing.Sequence != 2 {
		t.Fatal(v, err)
	}
	get("all-down-no-fail-open", 502)
	badA.Store(false)
	unchanged = reloads.Load()
	lbHTTPCheck(t, s, in)
	if reloads.Load() != unchanged {
		t.Fatal("first recovery restored")
	}
	get("first-recovery-still-all-down", 502)
	lbHTTPCheck(t, s, in)
	for i := 0; i < 8; i++ {
		if get("A-restored-B-remains-out", 200) != "A" {
			t.Fatal("recovery threshold or exclusions lost")
		}
	}
	badB.Store(false)
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	v, _, err = s.readLoadBalanceEntry(domain)
	if err != nil || len(v.Routing.Down) != 0 || v.Routing.Sequence != 4 || v.Revision != 1 {
		t.Fatal(v, err)
	}
	// A real failed native syntax stage restores config+metadata+health(+CA).
	badA.Store(true)
	lbHTTPCheck(t, s, in)
	old := lbBackendFiles(t, s, domain)
	healthPath := s.loadBalanceHealthPath(domain)
	old[healthPath], err = os.ReadFile(healthPath)
	if err != nil {
		t.Fatal(err)
	}
	faulted := false
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if !faulted && name == "/usr/sbin/nginx" {
			faulted = true
			return "", errors.New("injected native pre-reload validation failure")
		}
		return run(ctx, name, args...)
	}
	if _, err = s.checkLoadBalanceHTTP(context.Background(), in); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatal("native rollback not confirmed", err)
	}
	s.Config.Run = run
	for path, want := range old {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("native rollback lost original set", path, err)
		}
	}
	if _, err = os.Lstat(s.loadBalancePendingPath()); !os.IsNotExist(err) {
		t.Fatal("rollback pending not retired", err)
	}
	get("post-rollback-business", 200)
	// Kill a genuine in-flight client at three boundaries. The last recovery
	// uses the exact production cold pre-start method while Nginx is stopped.
	fresh := lbActiveNativeService(stage, run)
	for _, checkpoint := range []string{"before-validation", "after-reload", "cold"} {
		master, err := readWAFReloadProcess("/proc", command.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		beforeGeneration, err := captureWAFReloadGeneration(context.Background(), "/proc", "/usr/sbin/nginx", master.PID)
		if err != nil {
			t.Fatal(err)
		}
		childInput := lbActiveKillInput{Stage: stage, Input: in, Checkpoint: checkpoint, MasterPID: master.PID, MasterStart: master.Start}
		if err = moduleWrite(filepath.Join(stage, "kill-input.json"), childInput); err != nil {
			t.Fatal(err)
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.v", "-test.run=^TestLoadBalanceActivePrivateNativeQA$", "-test.timeout=25s")
		child.Env = append(os.Environ(), "PANEL_LB_ACTIVE_KILL_CHILD="+stage)
		childLog, err := os.OpenFile(filepath.Join(stage, "kill-child-"+checkpoint+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer childLog.Close()
		child.Stdout, child.Stderr = childLog, childLog
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()
		defer func() {
			if child.ProcessState == nil {
				child.Process.Kill()
				<-childDone
			}
		}()
		deadline = time.Now().Add(8 * time.Second)
		for {
			if _, err = os.Stat(filepath.Join(stage, "kill-"+checkpoint+"-ready")); err == nil {
				break
			}
			select {
			case err := <-childDone:
				t.Fatal("child exited before native transaction checkpoint", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("child did not reach native transaction checkpoint")
			}
			time.Sleep(20 * time.Millisecond)
		}
		pending, err := s.readLoadBalanceTransaction()
		if err != nil || pending.State != "applying" || (encrypted && pending.Format != 4) || (!encrypted && pending.Format != 3) {
			t.Fatal("real pending not complete", pending, err)
		}
		for _, c := range pending.Changes {
			match, err := s.wafCurrentMatches(c, true)
			if err != nil || !match {
				t.Fatal("child had not written complete native next set", c.Path, err)
			}
		}
		if checkpoint == "after-reload" {
			if err = waitWAFReloadGeneration(context.Background(), beforeGeneration); err != nil {
				t.Fatal("child real new worker generation", err)
			}
			next, err := decodeLoadBalanceEntry(pending.Changes[1].NextData)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.verifyLoadBalanceLive(context.Background(), next); err != nil {
				t.Fatal("child real newly applied routing", err)
			}
			for i := 0; i < 6; i++ {
				if get("actual-child-after-reload-before-journal-commit", 200) != "B" {
					t.Fatal("child exclusion not live")
				}
			}
		}
		if err = child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		childErr := <-childDone
		var exit *exec.ExitError
		if !errors.As(childErr, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatal("child did not receive actual SIGKILL", childErr)
		}
		fresh = lbActiveNativeService(stage, run)
		if checkpoint == "cold" {
			oldMaster := command.Process.Pid
			if err = command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				masterAlive = false
			case <-time.After(5 * time.Second):
				t.Fatal("private Nginx did not stop for cold recovery")
			}
			if err = fresh.recoverLoadBalanceCold(); err != nil {
				t.Fatal("exact production cold pre-start recovery", err)
			}
			command = exec.Command("/usr/sbin/nginx", "-p", stage+"/", "-c", filepath.Join(stage, "nginx.conf"), "-g", "daemon off;")
			command.Stdout, command.Stderr = output, output
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			done = make(chan error, 1)
			masterAlive = true
			go func(c *exec.Cmd, out chan error) { out <- c.Wait() }(command, done)
			deadline = time.Now().Add(5 * time.Second)
			for {
				if err = fresh.verifyLoadBalanceLive(context.Background(), v); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual cold Nginx restart did not resume original fingerprint", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			newGeneration, err := captureWAFReloadGeneration(context.Background(), "/proc", "/usr/sbin/nginx", command.Process.Pid)
			if err != nil || newGeneration.Master.Start == master.Start || len(newGeneration.Workers) == 0 {
				t.Fatal("actual cold generation was not replaced", err)
			}
			proof["cold_nginx_old_pid"] = oldMaster
			proof["cold_nginx_new_pid"] = command.Process.Pid
			proof["cold_nginx_new_start"] = newGeneration.Master.Start
		} else if err = fresh.recoverLoadBalanceBeforeMutation(context.Background(), "/usr/sbin/nginx"); err != nil {
			t.Fatal("fresh native recovery", checkpoint, err)
		}
		for path, want := range old {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("SIGKILL recovery changed original set", path, err)
			}
		}
		v, _, err = fresh.readLoadBalanceEntry(domain)
		if err != nil || len(v.Routing.Down) != 0 || v.Routing.Sequence != 4 {
			t.Fatal(v, err)
		}
		get("actual-SIGKILL-"+checkpoint+"-fresh-recovery", 200)
	}
	rows, err := fresh.loadBalanceHealthReports([]loadBalanceEntry{v}, time.Now().UTC())
	if err != nil || rows[0]["automatic_traffic_changes"] != true || rows[0]["traffic_excluded"] != false {
		t.Fatal("real state/report mismatch", rows, err)
	}
	proof["actual_client_SIGKILL"] = true
	proof["actual_client_SIGKILL_checkpoints"] = []string{"before-validation", "after-reload", "cold"}
	proof["actual_cold_nginx_restart"] = true
	proof["native_reload_generation_verified"] = true
	proof["business_results"] = results
	proof["syntax_checks"] = checks.Load()
	proof["reloads"] = reloads.Load()
	proof["final_revision"] = v.Revision
	proof["final_routing_sequence"] = v.Routing.Sequence
}

type lbActiveKillInput struct {
	Stage       string              `json:"stage"`
	Input       core.AppModuleInput `json:"input"`
	Checkpoint  string              `json:"checkpoint"`
	MasterPID   int                 `json:"master_pid"`
	MasterStart uint64              `json:"master_start"`
}

func lbActiveNativeKillChild(t *testing.T) {
	stage := os.Getenv("PANEL_LB_ACTIVE_KILL_CHILD")
	if filepath.Dir(stage) != "/var/lib/panel-executor" || !strings.HasPrefix(filepath.Base(stage), "load-active-native-") {
		t.Fatal("child outside own mount")
	}
	var input lbActiveKillInput
	if err := moduleRead(filepath.Join(stage, "kill-input.json"), &input); err != nil || input.Stage != stage {
		t.Fatal("child input identity", err)
	}
	if input.Checkpoint != "before-validation" && input.Checkpoint != "after-reload" && input.Checkpoint != "cold" {
		t.Fatal("unknown child checkpoint")
	}
	master, err := readWAFReloadProcess("/proc", input.MasterPID)
	if err != nil || master.Start != input.MasterStart {
		t.Fatal("child master changed", err)
	}
	binary, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", input.MasterPID))
	if err != nil || binary != "/usr/sbin/nginx" {
		t.Fatal("child master binary changed", err)
	}
	pause := func(ctx context.Context) (string, error) {
		if err := atomicWrite(filepath.Join(stage, "kill-"+input.Checkpoint+"-ready"), []byte("complete durable next-set; "+input.Checkpoint+"\n"), 0600); err != nil {
			return "", err
		}
		<-ctx.Done()
		return "", ctx.Err()
	}
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/sbin/nginx" && len(args) == 3 && args[0] == "-t" && args[1] == "-c" && args[2] == filepath.Join(stage, "nginx.conf") {
			if input.Checkpoint != "after-reload" {
				return pause(ctx)
			}
			return RunCommand(ctx, name, args...)
		}
		if input.Checkpoint == "after-reload" && name == "/usr/bin/systemctl" {
			current, err := readWAFReloadProcess("/proc", input.MasterPID)
			if err != nil || current.Start != input.MasterStart {
				return "", errors.New("child master identity changed")
			}
			if strings.Join(args, " ") == "show nginx --property=ActiveState,MainPID" {
				return fmt.Sprintf("ActiveState=active\nMainPID=%d\n", input.MasterPID), nil
			}
			if strings.Join(args, " ") == "reload nginx" {
				if err = syscall.Kill(input.MasterPID, syscall.SIGHUP); err != nil {
					return "", err
				}
				return pause(ctx)
			}
		}
		return "", errors.New("unexpected child command")
	}
	s := lbActiveNativeService(stage, run)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := s.checkLoadBalanceHTTP(ctx, input.Input); err != nil {
		t.Fatal(err)
	}
	t.Fatal("SIGKILL checkpoint unexpectedly returned")
}
