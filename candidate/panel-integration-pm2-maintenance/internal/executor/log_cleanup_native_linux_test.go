//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLogCleanupNativePrivateNginxWriterReopensAndPersistentReplayDoesNotSignal(t *testing.T) {
	if os.Getenv("PANEL_QA_LOG_NATIVE") != "1" {
		t.Skip("explicit private read-only mount-namespace harness required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("private native QA requires root in its isolated namespace")
	}
	s, in, logs, now := siteLogLedgerFixture(t)
	tmp, err := os.Stat("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	// Only /tmp is a private bind mount inside this explicit QA namespace.
	// www-data needs traversal, not listing or write access, to its own logs.
	if err = os.Chmod("/tmp", 0711); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := os.Chmod("/tmp", tmp.Mode().Perm()); e != nil {
			t.Error(e)
		}
	})
	for _, dir := range []string{s.Config.SystemRoot, filepath.Dir(s.Config.SystemRoot), filepath.Join(s.Config.SystemRoot, "var"), filepath.Join(s.Config.SystemRoot, "var/log"), logs} {
		if err = os.Chmod(dir, 0711); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink("/proc", filepath.Join(s.Config.SystemRoot, "proc")); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "panel-" + in.SiteID + ".access.log"
	errorName := "panel-" + in.SiteID + ".error.log"
	configuration := fmt.Sprintf("user www-data; worker_processes 1; daemon off; pid %s/nginx.pid; error_log %s/%s info; events { worker_connections 64; } http { log_format qa '$request_method $status'; access_log %s/%s qa; client_body_temp_path %s/client; proxy_temp_path %s/proxy; fastcgi_temp_path %s/fastcgi; uwsgi_temp_path %s/uwsgi; scgi_temp_path %s/scgi; server { listen 127.0.0.1:%d; add_header X-Private-Writer $pid; return 200 'private-writer\\n'; } }", s.Config.SystemRoot, logs, errorName, logs, name, s.Config.SystemRoot, s.Config.SystemRoot, s.Config.SystemRoot, s.Config.SystemRoot, s.Config.SystemRoot, port)
	configPath := filepath.Join(s.Config.SystemRoot, "nginx.conf")
	if err = os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(filepath.Join(s.Config.SystemRoot, "nginx-process.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	command := exec.Command("/usr/sbin/nginx", "-p", s.Config.SystemRoot+"/", "-c", configPath)
	command.Stdout, command.Stderr = output, output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = command.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	// The native process is private, not installed as nginx.service. Only its
	// fixed read-only MainPID query is substituted; rotation code is real.
	s.Config.NginxBin = "/usr/sbin/nginx"
	queries := 0
	s.Config.RunWait = func(ctx context.Context, wait time.Duration, binary string, args ...string) (string, error) {
		if binary != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"show", "nginx", "--property=ActiveState,MainPID"}) {
			t.Fatalf("unexpected command %s %v", binary, args)
		}
		queries++
		return fmt.Sprintf("ActiveState=active\nMainPID=%d\n", command.Process.Pid), ctx.Err()
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	probe := func() error {
		response, e := client.Get(url)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 64))
		if e != nil || response.StatusCode != 200 || !strings.HasPrefix(string(body), "private-writer") || response.Header.Get("X-Private-Writer") == "" {
			return fmt.Errorf("private native probe failed")
		}
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for probe() != nil {
		if time.Now().After(deadline) {
			t.Fatal("private Nginx did not start; retained process log")
		}
		time.Sleep(25 * time.Millisecond)
	}
	access := filepath.Join(logs, name)
	var original []byte
	for {
		original, err = os.ReadFile(access)
		if err == nil && strings.Contains(string(original), "GET 200") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private native writer did not generate access log", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	before, err := captureWAFReloadGeneration(t.Context(), "/proc", "/usr/sbin/nginx", command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	retired := name + ".20260901-100000"
	foreign := "panel-" + core.ID() + ".access.log.20260901-100000"
	siteLogFixtureWrite(t, filepath.Join(logs, retired), "old private evidence")
	siteLogFixtureWrite(t, filepath.Join(logs, foreign), "foreign evidence")
	result, err := s.guardedSiteLogCleanup(t.Context(), in, now, nil)
	if err != nil || result.Rotated != 2 || result.Deleted != 1 || result.DeletedBytes != 20 || queries != 1 {
		t.Fatal("native log cleanup not verified", result, err, queries)
	}
	archived, err := os.ReadFile(access + "." + now.Format("20060102-150405"))
	if err != nil || !strings.HasPrefix(string(archived), string(original)) {
		t.Fatal("original native bytes lost", err)
	}
	completedInspection, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || !core.ValidLogCleanupInspection(completedInspection, in.RequestID, in.SiteID) {
		t.Fatal("native completed inspection was invalid", completedInspection, e)
	}
	for _, file := range completedInspection.Files {
		if file.Role == "rotation" && file.ArchiveState != "original_inode_unchanged" && file.ArchiveState != "original_inode_written" && file.ArchiveState != "original_inode_owner_changed" {
			t.Fatal("preserved native archive was mislabeled", file)
		}
	}
	if body, e := os.ReadFile(filepath.Join(logs, foreign)); e != nil || string(body) != "foreign evidence" {
		t.Fatal("other site log changed", e)
	}
	if _, e := os.Lstat(filepath.Join(logs, retired)); !os.IsNotExist(e) {
		t.Fatal("verified expired log not removed", e)
	}
	if err = probe(); err != nil {
		t.Fatal("native HTTP writer did not continue", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		body, e := os.ReadFile(access)
		if e == nil && strings.Contains(string(body), "GET 200") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reopened native log did not receive new request", e)
		}
		time.Sleep(25 * time.Millisecond)
	}
	in.Attempt = 1
	replay, e := New(s.Config).guardedSiteLogCleanup(t.Context(), in, now.Add(time.Hour), nil)
	if e != nil || !reflect.DeepEqual(result, replay) || queries != 1 {
		t.Fatal("completed native operation signalled or reran", replay, e, queries)
	}
	after, e := captureWAFReloadGeneration(t.Context(), "/proc", "/usr/sbin/nginx", command.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	if before.Master.Start != after.Master.Start || before.Master.PID != after.Master.PID || len(before.Workers) != len(after.Workers) {
		t.Fatal("rotation restarted native processes")
	}
	for i, worker := range before.Workers {
		if worker.PID != after.Workers[i].PID || worker.Start != after.Workers[i].Start {
			t.Fatal("USR1 replaced private worker")
		}
	}
	// Model losing confirmation after a genuine USR1 completed, not by
	// pretending a mocked callback proves native file reopening.
	unknown := in
	unknown.RequestID = core.ID()
	unknown.Attempt = 0
	active := []plannedSiteLog{}
	for _, file := range []string{name, errorName} {
		info, e := os.Lstat(filepath.Join(logs, file))
		if e != nil {
			t.Fatal(e)
		}
		if info.Size() > 0 {
			active = append(active, plannedSiteLog{name: file, target: file + "." + now.Add(time.Second).Format("20060102-150405"), info: info})
		}
	}
	actualReopen, e := s.prepareSiteLogReopen(t.Context(), active)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.guardedSiteLogCleanup(t.Context(), unknown, now.Add(time.Second), func(ctx context.Context) error {
		if e := actualReopen(ctx); e != nil {
			return e
		}
		return errors.New("controlled lost confirmation after genuine reopen")
	})
	if e == nil {
		t.Fatal("lost confirmation credited as success")
	}
	inspection, e := s.inspectSiteLogCleanup(t.Context(), unknown.SiteID, unknown.RequestID)
	if e != nil || inspection.State != "unknown" || inspection.Result != nil {
		t.Fatal(inspection, e)
	}
	continuation := core.LogCleanupContinueRequest{RequestID: unknown.RequestID, SiteID: unknown.SiteID, PlanSHA256: inspection.PlanSHA256, AcknowledgeUnknown: true}
	archivePath := filepath.Join(logs, active[0].target)
	writer, e := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, refused := s.continueSiteLogCleanup(t.Context(), continuation, nil)
	writer.Close()
	if refused == nil || !strings.Contains(refused.Error(), "写入模式") {
		t.Fatal("native archive writer was not refused", refused)
	}
	kept := map[string]string{}
	entries, e := os.ReadDir(logs)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		body, e := os.ReadFile(filepath.Join(logs, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		kept[entry.Name()] = string(body)
	}
	verified, e := s.continueSiteLogCleanup(t.Context(), continuation, nil)
	if e != nil || !siteLogSHA256(verified.EvidenceSHA256) {
		t.Fatal("genuine native continuation failed", verified, e)
	}
	queryCount := queries
	repeated, e := New(s.Config).continueSiteLogCleanup(t.Context(), continuation, nil)
	if e != nil || repeated != verified || queries != queryCount {
		t.Fatal("native continuation replay repeated verification", repeated, e, queries)
	}
	for file, body := range kept {
		actual, e := os.ReadFile(filepath.Join(logs, file))
		if e != nil || string(actual) != body {
			t.Fatal("native continuation changed bytes", file, e)
		}
	}
	inspection, e = s.inspectSiteLogCleanup(t.Context(), unknown.SiteID, unknown.RequestID)
	if e != nil || inspection.State != "unknown" || inspection.Result != nil || inspection.Continuation == nil {
		t.Fatal("native unknown was rewritten as success", inspection, e)
	}
	t.Logf("private native Nginx main=%d; genuine access writer, pidfd USR1, old fd closure, new inode writes and persistent replay verified; existing nginx.service untouched; not formal signed API proof", command.Process.Pid)
}
