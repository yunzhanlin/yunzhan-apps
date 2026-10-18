//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// REAL independent pinned Nginx master and Unix HTTP probe, real HUP and
// SIGKILL of a writer. A fixed command adapter routes reload to this owned
// process, NOT the host systemd service. This is NOT signed2.5 lifecycle or
// power-loss/cold-boot acceptance.
func TestStatisticsNativeHealthMigrationAndRecovery(t *testing.T) {
	if os.Getenv("PANEL_STATISTICS_NATIVE_NGINX_QA") != "1" {
		t.Skip("owned isolated Linux native Nginx fixture only")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 {
		t.Fatal("native health fixture identity")
	}
	pins := map[string]string{
		"lima-panel-development24beil-debian13": "452537ef7d534757bd21c3c4f67f801ef4db587bd354bc47fca68693f72ae75d",
		"lima-panel-analytics23t-unit-debian13": "254fac73e79add393fef33f514bc91b8a98ad1966c2b43c77a98c9359580a6d8",
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
		t.Fatal("NoNewPrivileges missing")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), key+":\t0000000000000000\n") {
			t.Fatal("native health fixture capabilities widened", key)
		}
	}
	program, err := os.ReadFile("/usr/sbin/nginx")
	checksum := sha256.Sum256(program)
	if err != nil || pins[strings.TrimSpace(string(host))] == "" || hex.EncodeToString(checksum[:]) != pins[strings.TrimSpace(string(host))] {
		t.Fatal("native program pin or guest mismatch")
	}
	if base := os.Getenv("PANEL_STATISTICS_HEALTH_KILL_ROOT"); base != "" {
		// The parent creates and owns the complete short private fixture.
		if !strings.HasPrefix(base, "/var/lib/st-n-") || filepath.Clean(base) != base || filepath.Dir(base) != "/var/lib" || ownedRuntimePath(base, true) != nil {
			t.Fatal("killed-writer fixture root invalid")
		}
		s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security"), NginxConf: filepath.Join(base, "nginx.conf")}).statisticsLogTransactionService()
		lock, err := s.lockWAFConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		previous, err := s.moduleInstalledRecord("website-statistics-v2")
		if err != nil {
			t.Fatal(err)
		}
		previous["updated_at"] = core.Now()
		previous["version"] = "2.5.0"
		next, _ := json.Marshal(previous)
		plan, err := s.statisticsLogPlan(next)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.startWAFTransaction(plan); err != nil {
			t.Fatal(err)
		}
		if err = wafApplyChange(plan[0], true); err != nil {
			t.Fatal(err)
		}
		fmt.Println("OWN_STATISTICS_CONFIG_UNCOMMITTED_READY")
		for {
			time.Sleep(time.Second)
		}
	}
	base, err := os.MkdirTemp("/var/lib", "st-n-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(base, "nginx.conf")
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security"), NginxConf: conf, NginxBin: "/usr/sbin/nginx"}).statisticsLogTransactionService()
	if err = s.wafOwnedDirectory(filepath.Dir(s.statisticsHealthSocket()), true); err != nil {
		t.Fatal(err)
	}
	temporary := ""
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		temporary += fmt.Sprintf("%s_temp_path %s; ", kind, filepath.Join(base, kind))
	}
	oldConf := []byte(fmt.Sprintf("user root root; pid %s; error_log %s error; events { worker_connections 32; } http { %s %s %s log_format panel_site escape=json '%s'; access_log off; }\n",
		filepath.Join(base, "nginx.pid"), filepath.Join(base, "nginx.error"), statisticsNginxPathMap, statisticsNginxRefererMap, temporary, statisticsNginxLegacyFormat))
	if err = os.WriteFile(conf, oldConf, 0600); err != nil {
		t.Fatal(err)
	}
	previous := map[string]any{"id": "website-statistics-v2", "version": "2.4.1", "settings": map[string]any{"owned": "keep"}, "installed_at": "2026-01-01T00:00:00Z"}
	if err = moduleWrite(s.statisticsLogConfigurationPaths()[1], previous); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	native := exec.CommandContext(ctx, "/usr/sbin/nginx", "-c", conf, "-p", base, "-g", "daemon off; master_process on;")
	log, err := os.OpenFile(filepath.Join(base, "native.private.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	native.Stdout, native.Stderr = log, log
	if err = native.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- native.Wait() }()
	defer func() {
		_ = native.Process.Signal(syscall.SIGQUIT)
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			_ = native.Process.Kill()
			<-wait
		}
	}()
	ready := false
	for attempt := 0; attempt < 60; attempt++ {
		pid, _ := os.ReadFile(filepath.Join(base, "nginx.pid"))
		if strings.TrimSpace(string(pid)) == strconv.Itoa(native.Process.Pid) {
			ready = true
			break
		}
		select {
		case err := <-wait:
			wait <- err
			diagnostic, _ := os.ReadFile(filepath.Join(base, "native.private.log"))
			t.Fatal("native master failed", err, string(diagnostic))
		case <-time.After(25 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("owned native master did not start")
	}
	refuseSignal := false
	s.Config.Run = func(commandCtx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/sbin/nginx" && len(args) == 3 && args[0] == "-t" && args[1] == "-c" && args[2] == conf {
			output, err := exec.CommandContext(commandCtx, name, args...).CombinedOutput()
			return string(output), err
		}
		if name == "/usr/bin/systemctl" && len(args) == 2 && args[1] == "nginx" {
			switch args[0] {
			case "is-active":
				return "active", nil
			case "reload":
				if refuseSignal {
					refuseSignal = false
					return "", nil // real worker still serves the OLD fingerprint
				}
				return "", native.Process.Signal(syscall.SIGHUP)
			}
		}
		return "", errors.New("unexpected fixture command")
	}
	s.Config.RunWait = func(c context.Context, _ time.Duration, name string, args ...string) (string, error) {
		return s.Config.Run(c, name, args...)
	}
	// Exercise the REAL normal fixed update entry, including actual schema
	// initialization and ready status. The command adapter still targets this
	// independent native master, not the host's systemd service or signed job.
	baseService := &Service{Config: s.Config}
	if err = baseService.updateSoftware(ctx, "website-statistics-v2", "2.5.0", func(string) {}); err != nil {
		t.Fatal("normal native update entry", err)
	}
	acceptedConf, _ := os.ReadFile(conf)
	if err = s.waitStatisticsHealth(ctx, acceptedConf); err != nil {
		t.Fatal(err)
	}
	next, err := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
	if err != nil {
		t.Fatal(err)
	}
	if status := baseService.appModuleStatus(ctx, "website-statistics-v2"); !status.Healthy || status.Version != "2.5.0" {
		t.Fatal("native update not actually ready", status)
	}
	store := filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
	beforeStore, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	// A successful command WITHOUT HUP must never publish the new candidate.
	refuseSignal = true
	plan, err := s.statisticsLogPlan(next)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	err = s.applyStatisticsLogPlan(ctx, plan)
	lock.Close()
	if err == nil {
		t.Fatal("old live fingerprint accepted as new")
	}
	restored, _ := os.ReadFile(conf)
	if !bytes.Equal(restored, acceptedConf) || s.waitStatisticsHealth(ctx, acceptedConf) != nil {
		t.Fatal("real HUP restore did not retain old fingerprint")
	}
	// Kill a separate writer while its cross-process lock/journal is active.
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStatisticsNativeHealthMigrationAndRecovery$", "-test.timeout=50s")
	child.Env = append(os.Environ(), "PANEL_STATISTICS_HEALTH_KILL_ROOT="+base)
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = child.Stdout
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	scanner := bufio.NewScanner(output)
	ready = false
	for scanner.Scan() {
		if scanner.Text() == "OWN_STATISTICS_CONFIG_UNCOMMITTED_READY" {
			ready = true
			break
		}
	}
	if !ready {
		_ = child.Wait()
		t.Fatal("writer never reached journaled candidate")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("writer not killed")
	}
	if read, err := s.statisticsLogReadLock(); err == nil {
		read.Close()
		t.Fatal("pending migration allowed history reader")
	}
	if _, err = s.openStatisticsHistory(ctx); err == nil {
		t.Fatal("pending migration allowed database creation/migration")
	}
	if status := s.appModuleStatus(ctx, "website-statistics-v2"); !status.StateUnknown || status.Healthy {
		t.Fatal("pending migration reported healthy")
	}
	afterStore, err := os.ReadFile(store)
	if err != nil || !bytes.Equal(beforeStore, afterStore) {
		t.Fatal("pending migration changed actual history store", err)
	}
	fresh := (&Service{Config: s.Config}).statisticsLogTransactionService()
	lock, err = fresh.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	err = fresh.recoverStatisticsLogBeforeMutation(ctx)
	lock.Close()
	if err != nil {
		t.Fatal("fresh executor native recovery", err)
	}
	restored, _ = os.ReadFile(conf)
	manifest, _ := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
	if !bytes.Equal(restored, acceptedConf) || !bytes.Equal(manifest, next) || s.waitStatisticsHealth(ctx, acceptedConf) != nil {
		t.Fatal("killed writer changed original published config/record")
	}
	if _, err = os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed recovery still pending", err)
	}
	reader, err := s.statisticsLogReadLock()
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := fresh.lockWAFConfiguration(); !errors.Is(err, errWAFConfigurationBusy) {
		if writer != nil {
			writer.Close()
		}
		reader.Close()
		t.Fatal("reader did not exclude concurrent migration", err)
	}
	reader.Close()
}
