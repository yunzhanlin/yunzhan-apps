//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func statisticsLogTransactionFixture(t *testing.T) (*Service, []byte, []byte) {
	t.Helper()
	base := wafPolicyFixture(t)
	// AF_UNIX has a fixed pathname budget; a deeply nested go-test TMPDIR
	// must not change the production path contract. Owned short root only.
	dir, err := os.MkdirTemp("/var/lib", "stats-h-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	base.Config.SystemRoot = dir
	base.Config.SecurityDir = filepath.Join(dir, "security")
	base.Config.NginxConf = filepath.Join(dir, "nginx.conf")
	base.Config.NginxBin = "/usr/sbin/nginx"
	if err := os.WriteFile(base.Config.NginxConf, statisticsNginxTestConfig(statisticsNginxLegacyFormat), 0644); err != nil {
		t.Fatal(err)
	}
	previous := map[string]any{"id": "website-statistics-v2", "version": "2.4.1", "settings": map[string]any{"owned": "keep"}, "installed_at": "2026-01-01T00:00:00Z"}
	if err := moduleWrite(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"), previous); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
	previous["version"] = "2.5.0"
	previous["updated_at"] = core.Now()
	next, _ := json.Marshal(previous)
	tx := base.statisticsLogTransactionService()
	return tx, old, next
}
func statisticsLogTestCommands(t *testing.T, s *Service, mode string, calls *[]string) {
	t.Helper()
	// Native command adapters are explicitly synthetic. The HTTP probe itself
	// still goes through a real Unix socket, with no production bypass.
	var server *http.Server
	var loaded atomic.Value
	loaded.Store("")
	closeProbe := func() {
		if server != nil {
			server.Close()
			server = nil
		}
	}
	t.Cleanup(closeProbe)
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		*calls = append(*calls, filepath.Base(name)+" "+strings.Join(args, " "))
		if name == "/usr/bin/systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "active", nil
		}
		if name == "/usr/bin/systemctl" && len(args) > 0 && args[0] == "reload" {
			if mode == "fail-once" {
				mode = "success"
				return "", errors.New("owned reload refusal")
			}
			if mode == "always-fail" {
				return "", errors.New("owned reload refusal")
			}
			if mode == "external-edit" {
				mode = "success"
				if err := os.WriteFile(s.Config.NginxConf, []byte("# external owned edit\n"), 0644); err != nil {
					t.Fatal(err)
				}
				return "", errors.New("owned external edit")
			}
			if mode == "false-success" {
				mode = "success"
				return "", nil
			}
			data, err := os.ReadFile(s.Config.NginxConf)
			if err != nil {
				return "", err
			}
			nonce, err := statisticsHealthConfigNonce(data, s.statisticsHealthSocket())
			if err != nil {
				return "", err
			}
			if nonce == "" {
				closeProbe()
			} else {
				loaded.Store(nonce)
				if server == nil {
					listener, err := net.Listen("unix", s.statisticsHealthSocket())
					if err != nil {
						return "", err
					}
					server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprint(w, "yunzhan-statistics-log-v2:"+loaded.Load().(string))
					})}
					go server.Serve(listener)
				}
			}
		}
		return "", nil
	}
	s.Config.RunWait = func(ctx context.Context, _ time.Duration, name string, args ...string) (string, error) {
		return s.Config.Run(ctx, name, args...)
	}
}

func TestStatisticsLogTransactionFixedPlanAndManifestLastCommit(t *testing.T) {
	s, old, next := statisticsLogTransactionFixture(t)
	var calls []string
	statisticsLogTestCommands(t, s, "success", &calls)
	before, _ := os.ReadFile(s.Config.NginxConf)
	plan, err := s.statisticsLogPlan(next)
	if err != nil || len(plan) != 2 {
		t.Fatal("fixed plan", err)
	}
	current, _ := os.ReadFile(s.Config.NginxConf)
	if !bytes.Equal(before, current) {
		t.Fatal("planning changed Nginx")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = s.applyStatisticsLogPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	current, _ = os.ReadFile(s.Config.NginxConf)
	manifest, _ := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
	if !bytes.Equal(current, plan[0].NextData) || !bytes.Equal(manifest, next) || bytes.Equal(manifest, old) {
		t.Fatal("fixed publication")
	}
	if _, err = os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		t.Fatal("successful transaction still pending", err)
	}
	receipts, _ := filepath.Glob(filepath.Join(filepath.Dir(s.wafPendingPath()), "*.json"))
	if len(receipts) != 1 {
		t.Fatal("private recovery receipt missing")
	}
	info, err := os.Lstat(receipts[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt privacy", err)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "-t -c") || calls[1] != "systemctl reload nginx" {
		t.Fatal("native command order", calls)
	}
}
func TestStatisticsLogTransactionReloadFailureRestoresBothOrRetainsPending(t *testing.T) {
	for _, mode := range []string{"fail-once", "always-fail", "external-edit", "false-success"} {
		t.Run(mode, func(t *testing.T) {
			s, old, next := statisticsLogTransactionFixture(t)
			before, _ := os.ReadFile(s.Config.NginxConf)
			var calls []string
			statisticsLogTestCommands(t, s, mode, &calls)
			plan, err := s.statisticsLogPlan(next)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err = s.applyStatisticsLogPlan(context.Background(), plan); err == nil {
				t.Fatal("refused reload became successful")
			}
			current, _ := os.ReadFile(s.Config.NginxConf)
			manifest, _ := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
			if !bytes.Equal(manifest, old) {
				t.Fatal("failed reload published future version")
			}
			_, pendingErr := os.Lstat(s.wafPendingPath())
			if mode == "fail-once" || mode == "false-success" {
				if !bytes.Equal(current, before) || !os.IsNotExist(pendingErr) {
					t.Fatal("verified rollback not complete", pendingErr)
				}
			} else {
				if pendingErr != nil {
					t.Fatal("unverified native restore lost its pending evidence", pendingErr)
				}
				if mode == "always-fail" && !bytes.Equal(current, before) {
					t.Fatal("old config not restored")
				}
				if mode == "external-edit" && string(current) != "# external owned edit\n" {
					t.Fatal("external changed config overwritten")
				}
			}
		})
	}
}
func TestStatisticsLogTransactionPartialFilesRecoverBeforeOtherNginxMutation(t *testing.T) {
	s, old, next := statisticsLogTransactionFixture(t)
	var calls []string
	statisticsLogTestCommands(t, s, "success", &calls)
	plan, err := s.statisticsLogPlan(next)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.startWAFTransaction(plan); err != nil {
		t.Fatal(err)
	}
	if err = wafApplyChange(plan[0], true); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	other := &Service{Config: s.Config}
	if f, e := other.lockWAFConfiguration(); e == nil {
		f.Close()
		t.Fatal("pending statistics allowed unrelated Nginx write")
	}
	lock, err = s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = s.recoverStatisticsLogBeforeMutation(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(s.Config.NginxConf)
	manifest, _ := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
	if !bytes.Equal(current, plan[0].OldData) || !bytes.Equal(manifest, old) {
		t.Fatal("partial fixed-file recovery")
	}
}
func TestStatisticsLogTransactionRejectsWrongPathSettingsAndFutureRecordShape(t *testing.T) {
	s, _, next := statisticsLogTransactionFixture(t)
	for _, raw := range []string{"{}", strings.Replace(string(next), "website-statistics-v2", "task-manager", 1), strings.Replace(string(next), `"2.5.0"`, `"3.0"`, 1), strings.Replace(string(next), `"owned":"keep"`, `"owned":"changed"`, 1)} {
		if _, err := s.statisticsLogPlan([]byte(raw)); err == nil {
			t.Fatal("unbound record accepted", raw)
		}
	}
	plan, err := s.statisticsLogPlan(next)
	if err != nil {
		t.Fatal(err)
	}
	plan[1].Path = filepath.Join(s.Config.SystemRoot, "unrelated.json")
	if _, err = s.startWAFTransaction(plan); err == nil {
		t.Fatal("unexpected recovery path accepted")
	}
	plan, err = s.statisticsLogPlan(next)
	if err != nil {
		t.Fatal(err)
	}
	plan[0].NextData = append(plan[0].NextData, []byte("# unrelated external change\n")...)
	if _, err = s.startWAFTransaction(plan); err == nil {
		t.Fatal("unrelated Nginx change bundled into statistics migration")
	}
}

func TestStatisticsLogTransactionStoppedRecoveryRequiresZeroPIDAndNeverStarts(t *testing.T) {
	for _, state := range []string{"inactive", "failed", "activating", "activating-live", "unknown", "inactive-live"} {
		t.Run(state, func(t *testing.T) {
			s, old, next := statisticsLogTransactionFixture(t)
			plan, err := s.statisticsLogPlan(next)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if _, err = s.startWAFTransaction(plan); err != nil {
				t.Fatal(err)
			}
			if err = wafApplyChange(plan[0], true); err != nil {
				t.Fatal(err)
			}
			var calls []string
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
				if name == "/usr/bin/systemctl" {
					if args[0] == "is-active" {
						return strings.TrimSuffix(state, "-live"), errors.New("not active")
					}
					if args[0] == "show" {
						if strings.HasSuffix(state, "-live") {
							return "77", nil
						}
						return "0", nil
					}
					return "", errors.New("unexpected attempt to mutate stopped service")
				}
				return "", nil
			}
			s.Config.RunWait = func(ctx context.Context, _ time.Duration, name string, args ...string) (string, error) {
				return s.Config.Run(ctx, name, args...)
			}
			err = s.recoverStatisticsLogBeforeMutation(context.Background())
			ok := state == "inactive" || state == "failed" || state == "activating"
			if (err == nil) != ok {
				t.Fatal("stopped recovery", state, err)
			}
			for _, call := range calls {
				if strings.Contains(call, "start ") || strings.Contains(call, "reload ") {
					t.Fatal("stopped service mutated", calls)
				}
			}
			_, pendingErr := os.Lstat(s.wafPendingPath())
			if ok && !os.IsNotExist(pendingErr) || !ok && pendingErr != nil {
				t.Fatal("pending evidence", pendingErr)
			}
			current, _ := os.ReadFile(s.Config.NginxConf)
			manifest, _ := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
			if !bytes.Equal(current, plan[0].OldData) || !bytes.Equal(manifest, old) {
				t.Fatal("original files changed")
			}
		})
	}
}

func TestStatisticsLogTransactionPendingFreezesHistoryAndInstalledHealth(t *testing.T) {
	s, original, next := statisticsLogTransactionFixture(t)
	db, err := s.openStatisticsHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := core.ID()
	if _, err = db.Exec("INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES(?,0,'','/original',200,0,0,'{}')", id); err != nil {
		t.Fatal(err)
	}
	plan, err := s.statisticsLogPlan(next)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.startWAFTransaction(plan); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	lock.Close()
	if _, err = s.openStatisticsHistory(context.Background()); err == nil {
		t.Fatal("pending journal allowed schema writes")
	}
	if _, err = s.ingestStatisticsHistory(context.Background(), db, id, time.Now()); err == nil {
		t.Fatal("pending journal allowed cleanup or ingestion")
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM access_rows WHERE path='/original'").Scan(&count); err != nil || count != 1 {
		t.Fatal("original history changed", err)
	}
	if status := s.appModuleStatus(context.Background(), "website-statistics-v2"); !status.StateUnknown || status.Healthy {
		t.Fatal("pending journal reported normal")
	}
	base := &Service{Config: s.Config}
	for _, action := range []string{"configure", "uninstall"} {
		if err = base.appModuleLifecycle(context.Background(), "website-statistics-v2", action, map[string]any{"changed": "must-refuse"}, func(string) {}); err == nil {
			t.Fatal("pending journal allowed lifecycle write", action)
		}
	}
	if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.4.1", func(string) {}); err == nil {
		t.Fatal("pending journal allowed version update")
	}
	current, err := os.ReadFile(s.statisticsLogConfigurationPaths()[1])
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("pending lifecycle changed original installed record", err)
	}
}

func TestStatisticsLogTransactionUndeclaredDirectoryBoundaryRefusesWithoutRecursion(t *testing.T) {
	s, _, _ := statisticsLogTransactionFixture(t)
	s.Config.ConfDir, s.Config.StateDir = "", ""
	// An isolated root is not permission to adopt arbitrary host ancestors.
	if err := s.wafOwnedDirectory("/", false); err == nil {
		t.Fatal("undeclared host boundary accepted")
	}
}
