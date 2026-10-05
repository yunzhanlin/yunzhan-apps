//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func operationWorker() core.PHPWorker {
	spec := core.DefaultPHPWorkerSpec(core.ID())
	spec.Name = "queue"
	spec.Entry = "artisan"
	return core.PHPWorker{PHPWorkerSpec: spec, ID: core.ID(), ObservedReleaseID: "php-8.4.25"}
}
func TestPHPWorkerOperationPersistsBeforeAcknowledgementAndScopesResults(t *testing.T) {
	s := New(Config{StateDir: t.TempDir()})
	s.phpWorkerQueueStarted = true
	s.phpWorkerQueueWake = make(chan struct{}, 1)
	v := operationWorker()
	op, e := s.enqueuePHPWorkerOperation(v, "stop", "")
	if e != nil {
		t.Fatal(e)
	}
	if op.State != "queued" || op.WorkerID != v.ID {
		t.Fatal(op)
	}
	st, e := os.Stat(filepath.Join(s.phpWorkerOperationsDir(), op.ID+".json"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, e)
	}
	records, e := readPHPWorkerOperations(s.phpWorkerOperationsDir())
	if e != nil || len(records) != 1 || records[0].Input.ObservedReleaseID != v.ObservedReleaseID {
		t.Fatal(records, e)
	}
	if _, e = s.phpWorkerOperation(core.ID(), op.ID); e == nil {
		t.Fatal("cross-site operation result exposed")
	}
	if _, e = s.enqueuePHPWorkerOperation(v, "delete", "wrong"); e == nil {
		t.Fatal("delete name bypassed")
	}
	if _, e = s.enqueuePHPWorkerOperation(v, "restart", ""); e == nil {
		t.Fatal("pending operation overwritten")
	}
}
func TestPHPWorkerOperationRestartNeverReportsInterruptedMutationAsSuccess(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{StateDir: dir})
	v := operationWorker()
	op := core.PHPWorkerOperation{ID: core.ID(), SiteID: v.SiteID, WorkerID: v.ID, State: "running", Action: "stop", CreatedAt: core.Now()}
	if e := s.savePHPWorkerOperation(phpWorkerOperationRecord{PHPWorkerOperation: op, Input: v}); e != nil {
		t.Fatal(e)
	}
	fresh := New(Config{StateDir: dir, Run: func(context.Context, string, ...string) (string, error) { return "", errors.New("state query failed") }})
	if e := fresh.StartPHPWorkerOperations(); e != nil {
		t.Fatal(e)
	}
	got, e := fresh.phpWorkerOperation(v.SiteID, op.ID)
	if e != nil || got.State != "needs_attention" || got.Error == "" || !phpWorkerOperationReference(got.State) {
		t.Fatal(got, e)
	}
	if e = fresh.StartPHPWorkerOperations(); e != nil {
		t.Fatal(e)
	}
	got, e = fresh.phpWorkerOperation(v.SiteID, op.ID)
	if e != nil || got.State != "needs_attention" {
		t.Fatal(got, e)
	}
}

func TestPHPWorkerInterruptedWithoutResourcesReleasesReferenceOnlyAfterProof(t *testing.T) {
	for _, test := range []struct {
		name, observed, boot string
		want                 string
	}{
		{"absent", "ActiveState=inactive\nMainPID=0", "Failed to get unit file state: No such file or directory", "failed"},
		{"live", "ActiveState=active\nMainPID=123", "disabled", "needs_attention"},
		{"enabled", "ActiveState=inactive\nMainPID=0", "enabled", "needs_attention"},
		{"boot query failed", "ActiveState=inactive\nMainPID=0", "Failed to connect to bus", "needs_attention"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(Config{StateDir: t.TempDir(), Run: func(ctx context.Context, binary string, args ...string) (string, error) {
				if args[0] == "show" {
					return test.observed, nil
				}
				if args[0] == "is-enabled" {
					if strings.HasPrefix(test.boot, "Failed") {
						return test.boot, errors.New("query failed")
					}
					return test.boot, nil
				}
				t.Fatal(args)
				return "", nil
			}})
			v := operationWorker()
			op := core.PHPWorkerOperation{ID: core.ID(), SiteID: v.SiteID, WorkerID: v.ID, State: "running", Action: "create", CreatedAt: core.Now()}
			if e := s.savePHPWorkerOperation(phpWorkerOperationRecord{PHPWorkerOperation: op, Input: v}); e != nil {
				t.Fatal(e)
			}
			if e := s.StartPHPWorkerOperations(); e != nil {
				t.Fatal(e)
			}
			got, e := s.phpWorkerOperation(v.SiteID, op.ID)
			if e != nil || got.State != test.want {
				t.Fatal(got, e)
			}
			if phpWorkerOperationReference(got.State) != (test.want == "needs_attention") {
				t.Fatal(got)
			}
		})
	}
}
func TestPHPWorkerOperationMetadataFailsClosed(t *testing.T) {
	for _, corrupt := range []string{"site", "runtime", "action", "state", "symlink"} {
		t.Run(corrupt, func(t *testing.T) {
			s := New(Config{StateDir: t.TempDir()})
			v := operationWorker()
			op := core.PHPWorkerOperation{ID: core.ID(), SiteID: v.SiteID, WorkerID: v.ID, State: "queued", Action: "stop", CreatedAt: core.Now()}
			r := phpWorkerOperationRecord{PHPWorkerOperation: op, Input: v}
			switch corrupt {
			case "site":
				r.Input.SiteID = core.ID()
			case "runtime":
				r.Input.ObservedReleaseID = "nginx-system"
			case "action":
				r.Action = "shell"
			case "state":
				r.State = "done"
			}
			if e := s.savePHPWorkerOperation(r); e != nil {
				t.Fatal(e)
			}
			if corrupt == "symlink" {
				p := filepath.Join(s.phpWorkerOperationsDir(), op.ID+".json")
				if e := os.Rename(p, p+".source"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(p+".source", p); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := readPHPWorkerOperations(s.phpWorkerOperationsDir()); e == nil {
				t.Fatal("corrupt record accepted")
			}
		})
	}
}
func TestPHPWorkerStopUsesConfiguredGraceInsteadOfGenericCommandDeadline(t *testing.T) {
	stopped := false
	s := New(Config{Run: func(ctx context.Context, binary string, args ...string) (string, error) {
		if !stopped || len(args) != 2 || args[0] != "disable" {
			t.Fatal("unlinked before stopping", args)
		}
		return "", nil
	}, RunWait: func(ctx context.Context, wait time.Duration, binary string, args ...string) (string, error) {
		if wait != 130*time.Second || binary != "/usr/bin/systemctl" || len(args) != 2 || args[0] != "stop" {
			t.Fatal(wait, binary, args)
		}
		stopped = true
		return "", nil
	}})
	v := operationWorker()
	v.StopSeconds = 120
	if e := s.stopPHPWorker(context.Background(), v); e != nil {
		t.Fatal(e)
	}
}

func TestPHPWorkerRunningMutationFailsSiteChangeBeforeLifecycleLock(t *testing.T) {
	s := New(Config{StateDir: t.TempDir()})
	v := operationWorker()
	op := core.PHPWorkerOperation{ID: core.ID(), SiteID: v.SiteID, WorkerID: v.ID, State: "running", Action: "stop", CreatedAt: core.Now()}
	if e := s.savePHPWorkerOperation(phpWorkerOperationRecord{PHPWorkerOperation: op, Input: v}); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, e := s.Apply(ctx, core.ApplyRequest{})
	if e == nil || !result.Restored || ctx.Err() != nil {
		t.Fatal(result, e, ctx.Err())
	}
}
