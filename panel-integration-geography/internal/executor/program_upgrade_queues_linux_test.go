//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func programQueueFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("native root ownership preflight; no ownership override on nonroot hosts")
	}
	return t.TempDir()
}
func writeProgramQueueFixture(t *testing.T, root, relative, id string, v any) string {
	t.Helper()
	p := filepath.Join(root, relative, id+".json")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func programQueuePHPFixture(state string) phpWorkerOperationRecord {
	w := operationWorker()
	return phpWorkerOperationRecord{PHPWorkerOperation: core.PHPWorkerOperation{ID: core.ID(), SiteID: w.SiteID, WorkerID: w.ID, Action: "stop", State: state, CreatedAt: core.Now(), UpdatedAt: core.Now()}, Input: w}
}
func programQueueTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		s := info.Sys().(*syscall.Stat_t)
		row, _ := json.Marshal([]any{s.Dev, s.Ino, s.Mode, s.Uid, s.Gid, s.Nlink, s.Size, s.Mtim, s.Ctim})
		out[p] = string(row)
		if info.Mode().IsRegular() {
			raw, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			out[p] += "|" + core.Hash(string(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProgramUpgradeQueuesEmptyMissingNamespacesAreReadonly(t *testing.T) {
	root := programQueueFixture(t)
	before := programQueueTree(t, root)
	if err := checkProgramUpgradeQueues(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("read-only missing preflight created state")
	}
}

func TestProgramUpgradeQueuesNativeUnitStateAndCompletedRecoveryAreDistinct(t *testing.T) {
	id := core.ID()
	unit := "panel-install@" + id + ".service"
	for _, row := range []struct {
		load, active, sub string
		want              bool
	}{{"loaded", "inactive", "dead", false}, {"loaded", "active", "running", true}, {"loaded", "active", "exited", true}, {"loaded", "activating", "start", true}, {"loaded", "deactivating", "stop-sigterm", true}, {"loaded", "failed", "failed", true}, {"masked", "inactive", "dead", true}, {"not-found", "inactive", "dead", true}} {
		t.Run(row.load+"-"+row.active+"-"+row.sub, func(t *testing.T) {
			err := decodeProgramQueueUnits(unit + " " + row.load + " " + row.active + " " + row.sub + " description\n")
			if (err != nil) != row.want {
				t.Fatal(err)
			}
		})
	}
	if err := decodeProgramQueueUnits("panel-nginx-recovery.service loaded active exited Completed boot recovery\n"); err != nil {
		t.Fatal("completed RemainAfterExit recovery incorrectly considered running", err)
	}
	if err := decodeProgramQueueUnits("panel-nginx-recovery.service loaded active running Live recovery\n"); err == nil {
		t.Fatal("actual running recovery ignored")
	}
}
func TestProgramUpgradeQueuesNativeInventoryNeverAcceptsPartialUnknownOrDuplicateRows(t *testing.T) {
	row := "panel-pm2-deploy@" + core.ID() + ".service loaded inactive dead Done\n"
	for _, raw := range []string{row + row, "panel.service loaded active running Panel\n", "panel-install@bad/path.service loaded inactive dead Bad\n", "UNIT LOAD ACTIVE SUB DESCRIPTION\n", strings.Repeat("x", (64<<10)+1), "\x00", strings.Repeat(row, 1025)} {
		if decodeProgramQueueUnits(raw) == nil {
			t.Fatal("invalid unit inventory accepted")
		}
	}
	if err := decodeProgramQueueUnits(""); err != nil {
		t.Fatal("empty successful native enumeration", err)
	}
}
func TestProgramUpgradeQueuesNativePendingJobsRefuseEvenWithNoActiveUnit(t *testing.T) {
	for _, prefix := range programQueueUnitPrefixes {
		row := "1 " + prefix + core.ID() + ".service start waiting\n"
		if decodeProgramQueueJobs(row) == nil {
			t.Fatal("waiting native operation ignored", prefix)
		}
	}
	if err := decodeProgramQueueJobs("2 unrelated.service start running\n"); err != nil {
		t.Fatal("unrelated host job is not a panel upgrade target", err)
	}
	for _, row := range []string{"0 unrelated.service start waiting\n", "01 unrelated.service start waiting\n", "1 unrelated.service start\n", "1 unrelated.service start waiting\n1 other.service stop running\n", "JOB UNIT TYPE STATE\n"} {
		if decodeProgramQueueJobs(row) == nil {
			t.Fatal("unverifiable pending inventory accepted")
		}
	}
}
func TestProgramUpgradeQueuesNativeObserverOnlyReadsFixedBoundedCommands(t *testing.T) {
	calls := 0
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		calls++
		if name != "/usr/bin/systemctl" || len(args) < 1 || args[0] != "list-units" && args[0] != "list-jobs" {
			t.Fatal("observer reached a mutation", name, args)
		}
		return "", nil
	}
	if err := checkProgramUpgradeNativeUnits(context.Background(), run); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
	for _, point := range []int{1, 2} {
		calls = 0
		run = func(context.Context, string, ...string) (string, error) {
			calls++
			if calls == point {
				return "", errors.New("owned inventory failure")
			}
			return "", nil
		}
		if checkProgramUpgradeNativeUnits(context.Background(), run) == nil {
			t.Fatal("command failure treated as an empty inventory")
		}
	}
}
func TestProgramUpgradeQueuesPM2OriginalLedgerNotStaleLatestLocatorOwnsState(t *testing.T) {
	for _, state := range []string{"queued", "running", "switching", "needs_attention", "succeeded", "failed"} {
		t.Run(state, func(t *testing.T) {
			root := programQueueFixture(t)
			relative := "etc/panel/security-apps/modules/pm2-manager/deployments"
			job := pm2Deployment{ID: core.ID(), AppID: "owned-app", SiteID: core.ID(), Revision: 1, State: state, CreatedAt: core.Now(), FinishedAt: core.Now(), PackageSHA: strings.Repeat("a", 64), LockSHA: strings.Repeat("b", 64)}
			view := publicPM2Deployment(job)
			view.State = "queued"
			view.FinishedAt = "" // Existing producer intentionally leaves this locator unchanged.
			writeProgramQueueFixture(t, root, relative, job.ID, job)
			writeProgramQueueFixture(t, root, relative, job.AppID+"-latest", view)
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != (state != "succeeded" && state != "failed") {
				t.Fatal(state, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("preflight repaired PM2 locator or original ledger")
			}
		})
	}
}
func TestProgramUpgradeQueuesPM2MissingOrChangedOriginalUnknownEntriesAndUnsafeArchiveRefuse(t *testing.T) {
	for _, kind := range []string{"missing-original", "changed-binding", "unknown", "unsafe-log", "unsafe-archive", "unknown-state", "missing-finish"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			relative := "etc/panel/security-apps/modules/pm2-manager/deployments"
			job := pm2Deployment{ID: core.ID(), AppID: "owned-app", SiteID: core.ID(), Revision: 1, State: "succeeded", CreatedAt: core.Now(), FinishedAt: core.Now(), PackageSHA: strings.Repeat("a", 64), LockSHA: strings.Repeat("b", 64)}
			view := publicPM2Deployment(job)
			if kind == "changed-binding" {
				view.SiteID = core.ID()
			}
			if kind == "unknown-state" {
				job.State = "done"
			}
			if kind == "missing-finish" {
				job.FinishedAt = ""
			}
			if kind != "missing-original" {
				writeProgramQueueFixture(t, root, relative, job.ID, job)
			}
			p := writeProgramQueueFixture(t, root, relative, job.AppID+"-latest", view)
			dir := filepath.Dir(p)
			switch kind {
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unknown.txt"), []byte("own"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-log":
				if err := os.WriteFile(filepath.Join(dir, job.ID+".npm.log"), []byte("own"), 0644); err != nil {
					t.Fatal(err)
				}
			case "unsafe-archive":
				if err := os.Mkdir(filepath.Join(dir, "archive"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkProgramUpgradeQueues(context.Background(), root); err == nil {
				t.Fatal("unverified PM2 state considered drained")
			}
		})
	}
	root := programQueueFixture(t)
	r := programQueueReader{ctx: context.Background(), root: root}
	relative := "etc/panel/security-apps/modules/pm2-manager/deployments"
	if err := os.MkdirAll(filepath.Join(root, relative), 0700); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 1025; n++ {
		if err := os.WriteFile(filepath.Join(root, relative, fmt.Sprintf("record-%04d.json", n)), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if r.pm2Deployments() == nil {
		t.Fatal("PM2 inventory truncated instead of refusing")
	}
}
func TestProgramUpgradeQueuesPHPAllTerminalAndPendingStates(t *testing.T) {
	for _, state := range []string{"queued", "running", "needs_attention", "succeeded", "failed", "resolved"} {
		t.Run(state, func(t *testing.T) {
			root := programQueueFixture(t)
			v := programQueuePHPFixture(state)
			writeProgramQueueFixture(t, root, "var/lib/panel-executor/php-worker-operations", v.ID, v)
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != phpWorkerOperationReference(state) {
				t.Fatal(state, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("preflight repaired or replayed PHP record")
			}
		})
	}
}
func TestProgramUpgradeQueuesIDSDoesNotStartOrRecoverWorker(t *testing.T) {
	for _, state := range []string{"queued", "running", "needs-attention", "succeeded", "failed"} {
		t.Run(state, func(t *testing.T) {
			root := programQueueFixture(t)
			o := core.NetworkIDSOperation{ID: core.ID(), Action: "ids-start", Input: core.NetworkIDSOperationInput{ExpectedRevision: 3}, State: state, CreatedAt: core.Now(), UpdatedAt: core.Now()}
			if state == "failed" || state == "needs-attention" {
				o.Error = "owned retained fixture failure"
			}
			writeProgramQueueFixture(t, root, "var/lib/panel-executor/network-ids-operations", o.ID, threatIDSOperationRecord{Format: 1, Operation: o})
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			want := state == "queued" || state == "running" || state == "needs-attention"
			if (err != nil) != want {
				t.Fatal(state, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("IDS preflight changed persistent receipt")
			}
		})
	}
}
func TestProgramUpgradeQueuesLocalPlansValidateEveryState(t *testing.T) {
	for _, state := range []string{"running", "interrupted", "pending", "paused", "paused-error", "succeeded", "conflicts", "failed", "unknown"} {
		t.Run(state, func(t *testing.T) {
			root := programQueueFixture(t)
			v := moduleSyncPlan{ID: "local-plan", SiteID: core.ID(), TargetSiteID: core.ID(), Interval: 60, Revision: 1, LastState: state}
			writeProgramQueueFixture(t, root, "etc/panel/security-apps/modules/files-sync/plans", v.ID, v)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != (state == "running" || state == "interrupted" || state == "unknown") {
				t.Fatal(state, err)
			}
		})
	}
}
func TestProgramUpgradeQueuesRemoteReservationIsNotEmptyEvenWhenPaused(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "retained-pending"}[pending], func(t *testing.T) {
			root := programQueueFixture(t)
			v := remoteSyncPlan{ID: "remote-plan", TargetID: "remote-target", SiteID: core.ID(), Revision: 1, TargetRevision: 1, SpecSHA: strings.Repeat("a", 64), Interval: 60, LastState: "paused", Excludes: []string{}}
			if pending {
				v.PendingJobID = core.ID()
			}
			writeProgramQueueFixture(t, root, "etc/panel/security-apps/modules/files-sync/remote/plans", v.ID, v)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != pending {
				t.Fatal(err)
			}
		})
	}
}
func TestProgramUpgradeQueuesRemoteJobsAndCheckpointsRetainUncertainEvidence(t *testing.T) {
	for _, state := range []string{"queued", "running", "interrupted", "succeeded", "failed", "conflicts", "recovered"} {
		t.Run(state, func(t *testing.T) {
			root := programQueueFixture(t)
			v := remoteSyncJob{ID: core.ID(), TargetID: "remote-target", SiteID: core.ID(), Revision: 1, SpecSHA: strings.Repeat("a", 64), State: state, CreatedAt: core.Now()}
			writeProgramQueueFixture(t, root, "etc/panel/security-apps/modules/files-sync/remote/jobs", v.ID, v)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != (state == "queued" || state == "running" || state == "interrupted") {
				t.Fatal(err)
			}
		})
	}
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "checkpoint-terminal", true: "checkpoint-pending"}[pending], func(t *testing.T) {
			root := programQueueFixture(t)
			v := remoteSyncCheckpoint{TargetID: "remote-target", SiteID: core.ID(), SpecSHA: strings.Repeat("a", 64), Files: map[string]moduleFile{}}
			if pending {
				v.Pending = &remoteSyncPending{ID: core.ID(), JobID: core.ID(), Path: "fixture.txt"}
			}
			writeProgramQueueFixture(t, root, "etc/panel/security-apps/modules/files-sync/remote/checkpoints", v.TargetID, v)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != pending {
				t.Fatal(err)
			}
		})
	}
}
func TestProgramUpgradeQueuesClosedJSONRejectsDuplicatesCaseEscapesUnknownNullAndTrailing(t *testing.T) {
	for _, raw := range []string{`{"id":"a","id":"b"}`, `{"id":"a","ID":"b"}`, `{"id":"a","\u0069d":"b"}`, `{"unknown":1}`, `null`, `[]`, `{"id":"a"} {}`, `{"id":"a"`, string([]byte{'{', '"', 'i', 'd', '"', ':', '"', 255, '"', '}'})} {
		var v struct {
			ID string `json:"id"`
		}
		if decodeProgramQueueJSON([]byte(raw), &v) == nil {
			t.Fatal("invalid closed record accepted", raw)
		}
	}
	var v struct {
		Items []string `json:"items"`
	}
	if err := decodeProgramQueueJSON([]byte(`{"items":null}`), &v); err != nil {
		t.Fatal("legacy nil slice changed", err)
	}
}

func TestProgramUpgradeQueuesJSONStructUnicodeFoldingDoesNotFoldDynamicPaths(t *testing.T) {
	type item struct {
		State string `json:"state"`
	}
	type record struct {
		Key   string          `json:"key"`
		Items map[string]item `json:"items"`
	}
	for _, raw := range []string{
		`{"key":"one","\u212Aey":"two"}`,
		`{"items":{"page.php":{"state":"running","\u017Ftate":"succeeded"}}}`,
		`{"items":{"page.php":{"state":"running"},"\u0070age.php":{"state":"succeeded"}}}`,
	} {
		var v record
		if decodeProgramQueueJSON([]byte(raw), &v) == nil {
			t.Fatal("equivalent struct or exact escaped map key conflict accepted", raw)
		}
	}
	var v record
	legitimate := `{"key":"original","items":{"Page.php":{"state":"running"},"page.php":{"state":"succeeded"},"ſite.php":{"state":"running"},"site.php":{"state":"succeeded"}}}`
	if err := decodeProgramQueueJSON([]byte(legitimate), &v); err != nil || len(v.Items) != 4 || v.Items["Page.php"].State != "running" || v.Items["page.php"].State != "succeeded" {
		t.Fatal("distinct case-sensitive website path was lost or rejected", err, v)
	}
}
func TestProgramUpgradeQueuesCorruptionNeverMeansEmpty(t *testing.T) {
	for _, kind := range []string{"unknown-name", "duplicate", "unknown-field", "truncated", "wrong-id", "unknown-state", "wrong-site", "wrong-runtime", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			v := programQueuePHPFixture("succeeded")
			relative := "var/lib/panel-executor/php-worker-operations"
			if kind == "wrong-id" {
				v.ID = core.ID()
			}
			if kind == "unknown-state" {
				v.State = "done"
			}
			if kind == "wrong-site" {
				v.Input.SiteID = core.ID()
			}
			if kind == "wrong-runtime" {
				v.Input.ObservedReleaseID = "nginx-system"
			}
			p := writeProgramQueueFixture(t, root, relative, core.ID(), v)
			if kind != "wrong-id" {
				p = writeProgramQueueFixture(t, root, relative, v.ID, v)
				entries, _ := os.ReadDir(filepath.Dir(p))
				for _, entry := range entries {
					if entry.Name() != v.ID+".json" {
						if err := os.Remove(filepath.Join(filepath.Dir(p), entry.Name())); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			raw, _ := os.ReadFile(p)
			switch kind {
			case "unknown-name":
				if err := os.Rename(p, filepath.Join(filepath.Dir(p), ".panel-write-unfinished")); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				raw = bytesAppendObject(raw, `"state":"succeeded"`)
			case "unknown-field":
				raw = bytesAppendObject(raw, `"unknown":1`)
			case "truncated":
				raw = raw[:len(raw)-1]
			case "oversized":
				raw = []byte(strings.Repeat(" ", (128<<10)+1))
			}
			if kind != "unknown-name" {
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, root)
			if err := checkProgramUpgradeQueues(context.Background(), root); err == nil {
				t.Fatal("corrupt record reported drained")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("corruption erased or repaired")
			}
		})
	}
}
func bytesAppendObject(raw []byte, field string) []byte {
	return []byte(strings.TrimSuffix(string(raw), "}") + "," + field + "}")
}
func TestProgramUpgradeQueuesUnsafeParentsAndFileIdentitiesFailClosed(t *testing.T) {
	for _, kind := range []string{"public-directory", "foreign-directory", "symlink-directory", "public-file", "foreign-file", "symlink-file", "hardlink-file", "fifo", "setuid-file"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			v := programQueuePHPFixture("succeeded")
			p := writeProgramQueueFixture(t, root, "var/lib/panel-executor/php-worker-operations", v.ID, v)
			dir := filepath.Dir(p)
			switch kind {
			case "public-directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "foreign-directory":
				if err := os.Chown(dir, 12345, 12345); err != nil {
					t.Fatal(err)
				}
			case "symlink-directory":
				if err := os.Rename(dir, dir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-original", dir); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "foreign-file":
				if err := os.Chown(p, 12345, 12345); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				if err := os.Rename(p, p+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+".original", p); err != nil {
					t.Fatal(err)
				}
			case "hardlink-file":
				if err := os.Link(p, filepath.Join(root, "owned-alias")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(p, 0600); err != nil {
					t.Fatal(err)
				}
			case "setuid-file":
				if err := os.Chmod(p, 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkProgramUpgradeQueues(context.Background(), root); err == nil {
				t.Fatal("unsafe identity considered an empty queue")
			}
		})
	}
}
func TestProgramUpgradeQueuesCompleteCapacityBoundaryAndNoPartialList(t *testing.T) {
	root := programQueueFixture(t)
	relative := "etc/panel/security-apps/modules/files-sync/plans"
	for n := 0; n < 32; n++ {
		id := core.ID()
		v := moduleSyncPlan{ID: id, SiteID: core.ID(), TargetSiteID: core.ID(), Interval: 60, Revision: 1, LastState: "paused"}
		writeProgramQueueFixture(t, root, relative, id, v)
	}
	if err := checkProgramUpgradeQueues(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	v := moduleSyncPlan{ID: core.ID(), SiteID: core.ID(), TargetSiteID: core.ID(), Interval: 60, Revision: 1, LastState: "running"}
	writeProgramQueueFixture(t, root, relative, v.ID, v)
	if err := checkProgramUpgradeQueues(context.Background(), root); err == nil {
		t.Fatal("33rd running record hidden by first32 truncation")
	}
}
func TestProgramUpgradeQueuesLateReplacementNewNamespaceAndCancellationAreNotDrainProof(t *testing.T) {
	for _, kind := range []string{"replace-record", "replace-directory", "create-missing", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := programQueueReader{ctx: ctx, root: root}
			relative := "var/lib/panel-executor/php-worker-operations"
			var p string
			if kind != "create-missing" {
				v := programQueuePHPFixture("succeeded")
				p = writeProgramQueueFixture(t, root, relative, v.ID, v)
			}
			if err := r.records(relative, 1024, 128<<10, checkProgramQueuePHP); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "replace-record":
				raw, _ := os.ReadFile(p)
				if err := os.Rename(p, p+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "replace-directory":
				dir := filepath.Dir(p)
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			case "create-missing":
				v := programQueuePHPFixture("running")
				writeProgramQueueFixture(t, root, relative, v.ID, v)
			case "cancel":
				cancel()
			}
			if err := r.unchanged(); err == nil {
				t.Fatal("late change reported drained")
			}
		})
	}
	root := programQueueFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkProgramUpgradeQueues(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
