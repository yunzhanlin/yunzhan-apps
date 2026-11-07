//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func programQueueIDSRecoveryFixture() ([]threatIDSOperationRecord, time.Time) {
	now := time.Date(2026, 10, 21, 20, 0, 5, 0, time.UTC)
	old := threatIDSOperationRecord{Format: 1, Operation: core.NetworkIDSOperation{ID: core.ID(), Action: "ids-start", Input: core.NetworkIDSOperationInput{ExpectedRevision: 1}, State: "needs-attention", Error: errThreatIDSLegacyCapture.Error(), CreatedAt: "2026-10-21T20:00:00Z", UpdatedAt: "2026-10-21T20:00:01.9Z"}}
	recovery := threatIDSOperationRecord{Format: 1, Operation: core.NetworkIDSOperation{ID: core.ID(), Action: "ids-recover", Input: core.NetworkIDSOperationInput{ExpectedRevision: 2}, State: "succeeded", CreatedAt: "2026-10-21T20:00:02Z", UpdatedAt: "2026-10-21T20:00:03Z"}}
	return []threatIDSOperationRecord{old, recovery}, now
}

func TestProgramUpgradeIDSRecoveryRequiresExactDeclineLaterExplicitRecoveryAndHigherRevision(t *testing.T) {
	for _, scenario := range []string{"valid", "boot-enable", "no-recovery", "wrong-error", "wrong-action", "boot-disable", "queued", "running", "unknown", "unfinished-recovery", "failed-recovery", "old-revision", "same-revision", "earlier", "same-time", "future-created", "future-updated", "ambiguous", "later-unknown-error", "nanosecond-order"} {
		t.Run(scenario, func(t *testing.T) {
			items, now := programQueueIDSRecoveryFixture()
			switch scenario {
			case "boot-enable", "boot-disable":
				items[0].Operation.Action = "ids-boot"
				enabled := scenario == "boot-enable"
				items[0].Operation.Input.Enabled = &enabled
			case "no-recovery":
				items = items[:1]
			case "wrong-error":
				items[0].Operation.Error += " changed"
			case "wrong-action":
				items[0].Operation.Action = "ids-stop"
			case "queued", "running", "unknown":
				items[0].Operation.State, items[0].Operation.Error = scenario, ""
			case "unfinished-recovery":
				items[1].Operation.State, items[1].Operation.Error = "needs-attention", "dispatched, not recovered"
			case "failed-recovery":
				items[1].Operation.State, items[1].Operation.Error = "failed", "not recovered"
			case "old-revision":
				items[1].Operation.Input.ExpectedRevision = 0
			case "same-revision":
				items[1].Operation.Input.ExpectedRevision = 1
			case "earlier":
				items[1].Operation.CreatedAt = "2026-10-21T20:00:01Z"
			case "same-time":
				items[1].Operation.CreatedAt = items[0].Operation.UpdatedAt
			case "future-created":
				items[1].Operation.CreatedAt, items[1].Operation.UpdatedAt = "2026-10-21T20:01:00Z", "2026-10-21T20:01:01Z"
			case "future-updated":
				items[1].Operation.UpdatedAt = "2026-10-21T20:01:00Z"
			case "ambiguous":
				other := items[1]
				other.Operation.ID = core.ID()
				other.Operation.Input.ExpectedRevision++
				items = append(items, other)
			case "later-unknown-error":
				other := items[0]
				other.Operation.ID = core.ID()
				other.Operation.Error = "unknown native result"
				other.Operation.UpdatedAt = "2026-10-21T20:00:04Z"
				items = append(items, other)
			case "nanosecond-order":
				// Lexicographic RFC3339 comparison would incorrectly reject this.
				items[0].Operation.UpdatedAt = "2026-10-21T20:00:02Z"
				items[1].Operation.CreatedAt = "2026-10-21T20:00:02.001Z"
			}
			revision, err := programQueueIDSRecoveryRevision(items, now)
			want := scenario == "valid" || scenario == "boot-enable" || scenario == "nanosecond-order"
			if (err == nil) != want || want && revision != 2 {
				t.Fatal(revision, err)
			}
		})
	}
}

type programQueueIDSLease struct{ closed bool }

func (l *programQueueIDSLease) Close() error { l.closed = true; return nil }

func TestProgramUpgradeIDSRecoveryCompletePrivateInventoryReadonlyAndRaceRefusal(t *testing.T) {
	for _, scenario := range []string{"valid", "scope-failure", "nil-lease", "changed", "mode", "symlink", "hardlink", "unknown-file", "partial", "pending", "config-pending", "runtime-pending", "transaction-link", "transaction-partial", "transaction-stage"} {
		t.Run(scenario, func(t *testing.T) {
			root := programQueueFixture(t)
			items, _ := programQueueIDSRecoveryFixture()
			var original string
			for _, item := range items {
				path := writeProgramQueueFixture(t, root, "var/lib/panel-executor/network-ids-operations", item.Operation.ID, item)
				if original == "" {
					original = path
				}
			}
			switch scenario {
			case "mode":
				os.Chmod(original, 0644)
			case "symlink":
				os.Rename(original, filepath.Join(root, "retained"))
				os.Symlink(filepath.Join(root, "retained"), original)
			case "hardlink":
				os.Link(original, filepath.Join(root, "retained"))
			case "unknown-file":
				os.WriteFile(filepath.Join(filepath.Dir(original), "unfinished.tmp"), []byte("retained"), 0600)
			case "partial":
				os.WriteFile(original, []byte(`{"format":1`), 0600)
			case "pending":
				other := items[1]
				other.Operation.ID = core.ID()
				other.Operation.State = "queued"
				writeProgramQueueFixture(t, root, "var/lib/panel-executor/network-ids-operations", other.Operation.ID, other)
			case "config-pending", "runtime-pending", "transaction-link", "transaction-partial", "transaction-stage":
				family := "config-transactions"
				if scenario == "runtime-pending" {
					family = "runtime-transactions"
				}
				dir := filepath.Join(root, "etc/panel/security-apps/modules/network-threat-detection", family)
				if err := os.MkdirAll(dir, 0750); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "transaction-link":
					os.Rename(dir, filepath.Join(root, "retained-transactions"))
					os.Symlink(filepath.Join(root, "retained-transactions"), dir)
				case "transaction-partial":
					os.WriteFile(filepath.Join(dir, core.ID()+".json"), []byte(`{"format":2`), 0600)
				case "transaction-stage":
					os.WriteFile(filepath.Join(dir, "unfinished.tmp"), []byte("retained"), 0600)
				default:
					os.WriteFile(filepath.Join(dir, "pending.json"), []byte("retained"), 0600)
				}
			}
			before := programQueueTree(t, root)
			r := programQueueReader{ctx: context.Background(), root: root}
			lease, called := &programQueueIDSLease{}, 0
			err := r.idsOperations(func(ctx context.Context, got string, revision int64) (io.Closer, error) {
				called++
				if got != root || revision != 2 || ctx.Err() != nil {
					t.Fatal("scope binding changed")
				}
				if scenario == "scope-failure" {
					return nil, errors.New("owned native identity mismatch")
				}
				if scenario == "nil-lease" {
					return nil, nil
				}
				if scenario == "changed" {
					os.Chmod(original, 0640)
				}
				return lease, nil
			})
			if (err == nil) != (scenario == "valid") {
				t.Fatal(err)
			}
			if scenario == "valid" && (called != 1 || lease.closed || len(r.readLeases) != 1) {
				t.Fatal("scope lease not held through final snapshot")
			}
			for _, l := range r.readLeases {
				l.Close()
			}
			if scenario != "changed" && !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("read-only check changed original evidence")
			}
			if scenario == "valid" {
				data, _ := os.ReadFile(original)
				if !strings.Contains(string(data), `"state":"needs-attention"`) {
					t.Fatal("old refusal was relabelled")
				}
			}
		})
	}
}

func programQueueIDSUnitFixture(unit string) string {
	active, sub, state := "active", "exited", "static"
	if unit == threatIDSService {
		active, sub, state = "inactive", "dead", "disabled"
	}
	return "Id=" + unit + "\nLoadState=loaded\nActiveState=" + active + "\nSubState=" + sub + "\nMainPID=0\nJob=\nFragmentPath=/etc/systemd/system/" + unit + "\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\nUnitFileState=" + state + "\nExecMainCode=1\nExecMainStatus=0\n"
}

func TestProgramUpgradeIDSRecoveryLoadedUnitsFailClosed(t *testing.T) {
	for _, unit := range []string{threatIDSService, "panel-network-ids-check.service", "panel-network-ids-recover.service"} {
		raw := programQueueIDSUnitFixture(unit)
		if !programQueueIDSIdleUnit(unit, raw) {
			t.Fatal(unit)
		}
		for _, edit := range [][2]string{{"LoadState=loaded", "LoadState=not-found"}, {"MainPID=0", "MainPID=123"}, {"Job=", "Job=123 start"}, {"DropInPaths=", "DropInPaths=/foreign.conf"}, {"NeedDaemonReload=no", "NeedDaemonReload=yes"}, {"Transient=no", "Transient=yes"}, {"ExecMainStatus=0", "ExecMainStatus=1"}, {"Job=", "Unknown="}, {"Id=" + unit, "Id=foreign.service"}} {
			if programQueueIDSIdleUnit(unit, strings.Replace(raw, edit[0], edit[1], 1)) {
				t.Fatal("unknown/active loaded policy accepted", unit, edit)
			}
		}
		if programQueueIDSIdleUnit(unit, raw+"MainPID=0\n") || programQueueIDSIdleUnit(unit, strings.ReplaceAll(raw, "ActiveState=active", "ActiveState=failed")) && unit != threatIDSService {
			t.Fatal("duplicate/failed unit accepted")
		}
		if unit == threatIDSService && (programQueueIDSIdleUnit(unit, strings.ReplaceAll(raw, "UnitFileState=disabled", "UnitFileState=enabled")) || programQueueIDSIdleUnit(unit, strings.ReplaceAll(raw, "ActiveState=inactive", "ActiveState=active"))) {
			t.Fatal("capture boot/active choice ignored")
		}
	}
	for _, args := range [][]string{{"start", threatIDSService}, {"show", "foreign.service", "--property=MainPID"}, {"reset-failed", threatIDSService}, {"show", threatIDSService, "--property=MainPID"}} {
		if _, err := programQueueIDSReadCommand(context.Background(), "/usr/bin/systemctl", args...); err == nil {
			t.Fatal("nonfixed command reached host", args)
		}
	}
}

func TestProgramUpgradeIDSRecoveryNativeScopeNeverCreatesMissingState(t *testing.T) {
	root := programQueueFixture(t)
	before := programQueueTree(t, root)
	if lease, err := programQueueIDSRecoveredScope(context.Background(), root, 2); err == nil || lease != nil {
		t.Fatal("missing native scope accepted")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("native observation created lock/state")
	}
}
