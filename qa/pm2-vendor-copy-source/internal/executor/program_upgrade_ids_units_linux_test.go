//go:build linux

package executor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func queueIDSUnitsFixture() []string {
	return []string{strings.TrimSuffix(programQueueIDSUnitFixture(threatIDSService), "\n"), strings.TrimSuffix(programQueueIDSUnitFixture("panel-network-ids-check.service"), "\n"), strings.TrimSuffix(programQueueIDSUnitFixture("panel-network-ids-recover.service"), "\n")}
}

func TestProgramQueueIDSCompleteThreeUnitSnapshotPreservesAllOldPredicates(t *testing.T) {
	blocks := queueIDSUnitsFixture()
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		raw := strings.Join([]string{blocks[order[0]], blocks[order[1]], blocks[order[2]]}, "\n\n") + "\n"
		if !programQueueIDSIdleUnits(raw) {
			t.Fatal("complete original set refused", order)
		}
	}
	for index := range blocks {
		for _, edit := range [][2]string{{"LoadState=loaded", "LoadState=not-found"}, {"MainPID=0", "MainPID=123"}, {"Job=", "Job=123 start"}, {"DropInPaths=", "DropInPaths=/foreign.conf"}, {"NeedDaemonReload=no", "NeedDaemonReload=yes"}, {"Transient=no", "Transient=yes"}, {"ExecMainStatus=0", "ExecMainStatus=1"}, {"Job=", "Unknown="}, {"Id=", "Id=foreign-"}, {"FragmentPath=/etc/systemd/system/", "FragmentPath=/run/systemd/system/"}} {
			changed := append([]string(nil), blocks...)
			changed[index] = strings.Replace(changed[index], edit[0], edit[1], 1)
			if programQueueIDSIdleUnits(strings.Join(changed, "\n\n") + "\n") {
				t.Fatal("old strict unit predicate bypassed", index, edit)
			}
		}
		for _, suffix := range []string{"\nMainPID=0", "\nId=panel-network-ids.service", "\nunknown=value"} {
			changed := append([]string(nil), blocks...)
			changed[index] += suffix
			if programQueueIDSIdleUnits(strings.Join(changed, "\n\n") + "\n") {
				t.Fatal("duplicate/unknown field accepted", index, suffix)
			}
		}
	}
	raw := strings.Join(blocks, "\n\n") + "\n"
	for _, bad := range []string{"", strings.TrimSuffix(raw, "\n"), raw + "\n", "\n" + raw, strings.ReplaceAll(raw, "\n", "\r\n"), raw + "\x00", strings.Join(blocks[:2], "\n\n") + "\n", strings.Join([]string{blocks[0], blocks[1], blocks[1]}, "\n\n") + "\n", raw + "\n" + blocks[0] + "\n", strings.Repeat("x", 3*4096+3)} {
		if programQueueIDSIdleUnits(bad) {
			t.Fatal("incomplete, ambiguous or unbounded set accepted")
		}
	}
}

func TestProgramQueueIDSObservationCommandIsStillClosed(t *testing.T) {
	args := programQueueIDSUnitArgs()
	if !programQueueIDSObservationCommand("/usr/bin/systemctl", args) {
		t.Fatal("fixed original three unit observation refused")
	}
	for _, unit := range []string{threatIDSService, "panel-network-ids-check.service", "panel-network-ids-recover.service"} {
		if !programQueueIDSObservationCommand("/usr/bin/systemctl", []string{"show", unit, programQueueIDSUnitProperties}) {
			t.Fatal("old fixed readonly observation changed")
		}
	}
	for i := range args {
		changed := append([]string(nil), args...)
		changed[i] = "unknown"
		if programQueueIDSObservationCommand("/usr/bin/systemctl", changed) {
			t.Fatal("observation scope widened", i)
		}
	}
	for _, bad := range [][]string{nil, {"start", threatIDSService}, append(append([]string(nil), args...), "foreign.service"), args[:4], {"show", threatIDSService, "--property=MainPID"}} {
		if programQueueIDSObservationCommand("/usr/bin/systemctl", bad) {
			t.Fatal("nonfixed command accepted", bad)
		}
	}
	if programQueueIDSObservationCommand("/bin/systemctl", args) {
		t.Fatal("alternate executable accepted")
	}
	args[1] = "mutated"
	if programQueueIDSUnitArgs()[1] != threatIDSService {
		t.Fatal("caller changed subsequent fixed args")
	}
}

func TestProgramQueueIDSFreshSnapshotUsesOneReadAndNeverCachesOrExtendsDeadline(t *testing.T) {
	raw := strings.Join(queueIDSUnitsFixture(), "\n\n") + "\n"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	run := func(got context.Context, name string, args ...string) (string, error) {
		calls++
		if got != ctx || name != "/usr/bin/systemctl" || !reflect.DeepEqual(args, programQueueIDSUnitArgs()) {
			t.Fatal("context/command changed")
		}
		if calls > 1 {
			return strings.Replace(raw, "MainPID=0", "MainPID=99", 1), nil
		}
		return raw, nil
	}
	if err := programQueueIDSVerifyIdleUnits(ctx, run); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	if programQueueIDSVerifyIdleUnits(ctx, run) == nil || calls != 2 {
		t.Fatal("fresh second native observation was replaced with cached authority", calls)
	}
	cancel()
	if programQueueIDSVerifyIdleUnits(ctx, run) == nil || calls != 2 {
		t.Fatal("cancelled observation ran or gained a new deadline")
	}
	if programQueueIDSVerifyIdleUnits(context.Background(), nil) == nil || programQueueIDSVerifyIdleUnits(nil, run) == nil {
		t.Fatal("missing original context/observer admitted")
	}
	for _, failed := range []bool{false, true} {
		active, stop := context.WithCancel(t.Context())
		err := programQueueIDSVerifyIdleUnits(active, func(context.Context, string, ...string) (string, error) {
			stop()
			if failed {
				return raw, errors.New("original native command failed")
			}
			return raw, nil
		})
		if err == nil {
			t.Fatal("command failure/cancellation ignored")
		}
	}
}
