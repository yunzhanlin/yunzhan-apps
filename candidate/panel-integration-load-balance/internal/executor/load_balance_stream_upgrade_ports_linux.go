//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"local/panel/internal/loadbalancestream"
	"local/panel/internal/upgraderead"
)

var streamProgrammeWriters = [...]string{"panel.service", "panel-executor.service", "panel-terminal.service", "panel-terminal-root.service"}

func streamProgrammeStoppedWriter(raw, unit string) bool {
	if len(raw) == 0 || len(raw) > 16384 || !utf8.ValidString(raw) || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	want := map[string]string{"Id": unit, "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "ControlGroup": "", "Result": "success"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		if key == "UnitFileState" {
			if value != "enabled" && value != "disabled" && value != "static" && value != "indirect" && value != "enabled-runtime" {
				return false
			}
		} else if expected, known := want[key]; !known || expected != value {
			return false
		}
	}
	return len(seen) == len(want)+1
}

func streamProgrammeNoWriterJobs(raw string) bool {
	if len(raw) > 1<<20 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) > 4096 {
		return false
	}
	seen := map[string]bool{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || seen[fields[0]] {
			return false
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != fields[0] {
			return false
		}
		seen[fields[0]] = true
		for _, unit := range append(streamProgrammeWriters[:], "panel-mysql-overwrite-recovery.timer", "panel-mysql-overwrite-recovery.service") {
			if fields[1] == unit {
				return false
			}
		}
	}
	return true
}

func streamProgrammeWritersStopped(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return loadbalancestream.ErrService
	}
	for _, unit := range streamProgrammeWriters {
		raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,ControlGroup,Result")
		if err != nil || !streamProgrammeStoppedWriter(raw, unit) {
			return loadbalancestream.ErrService
		}
		if _, err := os.Lstat("/sys/fs/cgroup/system.slice/" + unit); !errors.Is(err, os.ErrNotExist) {
			return loadbalancestream.ErrService
		}
	}
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager")
	if err != nil || !streamProgrammeNoWriterJobs(raw) {
		return loadbalancestream.ErrService
	}
	return ctx.Err()
}

// The normal listener census is mandatory while Core is online. Only this
// SELECT-only programme reader can validate an immutable historical plan while
// all four writers are strictly stopped under the actual parent's two EX
// leases. These fixed ports are recorded syntax, never a live listener claim
// or authority to allocate/start/reload anything. Mutation readers always use
// observeLoadBalanceStreamControlPorts directly.
func streamProgrammeReadPorts(ctx context.Context) ([]int, *upgraderead.MaintenanceRead, error) {
	ports, liveErr := observeLoadBalanceStreamControlPorts(ctx)
	if liveErr == nil {
		return ports, nil, nil
	}
	w, err := upgraderead.HoldMaintenanceRead(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("current Core ports or owned stopped maintenance: %w", errors.Join(liveErr, err))
	}
	if err := streamProgrammeWritersStopped(ctx); err != nil {
		w.Close()
		return nil, nil, err
	}
	if err := w.Current(ctx); err != nil {
		w.Close()
		return nil, nil, err
	}
	return []int{19100, 19102, 19080}, w, nil
}
