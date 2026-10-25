//go:build linux

package executor

import (
	"context"
	"errors"
	"reflect"
	"strings"
)

const programQueueIDSUnitProperties = "--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus"

// One fixed observation of the same three units, not a cache or a narrower
// inventory. Every independent original recovery scope still performs a fresh
// command under its existing read lease and the unchanged global5s deadline.
func programQueueIDSUnitArgs() []string {
	return []string{"show", threatIDSService, "panel-network-ids-check.service", "panel-network-ids-recover.service", programQueueIDSUnitProperties}
}

func programQueueIDSObservationCommand(name string, args []string) bool {
	if name != "/usr/bin/systemctl" {
		return false
	}
	if reflect.DeepEqual(args, programQueueIDSUnitArgs()) {
		return true
	}
	return len(args) == 3 && args[0] == "show" && args[2] == programQueueIDSUnitProperties &&
		(args[1] == threatIDSService || args[1] == "panel-network-ids-check.service" || args[1] == "panel-network-ids-recover.service")
}

func programQueueIDSIdleUnits(raw string) bool {
	// The old per-unit4096-byte bound stays exact. The full three-block output
	// must contain each of the three original Ids once, with all13 old properties.
	if len(raw) == 0 || len(raw) > 3*4096+2 || !strings.HasSuffix(raw, "\n") || strings.HasPrefix(raw, "\n") || strings.HasSuffix(raw, "\n\n") || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	blocks := strings.Split(strings.TrimSuffix(raw, "\n"), "\n\n")
	if len(blocks) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, block := range blocks {
		if len(block) == 0 || len(block)+1 > 4096 {
			return false
		}
		unit := ""
		for _, line := range strings.Split(block, "\n") {
			if value, found := strings.CutPrefix(line, "Id="); found {
				if unit != "" {
					return false
				}
				unit = value
			}
		}
		if unit == "" || seen[unit] || !programQueueIDSIdleUnit(unit, block+"\n") {
			return false
		}
		seen[unit] = true
	}
	return seen[threatIDSService] && seen["panel-network-ids-check.service"] && seen["panel-network-ids-recover.service"]
}

func programQueueIDSVerifyIdleUnits(ctx context.Context, run Command) error {
	bad := errors.New("IDS recovered native unit is not trusted and idle; upgrade refused")
	if ctx == nil || ctx.Err() != nil || run == nil {
		return bad
	}
	raw, err := run(ctx, "/usr/bin/systemctl", programQueueIDSUnitArgs()...)
	if err != nil || ctx.Err() != nil || !programQueueIDSIdleUnits(raw) {
		return bad
	}
	return nil
}
