//go:build linux

package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamControlPortPIDMustBeActualCurrentPanelUnitNotConfiguredText(t *testing.T) {
	raw := "Id=panel.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=219\nControlPID=0\n"
	if pid, err := decodeStreamCoreListenerOwner([]byte(raw)); err != nil || pid != 219 {
		t.Fatal("actual complete manager identity rejected", err)
	}
	for _, bad := range []string{"", raw[:len(raw)-1], raw + "MainPID=220\n", strings.Replace(raw, "panel.service", "other.service", 1), strings.Replace(raw, "active\n", "inactive\n", 1), strings.Replace(raw, "running", "dead", 1), strings.Replace(raw, "219", "0219", 1), strings.Replace(raw, "219", "1", 1), strings.Replace(raw, "ControlPID=0", "ControlPID=222", 1), raw + "ConfiguredPort=19100\n"} {
		if _, err := decodeStreamCoreListenerOwner([]byte(bad)); err == nil {
			t.Fatal("claimed/stale/ambiguous Core identity selected control ports")
		}
	}
}
