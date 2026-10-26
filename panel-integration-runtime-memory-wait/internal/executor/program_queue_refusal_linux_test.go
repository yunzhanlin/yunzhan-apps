//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestProgramQueueRejectedActualParserInputsRetainExactInventoryAndNeverGrantClosure(t *testing.T) {
	raw := "panel-mysql-overwrite-recovery.service loaded activating start fixture-private-description\n"
	err := decodeProgramQueueUnits(raw)
	if err == nil || err.Error() != "native program operation is active, failed or transitional; upgrade refused" {
		t.Fatal("active recovery was granted closure", err)
	}
	parts := strings.Split(ProgramUpgradeQueueFailureText(err), "\n")
	var value map[string]any
	if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &value) != nil || value["inventory_sha256"] != core.Hash(raw) || value["active_state"] != "activating" || value["sub_state"] != "start" || strings.Contains(parts[1], "fixture-private-description") {
		t.Fatal("original unit refusal was replaced or leaked", parts)
	}
	if decodeProgramQueueUnits("panel-mysql-overwrite-recovery.service loaded inactive dead Completed\n") != nil {
		t.Fatal("unchanged known-inactive contract rejected")
	}
	if ProgramUpgradeQueueFailureText(err) != strings.Join(parts, "\n") {
		t.Fatal("later successful observation replaced original refusal")
	}
	raw = "538093 panel-mysql-overwrite-recovery.service start running\n"
	err = decodeProgramQueueJobs(raw)
	if err == nil || err.Error() != "native program operation is queued; upgrade refused" {
		t.Fatal("queued operation was granted closure", err)
	}
	parts = strings.Split(ProgramUpgradeQueueFailureText(err), "\n")
	if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &value) != nil || value["inventory_sha256"] != core.Hash(raw) || value["job_id"] != "538093" || value["job_state"] != "running" {
		t.Fatal("original job refusal replaced", parts)
	}
	if decodeProgramQueueJobs("") != nil {
		t.Fatal("empty original queue rejected")
	}
	if ProgramUpgradeQueueFailureText(err) != strings.Join(parts, "\n") {
		t.Fatal("later queue read replaced original refusal")
	}
}
