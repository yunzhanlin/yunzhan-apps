//go:build linux

package executor

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestProgramQueueIDSBatchNativeActualReadOnlyCompleteUpgradeGuard(t *testing.T) {
	anchor := os.Getenv("PANEL_NATIVE_QUEUE_OBSERVATION_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit closed isolated read-only QA observations only; no programme installer")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/native-queue-observation24bmbh-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) ||
		threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("actual private fixed QA observation cohort is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := programQueueIDSVerifyIdleUnits(ctx, programQueueIDSReadCommand); err != nil {
		t.Fatal("actual original complete three unit observation refused", err)
	}
	// This uses the real unchanged entrypoint with its own original global5s
	// context, both complete filesystem/Core/native inventories and real locks.
	// No earlier failed programme install is retried or relabelled by this test.
	for attempt := 0; attempt < 3; attempt++ {
		started := time.Now()
		if err := CheckProgramUpgradeQueues(); err != nil {
			t.Fatal("complete original native upgrade guard refused", attempt, err)
		}
		t.Logf("NATIVE_QUEUE_COMPLETE_OBSERVATION original_global_deadline=5s attempt=%d elapsed=%s no_installer_or_service_action=true", attempt, time.Since(started))
	}
}
