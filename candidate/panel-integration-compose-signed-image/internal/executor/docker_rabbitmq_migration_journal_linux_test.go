//go:build linux

package executor

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func rabbitMQJournalFixture(t *testing.T) (*os.Root, rabbitMQMigrationPlan) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	job, project := core.ID(), core.ID()
	return root, rabbitMQMigrationPlan{
		JobID: job, RequestID: core.ID(), ActorID: core.ID(), ProjectID: project, OriginalContainer: strings.Repeat("1", 64),
		SourceSHA: strings.Repeat("b", 64), OriginalConfigSHA: strings.Repeat("2", 64), OriginalMetaSHA: strings.Repeat("3", 64),
		TargetManifestSHA: strings.Repeat("4", 64), OriginalVolume: "panel_" + project[:12] + "_data",
		CandidateVolume: "panel_rabbitmq_" + job,
	}
}

func TestRabbitMQMigrationJournalReopensAndFencesRollbackAtEndpointPublication(t *testing.T) {
	phaseSequence := []string{"quiesce-intent", "stop-original-intent", "original-stopped", "copy-intent", "copy-verified",
		"bridge-intent", "bridge-stopped", "target-check-intent", "target-verified-offline", "publish-endpoint-intent"}
	for _, stage := range []struct {
		name  string
		last  int
		final string
	}{
		{"during-copy", 4, "original-restored"},
		{"after-candidate-verified", 9, "original-restored"},
		{"endpoint-may-have-accepted-new-messages", 10, "target-published"},
	} {
		t.Run(stage.name, func(t *testing.T) {
			root, plan := rabbitMQJournalFixture(t)
			state, err := prepareRabbitMQMigrationJournal(root, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepareRabbitMQMigrationJournal(root, plan); err == nil {
				t.Fatal("second preparation replaced original plan")
			}
			var copied rabbitMQColdCopyResult
			for _, phase := range phaseSequence[:stage.last] {
				if phase == "copy-verified" {
					copied = rabbitMQColdCopyResult{Files: 10, Directories: 3, Bytes: 2048, SHA256: strings.Repeat("a", 64)}
				}
				state, err = appendRabbitMQMigrationEvent(root, plan, state, phase, copied)
				if err != nil {
					t.Fatalf("%s: %v", phase, err)
				}
			}
			// Reopen the job directory from disk as a new process would.
			second, err := os.OpenRoot(root.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			observed, err := readRabbitMQMigrationJournal(second, plan)
			if err != nil || observed != state {
				t.Fatalf("lost original progress after reopen: %v %v", observed, err)
			}
			if stage.final == "original-restored" {
				state, err = appendRabbitMQMigrationEvent(second, plan, state, "restore-original-intent", copied)
				if err != nil {
					t.Fatal(err)
				}
				state, err = appendRabbitMQMigrationEvent(second, plan, state, "restart-original-intent", copied)
				if err != nil {
					t.Fatal(err)
				}
			} else if _, err := appendRabbitMQMigrationEvent(second, plan, state, "restore-original-intent", copied); err == nil {
				t.Fatal("published endpoint allowed return to stale data volume")
			}
			state, err = appendRabbitMQMigrationEvent(second, plan, state, stage.final, copied)
			if err != nil || state.Phase != stage.final {
				t.Fatalf("failed to record recovery: %v %v", state, err)
			}
		})
	}
}

func TestRabbitMQMigrationJournalRejectsUnknownOriginalState(t *testing.T) {
	root, plan := rabbitMQJournalFixture(t)
	prepared, err := prepareRabbitMQMigrationJournal(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendRabbitMQMigrationEvent(root, plan, prepared, "copy-verified",
		rabbitMQColdCopyResult{Files: 1, Directories: 1, Bytes: 1, SHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("record permitted copying without confirmation of original shutdown")
	}
	quiesce, err := appendRabbitMQMigrationEvent(root, plan, prepared, "quiesce-intent", rabbitMQColdCopyResult{})
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := appendRabbitMQMigrationEvent(root, plan, quiesce, "stop-original-intent", rabbitMQColdCopyResult{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendRabbitMQMigrationEvent(root, plan, quiesce, "stop-original-intent", rabbitMQColdCopyResult{}); err == nil {
		t.Fatal("second stop was appended from stale initial state")
	}
	other := plan
	other.OriginalContainer = strings.Repeat("e", 64)
	if _, err := readRabbitMQMigrationJournal(root, other); err == nil {
		t.Fatal("accepted a replacement source container as the original")
	}
	name := fmt.Sprintf("event-%02d.json", stopped.Sequence+1)
	if err := root.WriteFile(name, []byte("partial-write"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRabbitMQMigrationJournal(root, plan); err == nil {
		t.Fatal("ignored an incomplete state file")
	}
	if raw, err := root.ReadFile(name); err != nil || string(raw) != "partial-write" {
		t.Fatalf("damaged evidence was overwritten: %q %v", raw, err)
	}
}
