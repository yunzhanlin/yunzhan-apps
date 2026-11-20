//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Run only by the native fixture on a disposable hosted runner which creates
// its own project, ports, and data. The executor's exact functions do the work.
func TestRabbitMQMigrationNativeWorker(t *testing.T) {
	action := os.Getenv("PANEL_RABBITMQ_NATIVE_ACTION")
	if action == "" {
		t.Skip("requires disposable RabbitMQ migration runner")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_REPOSITORY") != "yunzhanlin/yunzhan-apps" {
		t.Fatal("native fixture requires the isolated application runner")
	}
	dirname := os.Getenv("PANEL_RABBITMQ_NATIVE_DIR")
	if filepath.Dir(dirname) != "/var/lib/panel-rabbitmq-fixture" || filepath.Base(dirname) != "worker" {
		t.Fatal("native fixture path invalid")
	}
	raw, err := os.ReadFile(filepath.Join(dirname, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan rabbitMQMigrationPlan
	if err := json.Unmarshal(raw, &plan); err != nil || !plan.valid() {
		t.Fatal("invalid native fixture request")
	}
	project, err := openComposeUpdateDirectory(filepath.Join(dirname, "compose"), plan.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer project.Close()
	journal, err := os.OpenRoot(filepath.Join(dirname, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	store := dockerMutationStore{state: filepath.Join(dirname, "state"), blocked: func() bool { return false }, pending: func(context.Context) error { return nil }}
	lease, err := store.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	switch action {
	case "stage", "reject-connected":
		if _, err := prepareRabbitMQMigrationJournal(journal, plan); err != nil {
			t.Fatal(err)
		}
		authority, err := verifyRabbitMQMigrationRelease(ctx, plan)
		if err != nil {
			t.Fatal(err)
		}
		state, err := stageRabbitMQMigration(ctx, lease, project, journal, plan, authority, func(context.Context) error { return nil })
		if action == "reject-connected" {
			if err == nil || state.Phase != "prepared" {
				t.Fatalf("connected client did not prevent shutdown: %s %v", state.Phase, err)
			}
			return
		}
		if err != nil || state.Phase != "target-verified-offline" || state.VolumeCopy.Files == 0 {
			t.Fatalf("offline upgrade failed: %s %v", state.Phase, err)
		}
		t.Logf("isolated target verified, files=%d bytes=%d", state.VolumeCopy.Files, state.VolumeCopy.Bytes)
	case "restore":
		state, err := restoreRabbitMQBeforePublication(ctx, lease, project, journal, plan)
		if err != nil || state.Phase != "original-restored" {
			t.Fatalf("original recovery failed: %s %v", state.Phase, err)
		}
	case "publish":
		authority, err := verifyRabbitMQMigrationRelease(ctx, plan)
		if err != nil {
			t.Fatal(err)
		}
		next, err := publishRabbitMQMigration(ctx, lease, project, journal, plan, authority)
		if err != nil || next.Phase != "target-published" {
			t.Fatal("published endpoint could not be reconciled", err)
		}
	case "prepare-interrupted-cutover":
		err = lease.use(ctx, func(bound context.Context) error {
			state, err := readRabbitMQMigrationJournal(journal, plan)
			if err != nil || state.Phase != "target-verified-offline" {
				return errRabbitMQMigrationPending
			}
			cutover, err := rabbitMQPrepareCutover(project, plan)
			if err != nil {
				return err
			}
			if _, err := appendRabbitMQMigrationEvent(journal, plan, state, "publish-endpoint-intent", state.VolumeCopy); err != nil {
				return err
			}
			if err := cutover.apply(bound, project, plan); err != nil {
				return err
			}
			volume, err := namedRabbitMQMigrationVolume(bound, plan.CandidateVolume, rabbitMQCandidateVolumeLabels(plan))
			if err != nil {
				return err
			}
			_, err = rabbitMQCutoverContainer(bound, project, cutover.project, plan, volume)
			return err
		})
		if err != nil {
			t.Fatal("cannot simulate interruption after endpoint launch", err)
		}
	case "prepare-interrupted-restore":
		state, err := readRabbitMQMigrationJournal(journal, plan)
		if err != nil || state.Phase != "target-verified-offline" {
			t.Fatal("unexpected phase for original restart interruption", err)
		}
		err = lease.use(ctx, func(bound context.Context) error {
			state, err := appendRabbitMQMigrationEvent(journal, plan, state, "restore-original-intent", state.VolumeCopy)
			if err != nil {
				return err
			}
			_, err = appendRabbitMQMigrationEvent(journal, plan, state, "restart-original-intent", state.VolumeCopy)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown fixture action")
	}
}
