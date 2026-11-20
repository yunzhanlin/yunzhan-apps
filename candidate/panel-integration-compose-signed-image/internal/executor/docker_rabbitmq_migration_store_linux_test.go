//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRabbitMQMigrationFenceSurvivesOriginalWorkerExit(t *testing.T) {
	// This fixture only uses Linux files and flocks.
	mutex := dockerMutationFixture(t)
	_, plan := rabbitMQJournalFixture(t)
	store := rabbitMQMigrationStore{base: filepath.Join(mutex.state, rabbitMQMigrationJobDirectory)}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	lease, err := mutex.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := store.prepare(ctx, lease, plan); err != nil {
		t.Fatal(err)
	}
	if err := store.prepare(ctx, lease, plan); !errors.Is(err, os.ErrExist) {
		t.Fatalf("original job was replaced or returned unexpected error: %v", err)
	}
	if err := store.check(ctx); err != nil {
		t.Fatalf("prepared job still has no effect on Docker: %v", err)
	}
	journal, loaded, previous, err := store.read(plan.JobID)
	if err != nil || loaded != plan || previous.Phase != "prepared" {
		t.Fatalf("could not reopen exact plan: %v", err)
	}
	defer journal.Close()
	quiesced, err := appendRabbitMQMigrationEvent(journal.root, plan, previous, "quiesce-intent", previous.VolumeCopy)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()

	// A later process can obtain the locks physically, but ordinary Docker
	// operations and programme-upgrade checks still read the original intent.
	if other, err := mutex.acquire(ctx); !errors.Is(err, errRabbitMQMigrationPending) {
		other.Close()
		t.Fatalf("ordinary lease crossed durable RabbitMQ intent: %v", err)
	}
	if err := store.check(ctx); !errors.Is(err, errRabbitMQMigrationPending) {
		t.Fatalf("programme upgrade guard crossed durable intent: %v", err)
	}
	recovery, err := mutex.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	err = recovery.use(ctx, func(context.Context) error {
		resume, err := appendRabbitMQMigrationEvent(journal.root, plan, quiesced, "resume-listeners-intent", quiesced.VolumeCopy)
		if err != nil {
			return err
		}
		_, err = appendRabbitMQMigrationEvent(journal.root, plan, resume, "original-restored", resume.VolumeCopy)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery.Close()
	after, err := mutex.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after.Close()
}
