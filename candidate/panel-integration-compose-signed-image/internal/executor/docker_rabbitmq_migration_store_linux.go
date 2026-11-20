//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const rabbitMQMigrationJobDirectory = "rabbitmq-migrations"
const rabbitMQMigrationJobLimit = 128

// All job publication happens under the original shared runtime and exclusive
// Docker leases. Both the ordinary Docker guard and programme upgrade guard
// can read the durable state after those leases are released by a crash.
type rabbitMQMigrationStore struct{ base string }

func productionRabbitMQMigrationStore() rabbitMQMigrationStore {
	return rabbitMQMigrationStore{base: "/var/lib/panel-executor/" + rabbitMQMigrationJobDirectory}
}

func (s rabbitMQMigrationStore) prepare(ctx context.Context, lease *dockerMutationLease, plan rabbitMQMigrationPlan) error {
	if !plan.valid() {
		return errRabbitMQIdentity
	}
	return lease.use(ctx, func(bound context.Context) error {
		anchor := lease.tree.roots[len(lease.tree.roots)-2]
		base, err := s.openAt(anchor)
		if err != nil {
			return err
		}
		defer base.Close()
		if err := s.check(bound); err != nil {
			return err
		}
		dir, err := base.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		entries, err := dir.ReadDir(rabbitMQMigrationJobLimit)
		if err != nil && !errors.Is(err, io.EOF) || len(entries) >= rabbitMQMigrationJobLimit {
			return errors.New("RabbitMQ 迁移任务记录已达容量上限")
		}
		temporary := ".prepare-" + core.ID()
		if err := base.Mkdir(temporary, 0700); err != nil {
			return err
		}
		defer base.RemoveAll(temporary)
		stage, err := base.OpenRoot(temporary)
		if err != nil {
			return err
		}
		defer stage.Close()
		if _, err = prepareRabbitMQMigrationJournal(stage, plan); err != nil {
			return err
		}
		if bound.Err() != nil || !base.current() {
			return errRabbitMQMigrationPending
		}
		if err := unix.Renameat2(int(dir.Fd()), temporary, int(dir.Fd()), plan.JobID, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		return dir.Sync()
	})
}

func (s rabbitMQMigrationStore) openAt(state *os.Root) (*statisticsGeoDirectory, error) {
	if filepath.Join(state.Name(), rabbitMQMigrationJobDirectory) != s.base {
		return nil, errRabbitMQMigrationPending
	}
	err := state.Mkdir(rabbitMQMigrationJobDirectory, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err == nil {
		if err := ruleFeedStoreSync(state); err != nil {
			return nil, err
		}
	}
	return geoJobDirectory(s.base, false)
}

func (s rabbitMQMigrationStore) read(id string) (*composeUpdateDirectory, rabbitMQMigrationPlan, rabbitMQMigrationEvent, error) {
	var plan rabbitMQMigrationPlan
	var event rabbitMQMigrationEvent
	dir, err := openComposeUpdateDirectory(s.base, id)
	if err != nil {
		return nil, plan, event, err
	}
	raw, err := geoStoreRead(dir.root, "plan.json", 8<<10)
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan.JobID != id {
		dir.Close()
		return nil, plan, event, errRabbitMQMigrationPending
	}
	event, err = readRabbitMQMigrationJournal(dir.root, plan)
	if err != nil || !dir.current() {
		dir.Close()
		return nil, plan, event, errRabbitMQMigrationPending
	}
	return dir, plan, event, nil
}

// A prepared record is safe to leave idle because the worker must recheck
// project identity and persist quiesce-intent before any RabbitMQ effect.
func rabbitMQMigrationMayChangeDocker(phase string) bool {
	switch phase {
	case "prepared", "cancelled-before-stop", "original-restored", "target-published":
		return false
	}
	return true
}

// Retain the original named volume even if the migrated Compose project is
// later removed. Only the explicit migration retention flow can release it.
func (s rabbitMQMigrationStore) retainsOriginalVolume(ctx context.Context, name string) (bool, error) {
	var retained bool
	err := s.each(ctx, func(plan rabbitMQMigrationPlan, event rabbitMQMigrationEvent) error {
		if plan.OriginalVolume == name && (rabbitMQMigrationMayChangeDocker(event.Phase) || event.Phase == "target-published") {
			retained = true
		}
		return nil
	})
	return retained, err
}

func (s rabbitMQMigrationStore) check(ctx context.Context) error {
	return s.each(ctx, func(_ rabbitMQMigrationPlan, event rabbitMQMigrationEvent) error {
		if rabbitMQMigrationMayChangeDocker(event.Phase) {
			return errRabbitMQMigrationPending
		}
		return nil
	})
}

func (s rabbitMQMigrationStore) each(ctx context.Context, observe func(rabbitMQMigrationPlan, rabbitMQMigrationEvent) error) error {
	base, err := geoJobDirectory(s.base, false)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return errRabbitMQMigrationPending
	}
	defer base.Close()
	dir, err := base.Open(".")
	if err != nil {
		return errRabbitMQMigrationPending
	}
	defer dir.Close()
	before, err := dir.Stat()
	if err != nil {
		return errRabbitMQMigrationPending
	}
	entries, err := dir.ReadDir(rabbitMQMigrationJobLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > rabbitMQMigrationJobLimit {
		return errRabbitMQMigrationPending
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// An unpublished staging directory cannot authorize a worker. It may
		// be left by a crash before the first durable event was exposed.
		if stage, ok := strings.CutPrefix(entry.Name(), ".prepare-"); ok && core.ValidID(stage) {
			if info, err := base.Lstat(entry.Name()); err == nil && moduleRecordInfo(info, true, false) {
				continue
			}
			return errRabbitMQMigrationPending
		}
		job, plan, event, err := s.read(entry.Name())
		if err != nil {
			return errRabbitMQMigrationPending
		}
		job.Close()
		if err := observe(plan, event); err != nil {
			return err
		}
	}
	after, err := dir.Stat()
	if err != nil || !geoStoreStableInfo(before, after) || !base.current() {
		return errRabbitMQMigrationPending
	}
	return ctx.Err()
}
