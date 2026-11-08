//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"local/panel/internal/core"
)

// A historical final receipt is NOT current engine absence or a command grant.
// Original install/signature, fresh authorization/NSS and real Docker absence
// must still be independently checked by the caller under the engine lease.
func memcachedUnixControlIsRetirement(v memcachedUnixControlSnapshot, project, installed, cid, name string) bool {
	raw, err := json.Marshal(v.Seed)
	if err != nil {
		return false
	}
	if _, err = memcachedUnixControlDecodeSeed(raw); err != nil || v.Issued == nil || v.Issued.Format != 1 || v.Issued.SeedSHA256 != core.Hash(string(raw)) {
		return false
	}
	fingerprint, err := memcachedUnixRetirementFingerprint(v.Seed, *v.Issued)
	if err != nil {
		return false
	}
	if v.Observation != nil {
		original := v
		original.Observation = nil
		if validateMemcachedUnixControlObservation(*v.Observation, original) != nil {
			return false
		}
	}
	outcome := v.outcome()
	return v.Seed.Operation.ProjectID == project && v.Seed.InstalledRecordSHA256 == installed &&
		v.Seed.Operation.Input.Action == "retire" && v.Seed.Operation.Input.ConfirmName == name &&
		v.Issued != nil && v.Issued.ContainerID == cid && v.Issued.InitialPID == 0 &&
		outcome != nil && (outcome.State == "completed" || outcome.State == "observed") &&
		outcome.FinalState == "retired" && outcome.RuntimeSHA256 == fingerprint && core.ValidateMemcachedUnixControlResult(v.Seed.Operation, *outcome) == nil
}

// Read only. Missing/pending/failed commands never become "uninstalled". No
// secondary mutable index can diverge from the original immutable control
// journal. Enumerate the bounded store once; retain every original receipt.
func (s memcachedUnixControlJournalStore) retirement(ctx context.Context, project, installed, cid, name string) (*memcachedUnixControlSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || !core.ValidID(project) || len(installed) != 64 || !composeRequestSHAPattern.MatchString(installed) || len(cid) != 64 || !dockerObjectPattern.MatchString(cid) || !dockerResourceNamePattern.MatchString(name) || len(name) > 40 {
		return nil, core.ErrMemcachedUnixControl
	}
	root, err := geoJobDirectory(s.base, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !memcachedUnixJournalRootInfo(info) {
		return nil, core.ErrMemcachedUnixControl
	}
	before, err := memcachedUnixControlInventory(root)
	if err != nil {
		return nil, err
	}
	var result *memcachedUnixControlSnapshot
	for id := range before {
		if id == "store.lock" {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		journal, err := s.open(id)
		if err != nil {
			return nil, err
		}
		value, err := journal.read()
		journal.Close()
		if err != nil {
			return nil, err
		}
		if value.Seed.Operation.ProjectID != project || value.Seed.Operation.Input.Action != "retire" {
			continue
		}
		outcome := value.outcome()
		if outcome == nil || outcome.State == "unknown" || outcome.FinalState != "retired" {
			continue
		}
		if !memcachedUnixControlIsRetirement(value, project, installed, cid, name) || result != nil {
			return nil, core.ErrMemcachedUnixControl
		}
		copy := value
		result = &copy
	}
	after, err := memcachedUnixControlInventory(root)
	if err != nil || len(before) != len(after) || !root.current() || ctx.Err() != nil {
		return nil, core.ErrMemcachedUnixControl
	}
	for id, info := range before {
		if !geoStoreStableInfo(info, after[id]) {
			return nil, core.ErrMemcachedUnixControl
		}
	}
	return result, nil
}
