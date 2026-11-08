//go:build linux

package executor

import (
	"context"

	"local/panel/internal/core"
)

// A historical complete receipt alone never hides a live/foreign container.
// Current absence, private directory, original signature and NSS remain gates.
func memcachedUnixRetiredState(ctx context.Context, p *memcachedUnixProjectOriginal, account memcachedUnixAccount) (*memcachedUnixControlSnapshot, string, error) {
	if p == nil || p.current(ctx) != nil || p.head.Phase != "committed" {
		return nil, "", core.ErrMemcachedUnixControl
	}
	record, e := (memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}).retirement(ctx, p.head.Operation.ProjectID, memcachedUnixControlInstalledSHA(p.head), p.head.ContainerID, p.head.Operation.Name)
	if e != nil || record == nil {
		return record, "", e
	}
	if validateMemcachedUnixDirectory(p.head.Operation.ProjectID, p.head.Operation.SiteID, account) != nil {
		return nil, "", errMemcachedUnixNSS
	}
	fingerprint, e := memcachedUnixRetirementAbsence(ctx, record.Seed, *record.Issued, memcachedRetentionDaemon)
	if e != nil {
		return nil, "", e
	}
	actual, e := memcachedUnixOriginalAccount(ctx, p)
	if e != nil || actual != account || p.current(ctx) != nil {
		return nil, "", core.ErrMemcachedUnixControl
	}
	return record, fingerprint, nil
}
