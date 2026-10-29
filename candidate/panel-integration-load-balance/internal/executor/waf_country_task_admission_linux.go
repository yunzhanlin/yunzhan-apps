//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"time"

	"local/panel/internal/core"
)

// The only production construction path to a NEW sealed task. The lower
// metadata primitive is not a substitute for this full independent admission.
// Existing task observation/dispatch must remain a separate, non-replaying
// controller decision; preparation itself never starts a systemd unit.
func (s *Service) prepareWAFCountryTask(ctx context.Context, id, actor string, in core.WAFCountryDataSelection, raw []byte) (countryTaskRequest, string, bool, error) {
	cache, authority, err := s.authorizeWAFCountryData(ctx, id, actor, in, raw)
	if err != nil {
		return countryTaskRequest{}, "", false, err
	}
	if err := s.countryTaskUnitTrusted(ctx, id); err != nil {
		return countryTaskRequest{}, "", false, err
	}
	// systemd's fixed writable mounts must exist before namespace setup. This
	// only initializes/validates the public cache root AFTER full original
	// actor/app/data/instance authorization, never downloads or changes policy.
	base, err := cache.open(true)
	if err != nil {
		return countryTaskRequest{}, "", false, err
	}
	_, _, usageErr := cache.usage(ctx, base)
	base.Close()
	if usageErr != nil {
		return countryTaskRequest{}, "", false, usageErr
	}
	in.Countries = append([]string(nil), in.Countries...)
	envelope, err := json.Marshal(authority.Envelope())
	if err != nil {
		return countryTaskRequest{}, "", false, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return countryTaskRequest{}, "", false, err
	}
	request := countryTaskRequest{1, id, actor, in, core.Hash(string(payload)), core.Hash(string(envelope)), time.Now().UTC().Format(time.RFC3339)}
	store := productionCountryTaskStore()
	store.guard = cache.guard
	return store.prepare(ctx, request, envelope)
}
