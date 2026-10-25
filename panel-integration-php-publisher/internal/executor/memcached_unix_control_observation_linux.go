//go:build linux

package executor

import (
	"bytes"
	"encoding/json"

	"local/panel/internal/core"
)

// Append-only current-state evidence, NOT a replacement command result. A
// missing/unknown original result and its exact issued intent remain unchanged.
// The production caller must independently authenticate a fresh reviewer and
// the original signed installation, then inspect the real same CID/image,
// enforced kernel contract and same-connection peer under the original lease.
type memcachedUnixControlObservation struct {
	Format               int                             `json:"format"`
	SeedSHA256           string                          `json:"seed_sha256"`
	IssuedSHA256         string                          `json:"issued_sha256"`
	OriginalResultSHA256 string                          `json:"original_result_sha256"`
	Result               core.MemcachedUnixControlResult `json:"result"`
}

func memcachedUnixControlValueSHA(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return core.Hash(string(raw))
}

func validateMemcachedUnixControlObservation(value memcachedUnixControlObservation, original memcachedUnixControlSnapshot) error {
	if original.Issued == nil || original.Observation != nil || original.Result != nil && original.Result.State != "unknown" || value.Format != 1 || value.SeedSHA256 != memcachedUnixControlValueSHA(original.Seed) || value.IssuedSHA256 != memcachedUnixControlValueSHA(original.Issued) || value.OriginalResultSHA256 != memcachedUnixControlValueSHA(original.Result) || value.Result.State != "observed" || core.ValidateMemcachedUnixControlResult(original.Seed.Operation, value.Result) != nil {
		return core.ErrMemcachedUnixControl
	}
	return nil
}

func decodeMemcachedUnixControlObservation(raw []byte, original memcachedUnixControlSnapshot) (memcachedUnixControlObservation, error) {
	var value memcachedUnixControlObservation
	if len(raw) == 0 || len(raw) > memcachedUnixControlSeedLimit || json.Unmarshal(raw, &value) != nil || validateMemcachedUnixControlObservation(value, original) != nil {
		return value, core.ErrMemcachedUnixControl
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(raw, canonical) {
		return memcachedUnixControlObservation{}, core.ErrMemcachedUnixControl
	}
	return value, nil
}

// This framing helper performs no Docker/protocol call. Only the independent
// recovery admission may use it after verifying live ownership and permission.
func (l *memcachedUnixControlLease) observe(value core.MemcachedUnixControlResult) error {
	if !l.current() {
		return core.ErrMemcachedUnixControl
	}
	before, err := l.j.read()
	if err != nil {
		return err
	}
	observation := memcachedUnixControlObservation{Format: 1, SeedSHA256: memcachedUnixControlValueSHA(before.Seed), IssuedSHA256: memcachedUnixControlValueSHA(before.Issued), OriginalResultSHA256: memcachedUnixControlValueSHA(before.Result), Result: value}
	if validateMemcachedUnixControlObservation(observation, before) != nil {
		return core.ErrMemcachedUnixControl
	}
	raw, _ := json.Marshal(observation)
	if memcachedUnixControlWrite(l.j.d.root, "observation.json", raw) != nil {
		return core.ErrMemcachedUnixControl
	}
	after, err := l.j.read()
	if err != nil || after.Observation == nil || *after.Observation != observation || !l.current() {
		return core.ErrMemcachedUnixControl
	}
	return nil
}

func (value memcachedUnixControlSnapshot) outcome() *core.MemcachedUnixControlResult {
	if value.Observation != nil {
		return &value.Observation.Result
	}
	return value.Result
}
