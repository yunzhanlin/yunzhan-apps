package core

import (
	"bytes"
	"encoding/json"
	"errors"

	"local/panel/internal/appcatalog"
)

const MaxMemcachedUpdateSubmissionBytes = appcatalog.MaxMemcachedReleaseEnvelopeBytes + MaxMemcachedUpdateRecordBytes + 1024

// Exact original dispatch/evidence only: no YAML, host path, key, URL, command,
// mutable image choice, callback, retry flag or claimed verification result.
type MemcachedUpdateSubmission struct {
	Record   MemcachedUpdateRecord               `json:"record"`
	Envelope appcatalog.MemcachedReleaseEnvelope `json:"envelope"`
}

// Framing is NOT signing/user/native authority. Both producer and Root verify
// separately; Root reconstructs this seed from actual held project files.
func NewMemcachedUpdateSeed(dispatch MemcachedUpdateDispatch, plan MemcachedUpdatePlan, envelope appcatalog.MemcachedReleaseEnvelope) (MemcachedUpdateRecord, error) {
	var empty MemcachedUpdateRecord
	if ValidateMemcachedUpdateDispatch(dispatch) != nil || ValidateMemcachedUpdatePlan(plan, dispatch.ProjectID) != nil || dispatch.Input.ExpectedProjectSHA256 != plan.ProjectSHA256 {
		return empty, ErrMemcachedUpdateSnapshotIdentity
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return empty, err
	}
	if _, err = appcatalog.DecodeMemcachedReleaseEnvelope(raw); err != nil || Hash(string(envelope.AppManifest)) != dispatch.Input.ExpectedSHA256 {
		return empty, ErrMemcachedUpdateSnapshotIdentity
	}
	target, err := MemcachedComposeUpdateTarget(plan)
	if err != nil {
		return empty, err
	}
	return SealMemcachedUpdateRecord(MemcachedUpdateRecord{Format: 1, Dispatch: dispatch, DispatchSHA256: MemcachedUpdateDispatchSHA(dispatch), Plan: plan, EnvelopeSHA256: Hash(string(raw)), CatalogSHA256: Hash(string(envelope.Catalog)), TargetComposeSHA256: Hash(string(target)), Phase: "prepared"})
}

func DecodeMemcachedUpdateSubmission(raw []byte) (MemcachedUpdateSubmission, error) {
	var out MemcachedUpdateSubmission
	bad := errors.New("Memcached 原交付必须是完整、唯一、规范编码的原事务和签名信封")
	if len(raw) == 0 || len(raw) > MaxMemcachedUpdateSubmissionBytes || json.Unmarshal(raw, &out) != nil {
		return out, bad
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return MemcachedUpdateSubmission{}, bad
	}
	seed, err := NewMemcachedUpdateSeed(out.Record.Dispatch, out.Record.Plan, out.Envelope)
	if err != nil || seed != out.Record {
		return MemcachedUpdateSubmission{}, bad
	}
	return out, nil
}
