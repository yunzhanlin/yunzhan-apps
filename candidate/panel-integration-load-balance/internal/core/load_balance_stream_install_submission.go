package core

import (
	"bytes"
	"encoding/json"

	"local/panel/internal/appcatalog"
)

// The sole internal install wire. There is no actor, UID, path, command,
// programme hash, callback, retry or claimed success in a submission. Root must
// independently read the original running Core job and verify these exact
// signed metadata bytes with its compiled official key and feature contract.
type LoadBalanceStreamInstallSubmission struct {
	Format  int                                         `json:"format"`
	JobID   string                                      `json:"job_id"`
	Release appcatalog.LoadBalanceStreamReleaseEnvelope `json:"release"`
}

const LoadBalanceStreamInstallSubmissionMaxBytes = appcatalog.MaxMemcachedReleaseEnvelopeBytes + 256

func LoadBalanceStreamInstallSubmissionBytes(v LoadBalanceStreamInstallSubmission) ([]byte, error) {
	if v.Format != 1 || !ValidID(v.JobID) {
		return nil, errLoadBalanceStreamInstallAuthority
	}
	release, err := json.Marshal(v.Release)
	if err != nil {
		return nil, errLoadBalanceStreamInstallAuthority
	}
	if _, err = appcatalog.DecodeLoadBalanceStreamReleaseEnvelope(release); err != nil {
		return nil, errLoadBalanceStreamInstallAuthority
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > LoadBalanceStreamInstallSubmissionMaxBytes {
		return nil, errLoadBalanceStreamInstallAuthority
	}
	return raw, nil
}

func DecodeLoadBalanceStreamInstallSubmission(raw []byte) (LoadBalanceStreamInstallSubmission, error) {
	var v LoadBalanceStreamInstallSubmission
	if len(raw) == 0 || len(raw) > LoadBalanceStreamInstallSubmissionMaxBytes || json.Unmarshal(raw, &v) != nil {
		return LoadBalanceStreamInstallSubmission{}, errLoadBalanceStreamInstallAuthority
	}
	canonical, err := LoadBalanceStreamInstallSubmissionBytes(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return LoadBalanceStreamInstallSubmission{}, errLoadBalanceStreamInstallAuthority
	}
	return v, nil
}
