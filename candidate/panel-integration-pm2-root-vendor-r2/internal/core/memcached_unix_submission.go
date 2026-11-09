package core

import (
	"bytes"
	"encoding/json"
	"errors"

	"local/panel/internal/appcatalog"
)

const MaxMemcachedUnixInstallSubmissionBytes = appcatalog.MaxMemcachedReleaseEnvelopeBytes + (128 << 10)

// Independent install transfer, never the compat2 update/recovery journal.
// Framing/identity checks alone grant no actor, official signature, run lease,
// Linux UID/path, project ownership or Docker operation authority.
type MemcachedUnixInstallSubmission struct {
	Operation DockerProjectRequest                    `json:"operation"`
	Binding   MemcachedUnixBinding                    `json:"binding"`
	Envelope  appcatalog.MemcachedUnixReleaseEnvelope `json:"envelope"`
}

var errMemcachedUnixSubmission = errors.New("Memcached Socket 原安装传输容量、规范编码或身份绑定无效")

func NewMemcachedUnixInstallSubmission(op DockerProjectRequest, binding MemcachedUnixBinding, envelope appcatalog.MemcachedUnixReleaseEnvelope) (MemcachedUnixInstallSubmission, error) {
	var empty MemcachedUnixInstallSubmission
	if op.Action != "create" || op.TemplateProfile != MemcachedUnixProfile || ValidateDockerProject(op) != nil || binding.Version != appcatalog.MemcachedUnixVersion || !dockerRequestDigestPattern.MatchString(binding.ManifestSHA256) || Hash(string(envelope.AppManifest)) != binding.ManifestSHA256 {
		return empty, errMemcachedUnixSubmission
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return empty, errMemcachedUnixSubmission
	}
	closed, err := appcatalog.DecodeMemcachedUnixReleaseEnvelope(raw)
	if err != nil {
		return empty, errMemcachedUnixSubmission
	}
	out := MemcachedUnixInstallSubmission{Operation: op, Binding: binding, Envelope: closed}
	body, err := json.Marshal(out)
	if err != nil || len(body) > MaxMemcachedUnixInstallSubmissionBytes {
		return empty, errMemcachedUnixSubmission
	}
	return out, nil
}

// Same canonical private-RPC framing policy as the existing independent
// update transfer: unknown/duplicate/case aliases, nulls, arrays masquerading
// as []byte and extra documents cannot survive the exact round-trip.
// No global HTTP/executor body limit is raised.
func DecodeMemcachedUnixInstallSubmission(raw []byte) (MemcachedUnixInstallSubmission, error) {
	var out MemcachedUnixInstallSubmission
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixInstallSubmissionBytes || json.Unmarshal(raw, &out) != nil {
		return MemcachedUnixInstallSubmission{}, errMemcachedUnixSubmission
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return MemcachedUnixInstallSubmission{}, errMemcachedUnixSubmission
	}
	return NewMemcachedUnixInstallSubmission(out.Operation, out.Binding, out.Envelope)
}
