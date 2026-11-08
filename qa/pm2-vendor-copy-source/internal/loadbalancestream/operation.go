package loadbalancestream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const OperationKind = "load-balance-stream-control-v1"

// A future separately selected signed module. Published HTTP-only 1.8.x
// receipts must never become native TCP/UDP authority after a panel upgrade.
const AppVersion = "1.9.0"

var ErrOperation = errors.New("TCP/UDP 原始请求标识、动作或独立安装绑定无法核对；未授权或执行操作")
var operationID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Operation is the exact internal Core-to-Root request, never a shell, PID,
// account, probe-port allocator or proof of a grant. Root must independently
// read the original Core row/actor/session/grants and installed signed module,
// then recheck that authority before every effect under its original leases.
type Operation struct {
	Format    int      `json:"format"`
	Kind      string   `json:"kind"`
	RequestID string   `json:"request_id"`
	ActorID   string   `json:"actor_id"`
	Mutation  Mutation `json:"mutation"`
}

// OperationBinding is private Root evidence, not a client-supplied capability.
// It binds one original request to one immutable installed module/manifest,
// exact programme input cohort and actual actor/grant observation. Decoding it
// never verifies any of those facts or substitutes for fresh live authority.
type OperationBinding struct {
	Format                int    `json:"format"`
	AppID                 string `json:"app_id"`
	AppVersion            string `json:"app_version"`
	OperationSHA256       string `json:"operation_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
	InstalledSHA256       string `json:"installed_record_sha256"`
	ProgrammeInputs       string `json:"programme_inputs_sha256"`
	ActorObservationSHA   string `json:"actor_observation_sha256"`
	OriginalConfigSHA256  string `json:"original_config_sha256"`
	OriginalRequestSHA256 string `json:"original_request_sha256"`
}

func operationHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value || value == strings.Repeat("0", 64) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func OperationBytes(value Operation) ([]byte, error) {
	if value.Format != 1 || value.Kind != OperationKind || !operationID.MatchString(value.RequestID) || !operationID.MatchString(value.ActorID) {
		return nil, ErrOperation
	}
	rawMutation, err := json.Marshal(value.Mutation)
	if err != nil {
		return nil, ErrOperation
	}
	if _, err := DecodeMutation(rawMutation); err != nil {
		return nil, ErrOperation
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxEntryBytes+1024 {
		return nil, ErrOperation
	}
	return raw, nil
}

func DecodeOperation(raw []byte) (Operation, error) {
	var value Operation
	if len(raw) == 0 || len(raw) > MaxEntryBytes+1024 || json.Unmarshal(raw, &value) != nil {
		return Operation{}, ErrOperation
	}
	canonical, err := OperationBytes(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Operation{}, ErrOperation
	}
	return value, nil
}

func OperationSHA256(value Operation) string {
	raw, err := OperationBytes(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func OperationBindingBytes(value OperationBinding) ([]byte, error) {
	if value.Format != 1 || value.AppID != "load-balance" || value.AppVersion != AppVersion {
		return nil, ErrOperation
	}
	for _, hash := range []string{value.OperationSHA256, value.ManifestSHA256, value.InstalledSHA256, value.ProgrammeInputs, value.ActorObservationSHA, value.OriginalConfigSHA256, value.OriginalRequestSHA256} {
		if !operationHash(hash) {
			return nil, ErrOperation
		}
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) >= 2048 {
		return nil, ErrOperation
	}
	return append(raw, '\n'), nil
}

func DecodeOperationBinding(raw []byte, operation Operation) (OperationBinding, error) {
	var value OperationBinding
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &value) != nil {
		return OperationBinding{}, ErrOperation
	}
	canonical, err := OperationBindingBytes(value)
	expected := OperationSHA256(operation)
	if err != nil || expected == "" || value.OperationSHA256 != expected || !bytes.Equal(raw, canonical) {
		return OperationBinding{}, ErrOperation
	}
	return value, nil
}
