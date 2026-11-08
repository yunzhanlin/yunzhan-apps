package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// This schema intentionally differs from hardening. The original identifier
// and FULL digest are the only authority references; no paths, saved commands,
// replacement settings, historical bans, or client confirmation tokens.
func NormalizeIntrusionRecovery(input map[string]any) (map[string]any, error) {
	id, idOK := input["transaction_id"].(string)
	digest, digestOK := input["plan_sha256"].(string)
	decoded, err := hex.DecodeString(digest)
	if len(input) != 2 || !idOK || !digestOK || !ValidID(id) || err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
		return nil, errors.New("防入侵恢复需要原事务标识及完整小写SHA-256摘要，且不能附带其他字段")
	}
	return map[string]any{"transaction_id": id, "plan_sha256": digest}, nil
}

func decodeIntrusionRecoveryBody(raw []byte) (map[string]any, error) {
	if len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"settings"}) {
		return nil, errors.New("防入侵恢复请求必须是唯一、完整且有界的settings对象")
	}
	var envelope struct {
		Settings json.RawMessage `json:"settings"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !wafInventoryJSONShape(envelope.Settings, []string{"transaction_id", "plan_sha256"}) {
		return nil, errors.New("防入侵恢复字段缺失、重复、未知或非规范")
	}
	var input map[string]any
	if json.Unmarshal(envelope.Settings, &input) != nil {
		return nil, errors.New("防入侵恢复字段类型无效")
	}
	return NormalizeIntrusionRecovery(input)
}
