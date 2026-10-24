package core

import (
	"encoding/hex"
	"errors"
)

type HardeningRecoveryRequest struct {
	TransactionID string `json:"transaction_id"`
	SHA256        string `json:"sha256"`
	Confirm       string `json:"confirm"`
}

func NormalizeHardeningRecovery(raw map[string]any) (map[string]any, error) {
	if len(raw) != 3 {
		return nil, errors.New("加固恢复必须明确原事务、完整摘要和确认标识")
	}
	id, idOK := raw["transaction_id"].(string)
	digest, digestOK := raw["sha256"].(string)
	confirm, confirmOK := raw["confirm"].(string)
	decoded, err := hex.DecodeString(digest)
	if !idOK || !digestOK || !confirmOK || !ValidID(id) || confirm != id || len(decoded) != 32 || err != nil || hex.EncodeToString(decoded) != digest {
		return nil, errors.New("加固恢复原事务、摘要或精确确认无效")
	}
	return map[string]any{"transaction_id": id, "sha256": digest, "confirm": confirm}, nil
}
