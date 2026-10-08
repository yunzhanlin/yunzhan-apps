package core

import "errors"

// Nil is the legacy/default policy. Deletion requires a separately explicit
// acknowledgement and never applies to unknown or incomplete snapshots.
type WAFBodyLogRetentionConfig struct {
	Enabled       bool `json:"enabled"`
	Days          int  `json:"days"`
	KeepLatest    int  `json:"keep_latest"`
	ConfirmDelete bool `json:"confirm_delete_completed_snapshots"`
}

func DefaultWAFBodyLogRetention() WAFBodyLogRetentionConfig {
	return WAFBodyLogRetentionConfig{Days: 30, KeepLatest: 2}
}

func ValidateWAFBodyLogRetention(v *WAFBodyLogRetentionConfig) error {
	if v == nil {
		return nil
	}
	if v.Days < 1 || v.Days > 365 || v.KeepLatest < 1 || v.KeepLatest > 7 {
		return errors.New("WAF 已完成快照保留期为 1–365 天，至少保留最新 1–7 份")
	}
	if v.Enabled && !v.ConfirmDelete {
		return errors.New("必须明确确认自动移除超过保留期的已完成 WAF 快照；未知证据不会自动移除")
	}
	return nil
}

type WAFBodyLogRetentionRetainRequest struct {
	SHA256       string `json:"sha256"`
	Acknowledged bool   `json:"acknowledge_unknown_deletion_not_repeated"`
}

func (v *WAFBodyLogRetentionRetainRequest) UnmarshalJSON(data []byte) error {
	type plain WAFBodyLogRetentionRetainRequest
	var out plain
	if err := strictLogCleanupObject(data, []string{"sha256", "acknowledge_unknown_deletion_not_repeated"}, &out); err != nil {
		return err
	}
	*v = WAFBodyLogRetentionRetainRequest(out)
	return nil
}

func (v WAFBodyLogRetentionRetainRequest) Valid() bool {
	return v.Acknowledged && validLowerSHA256(v.SHA256)
}
