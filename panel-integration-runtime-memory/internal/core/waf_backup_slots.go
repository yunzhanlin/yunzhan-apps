package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type WAFBackupSlots struct {
	Available        bool     `json:"available"`
	IDs              []string `json:"ids"`
	CountMax         int      `json:"count_max"`
	ReadOnly         bool     `json:"read_only"`
	ContentsVerified bool     `json:"contents_verified"`
	Message          string   `json:"message"`
}

func DecodeWAFBackupSlots(raw []byte) (WAFBackupSlots, error) {
	var out WAFBackupSlots
	bad := errors.New("原快照目录标识不可核对；不代表完整内容已通过")
	if len(raw) > 8192 || !wafInventoryJSONShape(raw, []string{"available", "ids", "count_max", "read_only", "contents_verified", "message"}) {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.IDs == nil || len(out.IDs) > 100 || out.CountMax != 100 || !out.ReadOnly || out.ContentsVerified || len(out.Message) > 1024 || !out.Available && len(out.IDs) != 0 {
		return WAFBackupSlots{}, bad
	}
	previous := ""
	for _, id := range out.IDs {
		if !ValidID(id) || id <= previous {
			return WAFBackupSlots{}, bad
		}
		previous = id
	}
	out.Message = "仅核对受限目录身份；各快照索引和完整内容尚未核验，不代表完整备份库存通过。"
	if !out.Available {
		out.Message = "原配置锁不可核对；目录标识未知，不代表没有快照。"
	}
	return out, nil
}
