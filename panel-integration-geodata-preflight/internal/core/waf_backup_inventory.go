package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type WAFBackupInventoryRow struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Files     int    `json:"files"`
	Bytes     int64  `json:"bytes"`
	SHA       string `json:"sha256"`
}
type WAFBackupInventory struct {
	Available bool                    `json:"available"`
	Entries   []WAFBackupInventoryRow `json:"entries"`
	Bytes     int64                   `json:"bytes"`
	CountMax  int                     `json:"count_max"`
	ScanMax   int64                   `json:"scan_max_bytes"`
	ReadOnly  bool                    `json:"read_only"`
	Message   string                  `json:"message"`
}

// A selected row is complete only for that original snapshot. Reuse the
// strict row contract without returning a fabricated whole-inventory count.
func DecodeWAFBackupSnapshot(data []byte) (WAFBackupInventoryRow, error) {
	var row WAFBackupInventoryRow
	bad := errors.New("所选原配置快照元数据不可核对")
	if len(data) > 4096 || json.Unmarshal(data, &row) != nil {
		return WAFBackupInventoryRow{}, bad
	}
	wrapped, err := json.Marshal(map[string]any{"available": true, "entries": []json.RawMessage{data}, "bytes": row.Bytes, "count_max": 100, "scan_max_bytes": 128 << 20, "read_only": true, "message": "selected snapshot only"})
	if err != nil {
		return WAFBackupInventoryRow{}, bad
	}
	out, err := DecodeWAFBackupInventory(wrapped)
	if err != nil || len(out.Entries) != 1 {
		return WAFBackupInventoryRow{}, bad
	}
	return out.Entries[0], nil
}

// Closed DTO: never relay unreviewed executor fields or a raw backup to a
// browser. A failed full scan is not a zero/partial successful inventory.
func DecodeWAFBackupInventory(data []byte) (WAFBackupInventory, error) {
	var out WAFBackupInventory
	bad := errors.New("防火墙配置备份库存不可完整核对")
	if len(data) > 65536 {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return WAFBackupInventory{}, bad
	}
	// Require exact names and non-null fields, not encoding/json's case-folding
	// or null-to-zero compatibility. Private JSON duplicate scanner is below.
	if !wafInventoryJSONShape(data, []string{"available", "entries", "bytes", "count_max", "scan_max_bytes", "read_only", "message"}) {
		return WAFBackupInventory{}, bad
	}
	var shape struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if json.Unmarshal(data, &shape) != nil || len(shape.Entries) != len(out.Entries) || out.Entries == nil || out.CountMax != 100 || out.ScanMax != 128<<20 || !out.ReadOnly || len(out.Entries) > 100 || out.Bytes < 0 || out.Bytes > out.ScanMax || len(out.Message) > 1024 {
		return WAFBackupInventory{}, bad
	}
	var total int64
	previous := ""
	for i, row := range out.Entries {
		at, err := time.Parse(time.RFC3339, row.CreatedAt)
		if !wafInventoryJSONShape(shape.Entries[i], []string{"id", "created_at", "files", "bytes", "sha256"}) || !ValidID(row.ID) || row.ID <= previous || err != nil || at.IsZero() || len(row.CreatedAt) > 40 || row.Files < 5 || row.Files > 4096 || row.Bytes < 1 || row.Bytes > 9<<20 || len(row.SHA) != 64 {
			return WAFBackupInventory{}, bad
		}
		for _, c := range row.SHA {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return WAFBackupInventory{}, bad
			}
		}
		total += row.Bytes
		previous = row.ID
	}
	if total != out.Bytes || !out.Available && (len(out.Entries) != 0 || out.Bytes != 0) {
		return WAFBackupInventory{}, bad
	}
	out.Message = "完整核验全部备份索引及内容；仅返回元数据，不修改配置、归档或删除备份。"
	if !out.Available {
		out.Message = "尚无可核对的原配置锁；未创建目录或备份，也未宣称库存为空。"
	}
	return out, nil
}

func wafInventoryJSONShape(data []byte, fields []string) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !containsString(fields, key) {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	token, err = d.Token()
	return err == nil && token == json.Delim('}') && len(seen) == len(fields) && d.Decode(new(any)) == io.EOF
}
