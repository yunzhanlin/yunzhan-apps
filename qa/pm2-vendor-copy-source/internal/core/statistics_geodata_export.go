package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// This is an evidence download, never a trusted software/data installation
// envelope. Preserve the five original leaves byte-for-byte, without paths
// supplied by the caller. Base64 JSON remains below the existing 16MiB RPC cap.
const StatisticsGeoExportBundleMaxBytes = 5 << 20
const StatisticsGeoExportReplyMaxBytes = 7 << 20

var statisticsGeoEvidenceNames = []string{"request.json", "envelope.json", "started.json", "result.json", "install.lock"}
var statisticsGeoEvidenceLimits = map[string]int{"request.json": 4096, "envelope.json": 3 << 20, "started.json": 4096, "result.json": 32 << 10, "install.lock": 0}

type StatisticsGeoExportInput struct {
	JobID string `json:"job_id"`
	SHA   string `json:"expected_sha256"`
}
type StatisticsGeoEvidenceBundle struct {
	Format int                    `json:"format"`
	Record StatisticsGeoJobRecord `json:"record"`
	Files  map[string][]byte      `json:"files"`
}
type StatisticsGeoExportResult struct {
	Record    StatisticsGeoJobRecord `json:"record"`
	Bundle    []byte                 `json:"bundle"`
	BundleSHA string                 `json:"bundle_sha256"`
}

func ValidateStatisticsGeoExport(in StatisticsGeoExportInput) error {
	if !ValidID(in.JobID) || !statisticsGeoSHA.MatchString(in.SHA) {
		return errors.New("证据导出必须绑定原任务和完整摘要，不接受路径")
	}
	return nil
}
func DecodeStatisticsGeoExport(raw []byte) (StatisticsGeoExportInput, error) {
	var in StatisticsGeoExportInput
	if len(raw) > 512 || !wafInventoryJSONShape(raw, []string{"job_id", "expected_sha256"}) || json.Unmarshal(raw, &in) != nil {
		return in, errors.New("证据导出字段重复、未知、缺失或超限")
	}
	return in, ValidateStatisticsGeoExport(in)
}
func statisticsGeoExportRecordShape(raw []byte) bool {
	var wire struct {
		Archived *bool `json:"archived"`
	}
	return wafInventoryJSONShape(raw, []string{"job_id", "state", "sha256", "bytes", "archived"}) && json.Unmarshal(raw, &wire) == nil && wire.Archived != nil
}
func ValidateStatisticsGeoEvidenceBundle(raw []byte, record StatisticsGeoJobRecord) error {
	bad := errors.New("原证据导出内容、完整摘要或终态不同；未交付部分成功")
	if len(raw) > StatisticsGeoExportBundleMaxBytes || !validStatisticsGeoJobRecord(record) || record.State == "pending" || !wafInventoryJSONShape(raw, []string{"format", "record", "files"}) {
		return bad
	}
	var bundle StatisticsGeoEvidenceBundle
	var shape struct{ Record, Files json.RawMessage }
	if json.Unmarshal(raw, &bundle) != nil || json.Unmarshal(raw, &shape) != nil || bundle.Format != 1 || bundle.Record != record || !statisticsGeoExportRecordShape(shape.Record) || !wafInventoryJSONShape(shape.Files, statisticsGeoEvidenceNames) {
		return bad
	}
	var leaves map[string]json.RawMessage
	if json.Unmarshal(shape.Files, &leaves) != nil {
		return bad
	}
	h := sha256.New()
	var total int64
	for _, name := range statisticsGeoEvidenceNames {
		data, found := bundle.Files[name]
		var text string
		if !found || json.Unmarshal(leaves[name], &text) != nil || bytes.Equal(bytes.TrimSpace(leaves[name]), []byte("null")) || len(data) > statisticsGeoEvidenceLimits[name] || name != "install.lock" && len(data) == 0 {
			return bad
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		d := sha256.Sum256(data)
		h.Write(d[:])
		total += int64(len(data))
	}
	if total != record.Bytes || hex.EncodeToString(h.Sum(nil)) != record.SHA {
		return bad
	}
	return nil
}
func DecodeStatisticsGeoExportResult(raw []byte, in StatisticsGeoExportInput) (StatisticsGeoExportResult, error) {
	var out StatisticsGeoExportResult
	bad := errors.New("原证据导出回执不可核对")
	if ValidateStatisticsGeoExport(in) != nil || len(raw) > StatisticsGeoExportReplyMaxBytes || !wafInventoryJSONShape(raw, []string{"record", "bundle", "bundle_sha256"}) || json.Unmarshal(raw, &out) != nil || out.Record.JobID != in.JobID || out.Record.SHA != in.SHA || !statisticsGeoSHA.MatchString(out.BundleSHA) || Hash(string(out.Bundle)) != out.BundleSHA || ValidateStatisticsGeoEvidenceBundle(out.Bundle, out.Record) != nil {
		return StatisticsGeoExportResult{}, bad
	}
	// Closed nested record is checked independently of the bundle's record.
	var shape struct{ Record json.RawMessage }
	if json.Unmarshal(raw, &shape) != nil || !statisticsGeoExportRecordShape(shape.Record) {
		return StatisticsGeoExportResult{}, bad
	}
	return out, nil
}
