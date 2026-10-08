package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

func strictLogCleanupObject(data []byte, keys []string, out any) error {
	if len(data) > 128<<10 {
		return errors.New("日志操作 JSON 超过核实容量")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return errors.New("日志操作必须为完整对象")
	}
	allowed, seen := map[string]bool{}, map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for d.More() {
		value, e := d.Token()
		key, ok := value.(string)
		if e != nil || !ok || !allowed[key] || seen[key] {
			return errors.New("日志操作有重复或未识别字段")
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("日志操作字段缺失或为 null")
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(keys) || d.Decode(new(any)) != io.EOF {
		return errors.New("日志操作对象字段不完整或存在额外内容")
	}
	return json.Unmarshal(data, out)
}

var siteLogArchivePattern = regexp.MustCompile(`^panel-([a-f0-9]{32})\.(access|error)\.log\.([0-9]{8}-[0-9]{6})(\.gz)?$`)

func ValidSiteLogArchiveName(id, name string) bool {
	match := siteLogArchivePattern.FindStringSubmatch(name)
	if match == nil || !ValidID(id) || match[1] != id {
		return false
	}
	at, e := time.Parse("20060102-150405", match[3])
	return e == nil && at.Format("20060102-150405") == match[3]
}

type LogCleanupRequest struct {
	RequestID     string `json:"request_id"`
	Attempt       int    `json:"attempt"`
	SiteID        string `json:"site_id"`
	RetentionDays int    `json:"retention_days"`
}

func (v *LogCleanupRequest) UnmarshalJSON(data []byte) error {
	type plain LogCleanupRequest
	var decoded plain
	if e := strictLogCleanupObject(data, []string{"request_id", "attempt", "site_id", "retention_days"}, &decoded); e != nil {
		return e
	}
	if !ValidID(decoded.RequestID) || !ValidID(decoded.SiteID) || decoded.Attempt < 0 || decoded.Attempt > 2 || decoded.RetentionDays < 1 || decoded.RetentionDays > 100 {
		return errors.New("日志操作身份或参数无效")
	}
	*v = LogCleanupRequest(decoded)
	return nil
}

type LogCleanupResult struct {
	Rotated      int      `json:"rotated"`
	Deleted      int      `json:"deleted"`
	DeletedBytes int64    `json:"deleted_bytes"`
	Files        []string `json:"files"`
}

type LogCleanupFileInspection struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	State        string `json:"state"`
	ArchiveState string `json:"archive_state,omitempty"`
	PlannedBytes int64  `json:"planned_bytes"`
}

type LogCleanupInspection struct {
	RequestID     string                     `json:"request_id"`
	SiteID        string                     `json:"site_id"`
	State         string                     `json:"state"`
	RetentionDays int                        `json:"retention_days"`
	StartedAt     string                     `json:"started_at"`
	PlanSHA256    string                     `json:"plan_sha256,omitempty"`
	Files         []LogCleanupFileInspection `json:"files"`
	Result        *LogCleanupResult          `json:"result,omitempty"`
	ReadOnly      bool                       `json:"read_only"`
	Continuation  *LogCleanupContinuation    `json:"continuation,omitempty"`
}

// This is never a completed cleanup result: the earlier outcome stays unknown.
type LogCleanupContinuation struct {
	RequestID      string `json:"request_id"`
	SiteID         string `json:"site_id"`
	PlanSHA256     string `json:"plan_sha256"`
	VerifiedAt     string `json:"verified_at"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type LogCleanupContinueRequest struct {
	RequestID          string `json:"request_id"`
	SiteID             string `json:"site_id"`
	PlanSHA256         string `json:"plan_sha256"`
	AcknowledgeUnknown bool   `json:"acknowledge_unknown"`
}

func (v *LogCleanupContinueRequest) UnmarshalJSON(data []byte) error {
	type plain LogCleanupContinueRequest
	var decoded plain
	if e := strictLogCleanupObject(data, []string{"request_id", "site_id", "plan_sha256", "acknowledge_unknown"}, &decoded); e != nil {
		return e
	}
	if !ValidID(decoded.RequestID) || !ValidID(decoded.SiteID) || !validLowerSHA256(decoded.PlanSHA256) || !decoded.AcknowledgeUnknown {
		return errors.New("须核对完整计划摘要并确认原操作仍为未知结果")
	}
	*v = LogCleanupContinueRequest(decoded)
	return nil
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (v *LogCleanupResult) UnmarshalJSON(data []byte) error {
	type plain LogCleanupResult
	var decoded plain
	if e := strictLogCleanupObject(data, []string{"rotated", "deleted", "deleted_bytes", "files"}, &decoded); e != nil {
		return e
	}
	if decoded.Rotated < 0 || decoded.Rotated > 2 || decoded.Deleted < 0 || decoded.Deleted > 1000 || decoded.DeletedBytes < 0 || decoded.Files == nil || len(decoded.Files) != decoded.Deleted || decoded.Deleted == 0 && decoded.DeletedBytes != 0 {
		return errors.New("日志结果数量或文件列表不一致")
	}
	seen := map[string]bool{}
	for _, name := range decoded.Files {
		match := siteLogArchivePattern.FindStringSubmatch(name)
		if match == nil || seen[name] || !ValidSiteLogArchiveName(match[1], name) {
			return errors.New("日志结果文件身份异常或重复")
		}
		seen[name] = true
	}
	*v = LogCleanupResult(decoded)
	return nil
}
