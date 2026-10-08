//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func decodeWAFRetentionObject(data []byte, required, optional []string, out any) error {
	if len(data) > wafBodyRetentionRecordLimit {
		return errors.New("清理记录超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("清理记录必须为完整对象")
	}
	allowed, seen := map[string]bool{}, map[string]bool{}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return errors.New("清理记录有重复、大小写错误或未知字段")
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("清理记录不接受 null 或缺失值")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return errors.New("清理记录不完整或有额外内容")
	}
	for _, key := range required {
		if !seen[key] {
			return errors.New("清理记录缺少必填字段")
		}
	}
	return json.Unmarshal(data, out)
}

func (v *wafBodyRetentionIdentity) UnmarshalJSON(data []byte) error {
	type plain wafBodyRetentionIdentity
	var out plain
	if err := decodeWAFRetentionObject(data, []string{"archive", "index_sha256", "device", "inode", "mtime_nano", "uid", "gid"}, nil, &out); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type archivePlain wafBodyLogArchive
	var archive archivePlain
	if err := decodeWAFRetentionObject(raw["archive"], []string{"id", "captured_at", "bytes", "sha256", "state"}, nil, &archive); err != nil {
		return err
	}
	out.Archive = wafBodyLogArchive(archive)
	*v = wafBodyRetentionIdentity(out)
	return nil
}

func (v *wafBodyRetentionDeletePlan) UnmarshalJSON(data []byte) error {
	type plain wafBodyRetentionDeletePlan
	var out plain
	if err := decodeWAFRetentionObject(data, []string{"id", "at", "policy_revision", "days", "keep_latest", "inventory", "selected"}, nil, &out); err != nil {
		return err
	}
	*v = wafBodyRetentionDeletePlan(out)
	return nil
}

func (v *wafBodyRetentionOperation) UnmarshalJSON(data []byte) error {
	type plain wafBodyRetentionOperation
	var out plain
	if err := decodeWAFRetentionObject(data, []string{"plan", "plan_sha256", "state", "verified_deleted"}, nil, &out); err != nil {
		return err
	}
	*v = wafBodyRetentionOperation(out)
	return nil
}

func (v *wafBodyRetentionRecord) UnmarshalJSON(data []byte) error {
	type plain wafBodyRetentionRecord
	var out plain
	if err := decodeWAFRetentionObject(data, []string{"format", "checked_at", "policy_revision", "history"}, []string{"operation"}, &out); err != nil {
		return err
	}
	*v = wafBodyRetentionRecord(out)
	return nil
}
