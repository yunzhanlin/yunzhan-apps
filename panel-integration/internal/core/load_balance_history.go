package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

func LoadBalanceHistoryAction(action string) bool {
	return action == "transactions" || action == "archive-transaction"
}

// Closed, reviewed archive implementations; do not infer compatibility from
// a numerically newer, unknown application version.
func LoadBalanceHistoryVersion(version string) bool {
	return version == "1.8.0" || version == "1.8.1" || version == "1.8.2"
}

// The history API cannot inherit node, health, TLS or filesystem fields from
// the large generic application form. Reject duplicate and unrelated keys in
// both Core and executor, including unrelated fields with zero values.
func DecodeLoadBalanceHistoryInput(action string, raw []byte) (AppModuleInput, error) {
	var in AppModuleInput
	if !LoadBalanceHistoryAction(action) || len(raw) > 4096 {
		return in, errors.New("事务维护请求无效或超过 4 KiB")
	}
	allowed := map[string]bool{"limit": true, "offset": true}
	if action == "archive-transaction" {
		allowed = map[string]bool{"resource_id": true, "expected_sha": true, "confirm": true}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return in, errors.New("事务维护请求必须为独立对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return in, errors.New("事务维护字段重复或不被支持")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return in, errors.New("事务维护字段不能为空值")
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return in, errors.New("事务维护对象不完整")
	}
	if d.Decode(&struct{}{}) != io.EOF || json.Unmarshal(raw, &in) != nil {
		return in, errors.New("事务维护字段格式无效")
	}
	return in, ValidateLoadBalanceHistoryInput(action, in)
}

func ValidateLoadBalanceHistoryInput(action string, in AppModuleInput) error {
	var expected AppModuleInput
	if action == "transactions" {
		if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > 2560 {
			return errors.New("事务清单每页最多 32 条，起点最多 2560")
		}
		expected.Limit, expected.Offset = in.Limit, in.Offset
	} else if action == "archive-transaction" {
		if !ValidID(in.ResourceID) || len(in.ExpectedSHA) != 64 || in.Confirm != "ARCHIVE LOAD TRANSACTION "+in.ResourceID {
			return errors.New("归档须选择事务、核对完整摘要并精确确认 ARCHIVE LOAD TRANSACTION 事务标识")
		}
		for _, c := range in.ExpectedSHA {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return errors.New("事务摘要须为规范 SHA-256")
			}
		}
		expected.ResourceID, expected.ExpectedSHA, expected.Confirm = in.ResourceID, in.ExpectedSHA, in.Confirm
	} else {
		return errors.New("事务维护操作无效")
	}
	if !reflect.DeepEqual(in, expected) {
		return errors.New("事务维护不接受入口、TLS、检查策略或其他业务字段")
	}
	return nil
}
