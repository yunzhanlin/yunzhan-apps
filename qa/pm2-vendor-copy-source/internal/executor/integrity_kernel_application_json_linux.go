//go:build linux

package executor

import (
	"encoding/json"
	"errors"

	"local/panel/internal/core"
)

// omitempty preserves all published format1 hashes. Do not let an explicit
// empty app_id spell the same old identity differently in an original file.
func integrityKernelApplicationJSON(raw []byte, value any) error {
	check := func(data []byte, format int, application string) error {
		var shape struct {
			AppID *json.RawMessage `json:"app_id"`
		}
		if json.Unmarshal(data, &shape) != nil || format == 1 && (shape.AppID != nil || application != "") || format == 2 && (shape.AppID == nil || application != core.IntegrityKernelEnterpriseApplication) || format != 1 && format != 2 {
			return errors.New("原内核操作应用字段与格式不符；未归一化或覆盖原记录")
		}
		return nil
	}
	switch v := value.(type) {
	case *core.IntegrityKernelRequest:
		return check(raw, v.Format, v.AppID)
	case *integrityKernelPlan:
		return check(raw, v.Format, v.AppID)
	case *core.IntegrityKernelOperation:
		var shape struct {
			Request json.RawMessage `json:"request"`
		}
		if json.Unmarshal(raw, &shape) != nil {
			return errors.New("原操作请求结构无效")
		}
		return check(shape.Request, v.Request.Format, v.Request.AppID)
	case *core.IntegrityKernelClosure:
		var shape struct {
			Request json.RawMessage `json:"request"`
		}
		if json.Unmarshal(raw, &shape) != nil {
			return errors.New("原封存请求结构无效")
		}
		return check(shape.Request, v.Request.Format, v.Request.AppID)
	case *core.IntegrityKernelCloseRequest:
		var shape struct {
			Request json.RawMessage `json:"request"`
		}
		if json.Unmarshal(raw, &shape) != nil {
			return errors.New("原提交封存请求结构无效")
		}
		return check(shape.Request, v.Request.Format, v.Request.AppID)
	}
	return nil
}
