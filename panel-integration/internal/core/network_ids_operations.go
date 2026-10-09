package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// This is a closed passive-IDS control contract, not AppModuleInput or shell
// input. The operation identity is assigned by Core, bound to actor and retry
// key. Acceptance never means that capture/configuration has been verified.
type NetworkIDSOperationInput struct {
	ExpectedRevision int64                           `json:"expected_revision"`
	Interface        string                          `json:"network_interface,omitempty"`
	HomeNetworks     []string                        `json:"home_networks,omitempty"`
	Enabled          *bool                           `json:"enabled,omitempty"`
	RuleProfile      *NetworkIDSRuleProfileSelection `json:"rule_profile,omitempty"`
}
type NetworkIDSOperationRequest struct {
	Action string                   `json:"action"`
	Input  NetworkIDSOperationInput `json:"input"`
}
type NetworkIDSOperation struct {
	ID        string                   `json:"id"`
	Action    string                   `json:"action"`
	Input     NetworkIDSOperationInput `json:"input"`
	State     string                   `json:"state"`
	Error     string                   `json:"error,omitempty"`
	CreatedAt string                   `json:"created_at"`
	UpdatedAt string                   `json:"updated_at"`
	Steps     []Step                   `json:"steps"`
}

func NetworkIDSBackgroundAction(action string) bool {
	switch action {
	case "ids-config", "ids-rules", "ids-start", "ids-stop", "ids-boot", "ids-recover", "ids-rotate":
		return true
	}
	return false
}

func ValidateNetworkIDSOperationRequest(in NetworkIDSOperationRequest) error {
	if !NetworkIDSBackgroundAction(in.Action) || in.Input.ExpectedRevision < 0 || in.Input.ExpectedRevision >= 1<<60 {
		return errors.New("IDS 后台操作或配置修订无效")
	}
	if (in.Action == "ids-rules") != (in.Input.RuleProfile != nil) {
		return errors.New("IDS 规则切换需要明确选择；其他动作不能混入规则切换")
	}
	if in.Input.RuleProfile != nil {
		if err := ValidateNetworkIDSRuleProfile(*in.Input.RuleProfile); err != nil {
			return err
		}
	}
	if in.Action == "ids-config" {
		if in.Input.Interface == "" || len(in.Input.Interface) > 15 || len(in.Input.HomeNetworks) < 1 || len(in.Input.HomeNetworks) > 16 || in.Input.Enabled != nil {
			return errors.New("IDS 接口配置字段不完整或混入开机设置")
		}
		for _, cidr := range in.Input.HomeNetworks {
			if len(cidr) > 64 {
				return errors.New("IDS 本机范围超限")
			}
		}
	} else if in.Input.Interface != "" || in.Input.HomeNetworks != nil || (in.Action == "ids-boot") != (in.Input.Enabled != nil) {
		return errors.New("IDS 后台操作混入其他动作的配置字段")
	}
	return nil
}

// Exact spelling and duplicate checks run before Go's case-insensitive JSON
// field matching. No null, aliases, extra objects or trailing input is accepted.
func closedIDSOperationJSON(raw []byte, wrapped bool) error {
	if len(raw) < 1 || len(raw) > 4096 {
		return errors.New("IDS 后台输入超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var object func(bool) error
	object = func(outer bool) error {
		if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
			return errors.New("IDS 输入必须为对象")
		}
		seen := map[string]bool{}
		for d.More() {
			tok, err := d.Token()
			name, ok := tok.(string)
			if err != nil || !ok || seen[name] {
				return errors.New("IDS 输入字段重复")
			}
			seen[name] = true
			if outer && name == "input" {
				if err := object(false); err != nil {
					return err
				}
				continue
			}
			if !outer && name == "rule_profile" {
				var choice json.RawMessage
				if err := d.Decode(&choice); err != nil {
					return err
				}
				if _, err := decodeNetworkIDSRuleProfile(choice); err != nil {
					return err
				}
				continue
			}
			if outer && name != "action" || !outer && name != "expected_revision" && name != "network_interface" && name != "home_networks" && name != "enabled" {
				return errors.New("IDS 输入字段未知或名称不规范")
			}
			value, err := d.Token()
			if err != nil || value == nil {
				return errors.New("IDS 输入不完整或含 null")
			}
			if name == "home_networks" {
				if value != json.Delim('[') {
					return errors.New("IDS 网段须为数组")
				}
				count := 0
				for d.More() {
					v, err := d.Token()
					text, ok := v.(string)
					count++
					if err != nil || !ok || len(text) > 64 || count > 16 {
						return errors.New("IDS 网段数组无效")
					}
				}
				if end, err := d.Token(); err != nil || end != json.Delim(']') {
					return errors.New("IDS 网段不完整")
				}
			} else if _, nested := value.(json.Delim); nested {
				return errors.New("IDS 输入包含多余嵌套")
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return errors.New("IDS 输入对象不完整")
		}
		if outer && (len(seen) != 2 || !seen["input"] || !seen["action"]) || !outer && !seen["expected_revision"] {
			return errors.New("IDS 输入缺少明确动作或配置修订")
		}
		return nil
	}
	if err := object(wrapped); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("IDS 输入有多余内容")
	}
	return nil
}
func DecodeNetworkIDSOperationRequest(raw []byte) (NetworkIDSOperationRequest, error) {
	var in NetworkIDSOperationRequest
	if err := closedIDSOperationJSON(raw, true); err != nil {
		return in, err
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return in, err
	}
	return in, ValidateNetworkIDSOperationRequest(in)
}
func decodeNetworkIDSOperationInput(action string, raw []byte) (NetworkIDSOperationRequest, error) {
	in := NetworkIDSOperationRequest{Action: action}
	if err := closedIDSOperationJSON(raw, false); err != nil {
		return in, err
	}
	if err := json.Unmarshal(raw, &in.Input); err != nil {
		return in, err
	}
	return in, ValidateNetworkIDSOperationRequest(in)
}

func (a *Server) submitNetworkIDSOperation(w http.ResponseWriter, r *http.Request, u identity, action string) {
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 1 || len(key) > 128 || strings.TrimSpace(key) != key {
		fail(w, 400, "IDS 后台操作需要稳定的幂等键；未执行")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	in, decodeErr := decodeNetworkIDSOperationInput(action, raw)
	if err != nil || decodeErr != nil {
		fail(w, 400, "IDS 后台输入重复、未知或不完整")
		return
	}
	id := Hash("network-ids-operation-v1\x00" + u.ID + "\x00" + key)[:32]
	ctx, cancel := contextWithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var out NetworkIDSOperation
	if err := a.Executor.Call(ctx, "POST", "/v1/network-ids/operations/"+id, in, &out); err != nil {
		fail(w, 409, "IDS 提交回执不能核对；请保留原提交键重试："+err.Error())
		return
	}
	if !validNetworkIDSOperation(out) || out.ID != id || out.Action != action || !reflect.DeepEqual(out.Input, in.Input) {
		fail(w, 502, "IDS 后台回执身份无效；未宣称完成")
		return
	}
	// Replays return the original receipt; they do not assert a new mutation.
	if err := a.Store.Audit(u.Username, "network.ids.operation.observe", id, out.State); err != nil {
		fail(w, 503, "IDS 任务可能已接收，但审计保存失败；保留原提交键核对")
		return
	}
	send(w, 202, out)
}
func validNetworkIDSOperation(out NetworkIDSOperation) bool {
	if !ValidID(out.ID) || ValidateNetworkIDSOperationRequest(NetworkIDSOperationRequest{out.Action, out.Input}) != nil || len(out.Error) > 2048 || len(out.Steps) > 16 {
		return false
	}
	switch out.State {
	case "queued", "running", "succeeded", "failed", "needs-attention":
	default:
		return false
	}
	for _, raw := range []string{out.CreatedAt, out.UpdatedAt} {
		if _, err := time.Parse(time.RFC3339Nano, raw); err != nil {
			return false
		}
	}
	return (out.State != "succeeded" || out.Error == "") && ((out.State != "failed" && out.State != "needs-attention") || out.Error != "")
}
func (a *Server) networkIDSOperationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/network-threat-detection/operations", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := contextWithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out := []NetworkIDSOperation{}
		if err := a.Executor.Call(ctx, "GET", "/v1/network-ids/operations", nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if len(out) > 16 {
			fail(w, 502, "IDS 后台任务数量超过契约")
			return
		}
		seen := map[string]bool{}
		for _, row := range out {
			if !validNetworkIDSOperation(row) || seen[row.ID] {
				fail(w, 502, "IDS 后台任务列表不能核对")
				return
			}
			seen[row.ID] = true
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/app-modules/network-threat-detection/operations/{operation}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("operation")
		if !ValidID(id) {
			fail(w, 400, "IDS 后台任务标识无效")
			return
		}
		ctx, cancel := contextWithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		var out NetworkIDSOperation
		if err := a.Executor.Call(ctx, "GET", "/v1/network-ids/operations/"+id, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if !validNetworkIDSOperation(out) || out.ID != id {
			fail(w, 502, "IDS 后台状态不能核对")
			return
		}
		send(w, 200, out)
	}))
}
