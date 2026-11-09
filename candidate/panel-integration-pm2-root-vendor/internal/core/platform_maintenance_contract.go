package core

import (
	"encoding/json"
	"errors"
	"regexp"
)

const PlatformMaintenanceGrantLimit = 128
const PlatformMaintenanceOperationLimit = 1024
const PlatformMaintenanceAppVersion = "1.3.0"

var platformMaintenanceSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type PlatformMaintenanceGrantInput struct {
	Commands []string `json:"commands"`
	Minutes  int      `json:"minutes"`
	Confirm  string   `json:"confirm"`
}
type PlatformMaintenanceInput struct {
	RequestID       string `json:"request_id"`
	Command         string `json:"command"`
	ExpectedPlanSHA string `json:"expected_plan_sha256"`
	Confirm         string `json:"confirm"`
}
type PlatformMaintenanceNativeRequest struct {
	Format  int                      `json:"format"`
	GrantID string                   `json:"grant_id"`
	ActorID string                   `json:"actor_id"`
	Input   PlatformMaintenanceInput `json:"input"`
}
type PlatformMaintenancePlan struct {
	Format   int      `json:"format"`
	SHA      string   `json:"sha256"`
	Commands []string `json:"commands"`
}
type PlatformMaintenanceRecord struct {
	Format     int                              `json:"format"`
	Request    PlatformMaintenanceNativeRequest `json:"request"`
	RequestSHA string                           `json:"request_sha256"`
	State      string                           `json:"state"`
	Outcome    string                           `json:"outcome"`
}

func PlatformMaintenanceCommands() []string { return []string{"nginx-check", "nginx-reload"} }
func validatePlatformMaintenanceCommands(commands []string) bool {
	if len(commands) < 1 || len(commands) > 2 {
		return false
	}
	previous := ""
	for _, c := range commands {
		if c <= previous || c != "nginx-check" && c != "nginx-reload" {
			return false
		}
		previous = c
	}
	return true
}
func DecodePlatformMaintenanceGrant(raw []byte) (PlatformMaintenanceGrantInput, error) {
	var in PlatformMaintenanceGrantInput
	if len(raw) > 1024 || !wafInventoryJSONShape(raw, []string{"commands", "minutes", "confirm"}) || json.Unmarshal(raw, &in) != nil || !validatePlatformMaintenanceCommands(in.Commands) || in.Minutes < 5 || in.Minutes > 1440 || in.Confirm != "GRANT NGINX MAINTENANCE" {
		return in, errors.New("维护授权须明确选择固定命令、5–1440分钟有效期和完整确认；旧只读授权不会升级")
	}
	return in, nil
}
func ValidatePlatformMaintenanceInput(in PlatformMaintenanceInput) error {
	if !ValidID(in.RequestID) || !platformMaintenanceSHA.MatchString(in.ExpectedPlanSHA) || in.Command != "nginx-check" && in.Command != "nginx-reload" || in.Command == "nginx-check" && in.Confirm != "" || in.Command == "nginx-reload" && in.Confirm != "RELOAD NGINX "+in.ExpectedPlanSHA {
		return errors.New("维护请求须绑定原ID、固定命令、计划摘要和精确重载确认，不接受脚本、路径或停止操作")
	}
	return nil
}
func DecodePlatformMaintenanceInput(raw []byte) (PlatformMaintenanceInput, error) {
	var in PlatformMaintenanceInput
	if len(raw) > 1024 || !wafInventoryJSONShape(raw, []string{"request_id", "command", "expected_plan_sha256", "confirm"}) || json.Unmarshal(raw, &in) != nil {
		return in, errors.New("维护命令字段重复、缺失、未知或超限")
	}
	return in, ValidatePlatformMaintenanceInput(in)
}
func PlatformMaintenanceRequestSHA(in PlatformMaintenanceNativeRequest) string {
	raw, _ := json.Marshal(in)
	return Hash(string(raw))
}
func ValidatePlatformMaintenanceNativeRequest(in PlatformMaintenanceNativeRequest) error {
	if in.Format != 1 || !platformMaintenanceSHA.MatchString(in.GrantID) || !ValidID(in.ActorID) || ValidatePlatformMaintenanceInput(in.Input) != nil {
		return errors.New("原维护授权、主体和命令绑定不可核对")
	}
	return nil
}
func DecodePlatformMaintenanceNativeRequest(raw []byte) (PlatformMaintenanceNativeRequest, error) {
	var in PlatformMaintenanceNativeRequest
	var shape struct{ Input json.RawMessage }
	if len(raw) > 2048 || !wafInventoryJSONShape(raw, []string{"format", "grant_id", "actor_id", "input"}) || json.Unmarshal(raw, &in) != nil || json.Unmarshal(raw, &shape) != nil {
		return in, errors.New("原维护交接结构无效")
	}
	if _, err := DecodePlatformMaintenanceInput(shape.Input); err != nil {
		return in, err
	}
	return in, ValidatePlatformMaintenanceNativeRequest(in)
}
func ValidatePlatformMaintenanceRecord(out PlatformMaintenanceRecord) error {
	if out.Format != 1 || ValidatePlatformMaintenanceNativeRequest(out.Request) != nil || out.RequestSHA != PlatformMaintenanceRequestSHA(out.Request) {
		return errors.New("原维护回执身份不同")
	}
	switch out.State {
	case "started":
		if out.Outcome != "unknown" {
			return errors.New("开始记录不能宣称完成")
		}
	case "completed":
		if out.Request.Input.Command == "nginx-check" && out.Outcome != "config_valid" || out.Request.Input.Command == "nginx-reload" && out.Outcome != "reload_signal_submitted" {
			return errors.New("命令结果不能宣称网站健康或全进程重载完成")
		}
	case "failed":
		if out.Outcome != "command_failed" && out.Outcome != "plan_changed_before_command" {
			return errors.New("失败结果无效")
		}
	default:
		return errors.New("维护回执状态无效")
	}
	return nil
}
func DecodePlatformMaintenanceRecord(raw []byte, expected PlatformMaintenanceNativeRequest) (PlatformMaintenanceRecord, error) {
	var out PlatformMaintenanceRecord
	var shape struct{ Request json.RawMessage }
	if len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"format", "request", "request_sha256", "state", "outcome"}) || json.Unmarshal(raw, &out) != nil || json.Unmarshal(raw, &shape) != nil {
		return out, errors.New("原维护回执格式无效")
	}
	if _, err := DecodePlatformMaintenanceNativeRequest(shape.Request); err != nil {
		return out, err
	}
	if out.Request != expected {
		return out, errors.New("维护回执不是原请求")
	}
	return out, ValidatePlatformMaintenanceRecord(out)
}
func DecodePlatformMaintenancePlan(raw []byte) (PlatformMaintenancePlan, error) {
	var out PlatformMaintenancePlan
	if len(raw) > 512 || !wafInventoryJSONShape(raw, []string{"format", "sha256", "commands"}) || json.Unmarshal(raw, &out) != nil || out.Format != 1 || !platformMaintenanceSHA.MatchString(out.SHA) || !validatePlatformMaintenanceCommands(out.Commands) || len(out.Commands) != 2 {
		return out, errors.New("完整维护计划不可核对")
	}
	return out, nil
}
