//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
)

// Never retain request bodies: module inputs can contain passwords and tokens.
type moduleEvent struct {
	ID         string `json:"id"`
	Time       string `json:"time"`
	Action     string `json:"action"`
	Trigger    string `json:"trigger"`
	Outcome    string `json:"outcome"`
	SiteID     string `json:"site_id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	Error      string `json:"error,omitempty"`
	Copied     int    `json:"copied_count,omitempty"`
	Conflicts  int    `json:"conflicts_count,omitempty"`
	Changes    int    `json:"changes_count,omitempty"`
	Restored   int    `json:"restored_count,omitempty"`
}

func moduleCount(result map[string]any, field string) int {
	if n, ok := result[field+"_count"].(int); ok {
		return n
	}
	switch v := result[field].(type) {
	case []string:
		return len(v)
	case []any:
		return len(v)
	case []moduleChange:
		return len(v)
	}
	return 0
}
func (s *Service) appendModuleEvent(id, action, trigger string, in core.AppModuleInput, result any, operationError error) error {
	event := moduleEvent{ID: core.ID(), Time: core.Now(), Action: action, Trigger: trigger, Outcome: "succeeded"}
	if core.ValidID(in.SiteID) {
		event.SiteID = in.SiteID
	}
	if syncPlanID.MatchString(in.ResourceID) {
		event.ResourceID = in.ResourceID
	}
	if operationError != nil {
		event.Outcome = "failed"
		event.Error = operationError.Error()
		for _, secret := range []string{in.Password, in.Token} {
			if secret != "" {
				event.Error = strings.ReplaceAll(event.Error, secret, "[已隐藏]")
			}
		}
		if len(event.Error) > 512 {
			event.Error = event.Error[:512] + "…"
		}
	}
	if value, ok := result.(map[string]any); ok {
		event.Copied = moduleCount(value, "copied")
		event.Conflicts = moduleCount(value, "conflicts")
		if sites, ok := value["sites"].([]any); ok {
			for _, item := range sites {
				if row, ok := item.(map[string]any); ok {
					event.Changes += moduleCount(row, "changes")
					event.Restored += moduleCount(row, "restored")
				}
			}
		}
		if event.Conflicts > 0 && operationError == nil {
			event.Outcome = "conflicts"
		}
	}
	path := filepath.Join(s.moduleDir(id), "history.json")
	events := []moduleEvent{}
	if err := moduleRead(path, &events); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("历史记录损坏，未覆盖旧记录")
	}
	events = append(events, event)
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	for len(events) > 1 {
		raw, err := json.MarshalIndent(events, "", "  ")
		if err != nil {
			return err
		}
		if len(raw) <= 384<<10 {
			break
		}
		events = events[1:]
	}
	return moduleWrite(path, events)
}
func (s *Service) moduleHistory(id string, in core.AppModuleInput) (any, error) {
	events := []moduleEvent{}
	err := moduleRead(filepath.Join(s.moduleDir(id), "history.json"), &events)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	selected := []moduleEvent{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if in.SiteID != "" && event.SiteID != in.SiteID || in.ResourceID != "" && event.ResourceID != in.ResourceID {
			continue
		}
		selected = append(selected, event)
	}
	return map[string]any{"history": selected, "history_limited": true, "scope": "保留最近 100 条 / 384 KiB 执行摘要；不保存密码、令牌或完整请求正文"}, nil
}

func boundedModulePaths(paths []string) []string {
	result := []string{}
	budget := 128 << 10
	for _, path := range paths {
		raw, _ := json.Marshal(path)
		if len(result) >= 200 || len(raw) > budget {
			break
		}
		budget -= len(raw)
		result = append(result, path)
	}
	return result
}
func syncReport(preview bool, copies, conflicts []string, checkpoint string) map[string]any {
	copiedRows, conflictRows := boundedModulePaths(copies), boundedModulePaths(conflicts)
	return map[string]any{"preview": preview, "copied": copiedRows, "conflicts": conflictRows, "copied_count": len(copies), "conflicts_count": len(conflicts), "report_limited": len(copiedRows) != len(copies) || len(conflictRows) != len(conflicts), "deletes": []string{}, "checkpoint": checkpoint}
}
