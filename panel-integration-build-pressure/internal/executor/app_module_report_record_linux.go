//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Only the two fixed retrospective JSON records are accepted here. This is
// not a general path reader and never creates, chmods or repairs evidence.
func (s *Service) moduleRetrospectiveRecord(id, name string, out any) error {
	if name != "history.json" && name != "last-report.json" {
		return errors.New("模块报告记录名无效")
	}
	dir, err := s.moduleRecordDirectory(id)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !dir.current() {
			return errors.New("模块报告目录身份变化；未将异常当作没有历史")
		}
		return err
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > 4<<20 {
		return errors.New("模块报告记录类型、身份、权限或容量异常")
	}
	f, err := dir.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("模块报告打开期间变化或不可读取")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, false, false) {
		return errors.New("模块报告读取身份变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	after, afterErr := f.Stat()
	visible, visibleErr := dir.Lstat(name)
	if err != nil || afterErr != nil || visibleErr != nil || int64(len(raw)) != info.Size() ||
		!os.SameFile(info, after) || !os.SameFile(info, visible) || after.Size() != info.Size() || visible.Size() != info.Size() ||
		after.ModTime() != info.ModTime() || visible.ModTime() != info.ModTime() || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(visible, false, false) || !dir.current() {
		return errors.New("模块报告读取期间内容或身份变化")
	}
	if err := validateModuleRetrospectiveJSON(raw, name); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func validateModuleRetrospectiveJSON(raw []byte, name string) error {
	if name == "history.json" {
		var events []moduleEvent
		if err := decodeModuleRetrospectiveJSON(raw, &events, true); err != nil {
			return err
		}
		if len(events) > 100 {
			return errors.New("旧历史摘要超过 100 条，未部分返回")
		}
		for _, event := range events {
			if err := validateModuleLedgerEvent(event); err != nil {
				return err
			}
		}
	} else {
		var report struct {
			Time   string          `json:"time"`
			Action string          `json:"action"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := decodeModuleRetrospectiveJSON(raw, &report, false); err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339, report.Time); err != nil || report.Action == "" || len(report.Action) > 80 || len(report.Error) > 64<<10 {
			return errors.New("模块报告时间、操作或错误摘要无效")
		}
	}
	return nil
}

func decodeModuleRetrospectiveJSON(raw []byte, out any, history bool) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	fields := map[string]bool{"time": true, "action": true, "result": true, "error": true}
	if history {
		fields = map[string]bool{"id": true, "time": true, "action": true, "trigger": true, "outcome": true, "site_id": true, "resource_id": true, "error": true, "copied_count": true, "conflicts_count": true, "changes_count": true, "restored_count": true, "findings_count": true, "quarantined_count": true}
	}
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 16 || nodes > 100000 {
			return errors.New("模块报告结构超过安全容量")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			if depth == 0 && (history && delimiter != '[' || !history && delimiter != '{') {
				return errors.New("模块报告根结构无效")
			}
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					key, ok := token.(string)
					if err != nil || !ok || seen[strings.ToLower(key)] {
						return errors.New("模块报告字段重复")
					}
					seen[strings.ToLower(key)] = true
					if (!history && depth == 0 || history && depth == 1) && !fields[key] {
						return errors.New("模块报告字段未知或大小写无效")
					}
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				if !history && depth == 0 || history && depth == 1 {
					required := []string{"time", "action", "result"}
					if history {
						required = []string{"id", "time", "action", "trigger", "outcome"}
					}
					for _, key := range required {
						if !seen[key] {
							return errors.New("模块报告完整字段缺失")
						}
					}
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("模块报告 JSON 结构异常")
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("模块报告 JSON 结构不完整")
			}
		} else if depth == 0 || history && depth == 1 {
			return errors.New("模块报告须为完整对象或摘要对象列表")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("模块报告有额外 JSON 内容")
	}
	return json.Unmarshal(raw, out)
}
