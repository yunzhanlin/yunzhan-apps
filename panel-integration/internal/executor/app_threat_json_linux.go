//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Private IDS ownership and recovery records are not last-key-wins documents.
// Check every nested object before decoding the typed contract, including
// escaped and case-equivalent keys that encoding/json would otherwise merge.
func decodeThreatIDSPrivateJSON(data []byte, out any) error {
	if len(data) > 128<<10 {
		return errors.New("IDS 私有记录超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("IDS 私有记录嵌套过深")
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return errors.New("IDS 私有记录不完整或含 null")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[strings.ToLower(name)] {
						return errors.New("IDS 私有记录字段重复或无效")
					}
					seen[strings.ToLower(name)] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				if depth == 0 {
					return errors.New("IDS 私有记录必须为对象")
				}
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("IDS 私有记录结构异常")
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("IDS 私有记录结构不完整")
			}
		} else if depth == 0 {
			return errors.New("IDS 私有记录必须为对象")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("IDS 私有记录有多余内容")
	}
	return decodeFTPPrivateJSON(data, out)
}
