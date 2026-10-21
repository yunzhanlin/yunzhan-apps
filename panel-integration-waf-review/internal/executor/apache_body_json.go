package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

// Durable evidence cannot contain ambiguous duplicate keys at any depth.
// Bound scanning independently of the decoder's own recursion allowance.
func apacheBodyDecodeJSON(b []byte, out any) error {
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer || typ.Elem().Kind() != reflect.Struct {
		return errors.New("Apache JSON 解码目标不是固定结构")
	}
	known := map[string]bool{}
	for i := 0; i < typ.Elem().NumField(); i++ {
		name := strings.Split(typ.Elem().Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			known[name] = true
		}
	}
	if err := apacheBodyValidateJSON(b, 64<<10, 4096, 6, known); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// Installation extensions remain opaque and are preserved, but ambiguities
// inside those extensions are still refused before privileged operations.
// Nil known permits extension keys, not duplicate/depth/budget bypasses.
func apacheBodyValidateJSON(b []byte, bytesMax, nodesMax, depthMax int, known map[string]bool) error {
	if len(b) == 0 || len(b) > bytesMax {
		return errors.New("Apache 私有 JSON 为空或超限")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes := 0
	var scan func(int, bool) error
	scan = func(depth int, root bool) error {
		nodes++
		if depth > depthMax || nodes > nodesMax {
			return errors.New("Apache JSON 深度或节点超限")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if root && (!compound || delimiter != '{') {
			return errors.New("Apache JSON 根必须为固定对象")
		}
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				folded := strings.ToLower(name)
				if !ok || len(name) > 256 || keys[folded] || (root && known != nil && !known[name]) {
					return errors.New("Apache JSON 字段未知、重复或超限")
				}
				keys[folded] = true
				if err := scan(depth+1, false); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := scan(depth+1, false); err != nil {
					return err
				}
			}
		default:
			return errors.New("Apache JSON 定界符异常")
		}
		end, err := d.Token()
		if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
			return errors.New("Apache JSON 对象或数组不完整")
		}
		return nil
	}
	if err := scan(0, true); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Apache JSON 含额外内容")
	}
	return nil
}
