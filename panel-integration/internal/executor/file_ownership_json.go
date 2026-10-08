package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func (v *fileOwner) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("文件所有者必须是完整 UID/GID 对象")
	}
	seen := map[string]bool{}
	out := fileOwner{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || (name != "uid" && name != "gid") || seen[name] {
			return errors.New("文件所有者字段重复、大小写错误或未知")
		}
		seen[name] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("文件所有者不接受 null")
		}
		var value uint32
		if json.Unmarshal(raw, &value) != nil || value == ^uint32(0) {
			return errors.New("文件所有者不是明确有效的 UID/GID")
		}
		if name == "uid" {
			out.UID = value
		} else {
			out.GID = value
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 || d.Decode(new(any)) != io.EOF {
		return errors.New("文件所有者字段缺失或包含额外内容")
	}
	*v = out
	return nil
}
