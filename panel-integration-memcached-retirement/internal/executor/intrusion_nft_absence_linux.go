//go:build linux

package executor

import "errors"

// Absence is established from a successful complete typed listing, never an
// arbitrary CLI failure message. It is deferred verification, NOT a claim that
// a ban or either address family has already worked in the kernel.
func intrusionNftTableKnownAbsent(raw []byte, wanted string) error {
	return intrusionNftTableDirectoryValidate(raw, wanted, true)
}

func intrusionNftTableDirectoryValidate(raw []byte, wanted string, requireAbsent bool) error {
	if len(raw) < 1 || len(raw) > 24<<10 || !intrusionNftName(wanted) {
		return errors.New("内核表缺失观察范围无效")
	}
	var doc map[string][]map[string]any
	if decodeApacheWAFPrivateJSON(raw, &doc, map[string]bool{"nftables": true}, 8000) != nil || len(doc) != 1 || doc["nftables"] == nil || len(doc["nftables"]) > 1024 {
		return errors.New("内核表完整目录未知、重复或超限")
	}
	seen := map[string]bool{}
	meta := false
	for _, object := range doc["nftables"] {
		if len(object) != 1 {
			return errors.New("内核表目录含不明确对象")
		}
		if v, ok := object["metainfo"]; ok {
			if meta {
				return errors.New("内核表目录元数据重复")
			}
			if _, ok := v.(map[string]any); !ok {
				return errors.New("内核表目录元数据类型未知")
			}
			meta = true
			continue
		}
		value, ok := object["table"].(map[string]any)
		if !ok || !intrusionNftObjectKeys(value, []string{"family", "name"}, "handle") {
			return errors.New("内核表目录对象格式未支持核对")
		}
		family, ok := value["family"].(string)
		if !ok {
			return errors.New("内核表目录地址族类型未知")
		}
		if family != "inet" && family != "ip" && family != "ip6" && family != "arp" && family != "bridge" && family != "netdev" {
			return errors.New("内核表目录地址族未支持核对")
		}
		name, ok := value["name"].(string)
		if !ok || !intrusionNftName(name) || seen[family+":"+name] {
			return errors.New("内核表目录身份未知或重复")
		}
		seen[family+":"+name] = true
		if handle, present := value["handle"]; present {
			number, ok := handle.(float64)
			if !ok || number < 1 || number > 9007199254740991 || number != float64(int64(number)) {
				return errors.New("内核表目录句柄无法核对")
			}
		}
		if requireAbsent && family == "inet" && name == wanted {
			return errors.New("目标内核表实际存在，不能当作尚未创建")
		}
	}
	return nil
}
