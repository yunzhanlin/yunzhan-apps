//go:build linux

package executor

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"local/panel/internal/core"
)

//go:embed intrusion_configuration_dump.py
var intrusionConfigurationDumpBody string

var intrusionConfigurationDumpScript = intrusionFilterMetadataScript + "\n" + intrusionFilterProjectionScript + "\n" + intrusionConfigurationDumpBody

type intrusionEffectiveDump struct {
	Format         int                      `json:"format"`
	Commands       [][]any                  `json:"commands"`
	FilterMetadata *intrusionFilterMetadata `json:"filter_metadata,omitempty"`
}

type intrusionEffectiveConfiguration struct {
	Identity string
	Commands [][]any
}

func intrusionDumpLiteral(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > 12 || *nodes > 8192 {
		return false
	}
	switch v := value.(type) {
	case string:
		return len(v) <= 24<<10 && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
	case bool:
		return true
	case float64:
		return v >= -9007199254740991 && v <= 9007199254740991 && v == float64(int64(v))
	case []any:
		if len(v) > 512 {
			return false
		}
		for _, item := range v {
			if !intrusionDumpLiteral(item, depth+1, nodes) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func intrusionDumpLimit(value any, wanted, factor int) bool {
	if n, ok := value.(float64); ok {
		return n == float64(wanted*factor)
	}
	raw, ok := value.(string)
	if !ok || raw == "" {
		return false
	}
	for suffix, multiplier := range map[string]int{"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800} {
		label := raw
		if suffix != "" {
			if !strings.HasSuffix(raw, suffix) {
				continue
			}
			label = strings.TrimSuffix(raw, suffix)
		}
		n, err := strconv.Atoi(label)
		if err == nil && n > 0 && n <= 604800 && strconv.Itoa(n) == label && n*multiplier == wanted*factor {
			return true
		}
	}
	return false
}

// The stream is an observation, NEVER commands to send/replay. Every target
// action is positively matched against the live complete stock recipe. Only
// the three public limits and their two port-bearing action declarations may
// differ between validated BEFORE/AFTER configurations. Filters, maxmatches,
// ignore policy, other Jails and global settings remain exact and ordered.
// This alone does NOT authorize reload: live filter agreement, trusted on-disk
// inventory, original transaction, CAS and fresh kernel checks are also needed.
func intrusionEffectiveConfigurationDecode(raw []byte, runtime intrusionRuntimeState, settings map[string]int) (intrusionEffectiveConfiguration, error) {
	var out intrusionEffectiveConfiguration
	var dump intrusionEffectiveDump
	if len(raw) < 1 || len(raw) > 32<<10 || decodeProgramQueueJSON(raw, &dump) != nil || dump.Format != 1 || len(dump.Commands) < 16 || len(dump.Commands) > 512 || intrusionPolicyValidate(runtime.Policy) != nil {
		return out, errors.New("入侵防护磁盘配置不是完整固定测试观察")
	}
	if _, err := intrusionJournalSettings(settings); err != nil {
		return out, err
	}
	if dump.FilterMetadata != nil && !intrusionFilterMetadataValid(*dump.FilterMetadata) {
		return out, errors.New("磁盘过滤器可读元数据格式或版本不可核对")
	}
	// Pure retained-dump parsing may have no live runtime authority. Every
	// normal mutation read below requires it; absence is never a default.
	if runtime.FilterMetadata.Format != 0 && (!intrusionFilterMetadataValid(runtime.FilterMetadata) || dump.FilterMetadata == nil || runtime.FilterMetadata != *dump.FilterMetadata) {
		return out, errors.New("运行中过滤器可读元数据与磁盘配置不一致；未重载、重启或修补")
	}
	nodes := 0
	for _, command := range dump.Commands {
		if !intrusionDumpLiteral([]any(command), 0, &nodes) {
			return out, errors.New("磁盘配置声明含未知字面类型或超过固定范围")
		}
	}
	if _, err := intrusionActionRecipeValidate(intrusionRecipeJSON(runtime.Recipe), runtime.Policy); err != nil {
		return out, err
	}
	// Marshal/unmarshal clones nested declarations before normalization; caller
	// evidence is never repaired or modified by a comparison.
	encoded, err := json.Marshal(dump.Commands)
	if err != nil {
		return out, err
	}
	var projection [][]any
	if json.Unmarshal(encoded, &projection) != nil {
		return out, errors.New("磁盘配置完整声明无法重新核对")
	}
	seen := map[string]bool{}
	active, started := false, false
	for i, cmd := range dump.Commands {
		if len(cmd) < 2 || len(cmd) > 16 {
			return out, errors.New("磁盘配置声明范围未知")
		}
		verb, ok := cmd[0].(string)
		if !ok || !slices.Contains([]string{"set", "multi-set", "add", "start"}, verb) {
			return out, errors.New("磁盘配置含未知协议声明，未执行")
		}
		name, ok := cmd[1].(string)
		if !ok || name == "" {
			return out, errors.New("磁盘配置目标身份无法核对")
		}
		if name != "sshd" {
			continue
		}
		key := verb
		if verb == "set" || verb == "multi-set" {
			if len(cmd) < 4 {
				return out, errors.New("SSH 配置字段缺失")
			}
			key, ok = cmd[2].(string)
			if !ok {
				return out, errors.New("SSH 配置字段类型未知")
			}
		}
		if seen[key] || started {
			return out, errors.New("SSH 磁盘配置重复或声明顺序未知")
		}
		seen[key] = true
		if verb == "add" {
			if len(cmd) != 3 || cmd[2] != "systemd" || active {
				return out, errors.New("SSH 磁盘配置未保持实际 systemd 后端，未重启 Jail")
			}
			active = true
			continue
		}
		if !active {
			return out, errors.New("SSH 磁盘声明没有明确的既存后端")
		}
		if verb == "start" {
			if len(cmd) != 2 {
				return out, errors.New("SSH 配置启动声明含未知参数")
			}
			started = true
			continue
		}
		p := projection[i]
		switch key {
		case "maxretry", "findtime", "bantime":
			item := map[string]struct {
				name   string
				factor int
			}{"maxretry": {"max_retry", 1}, "findtime": {"find_time_minutes", 60}, "bantime": {"ban_time_minutes", 60}}[key]
			if verb != "set" || len(cmd) != 4 || !intrusionDumpLimit(cmd[3], settings[item.name], item.factor) {
				return out, errors.New("SSH 磁盘限额与本次明确目标不符")
			}
			p[3] = "transaction_owned_limit"
		case "addjournalmatch":
			parts := []string{}
			for _, v := range cmd[3:] {
				s, ok := v.(string)
				if !ok {
					return out, errors.New("磁盘日志匹配类型未知")
				}
				parts = append(parts, s)
			}
			if verb != "set" || strings.Join(parts, " ") != runtime.JournalMatch {
				return out, errors.New("SSH 磁盘日志来源与运行中后端不同")
			}
		case "addaction":
			if verb != "set" || len(cmd) != 4 || cmd[3] != runtime.Policy.Action {
				return out, errors.New("SSH 磁盘动作身份改变，未替换原动作")
			}
		case "action":
			if verb != "multi-set" || len(cmd) != 5 || cmd[3] != runtime.Policy.Action {
				return out, errors.New("SSH 磁盘动作不是唯一固定属性声明")
			}
			pairs, ok := cmd[4].([]any)
			if !ok || len(pairs) != 24 {
				return out, errors.New("SSH 磁盘完整动作字段缺失或含额外脚本")
			}
			expected, e := intrusionStockActionValues(runtime.Policy, runtime.Recipe.Values["nftables"], runtime.Recipe.Values["chain"])
			if e != nil {
				return out, e
			}
			for _, k := range []string{"actionreload", "actionreban", "actionrepair", "timeout"} {
				delete(expected, k)
			}
			actual := map[string]string{}
			for j, value := range pairs {
				pair, ok := value.([]any)
				if !ok || len(pair) != 2 {
					return out, errors.New("SSH 磁盘动作字段类型未知")
				}
				name, ok := pair[0].(string)
				if !ok {
					return out, errors.New("SSH 磁盘动作字段名称未知")
				}
				v, ok := pair[1].(string)
				if !ok {
					return out, errors.New("SSH 磁盘动作字段值类型未知")
				}
				if _, exists := actual[name]; exists {
					return out, errors.New("SSH 磁盘动作字段重复")
				}
				actual[name] = v
				if slices.Contains([]string{"port", "actionstart", "actionflush"}, name) {
					p[4].([]any)[j].([]any)[1] = "transaction_owned_port_recipe"
				}
			}
			if !reflect.DeepEqual(expected, actual) {
				return out, errors.New("SSH 磁盘完整动作与本次实际范围不符；未运行配置流")
			}
		case "addfailregex":
			values, ok := cmd[3].([]any)
			if verb != "multi-set" || len(cmd) != 4 || !ok || len(values) < 1 || len(values) > 128 {
				return out, errors.New("SSH 磁盘匹配规则格式或容量未支持")
			}
			for _, v := range values {
				if _, ok := v.(string); !ok {
					return out, errors.New("SSH 磁盘匹配规则不是字面文本")
				}
			}
		case "usedns", "prefregex", "datepattern", "ignorecommand", "logencoding":
			if verb != "set" || len(cmd) != 4 {
				return out, errors.New("SSH 磁盘过滤字段格式未知")
			}
			if _, ok := cmd[3].(string); !ok {
				return out, errors.New("SSH 磁盘过滤字段不是文本")
			}
		case "maxlines", "maxmatches":
			v, ok := cmd[3].(float64)
			if verb != "set" || len(cmd) != 4 || !ok || v < 1 || v > 1024 || float64(int(v)) != v {
				return out, errors.New("SSH 磁盘匹配容量不是明确整数")
			}
			if key == "maxmatches" && int(v) != runtime.Policy.MaxMatches {
				return out, errors.New("SSH 磁盘与实际匹配容量不一致，未随重试次数隐式调整")
			}
		default:
			return out, errors.New("SSH 磁盘配置存在未支持的附加行为，未接管或删除")
		}
	}
	required := []string{"add", "start", "usedns", "prefregex", "maxlines", "addfailregex", "datepattern", "addjournalmatch", "maxretry", "maxmatches", "findtime", "bantime", "ignorecommand", "logencoding", "addaction", "action"}
	if len(seen) != len(required) || !started {
		return out, errors.New("SSH 磁盘配置不是完整固定范围")
	}
	for _, name := range required {
		if !seen[name] {
			return out, errors.New("SSH 磁盘配置缺少完整字段")
		}
	}
	canonical, err := json.Marshal(struct {
		Commands       [][]any                  `json:"commands"`
		FilterMetadata *intrusionFilterMetadata `json:"filter_metadata,omitempty"`
	}{projection, dump.FilterMetadata})
	if err != nil {
		return out, err
	}
	out.Identity = core.Hash(string(canonical))
	out.Commands = dump.Commands
	return out, nil
}

func intrusionRecipeJSON(value intrusionActionRecipe) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func (s *Service) readIntrusionEffectiveConfiguration(ctx context.Context, runtime intrusionRuntimeState, settings map[string]int) (intrusionEffectiveConfiguration, error) {
	if !intrusionFilterMetadataValid(runtime.FilterMetadata) {
		return intrusionEffectiveConfiguration{}, errors.New("固定磁盘核对缺少本次运行中过滤器可读元数据")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := s.Config.Run(ctx, "/usr/bin/python3", "-I", "-B", "-c", intrusionConfigurationDumpScript)
	if err != nil || ctx.Err() != nil {
		return intrusionEffectiveConfiguration{}, errors.New("入侵防护固定磁盘配置测试未完成，未重试、重载或运行配置流")
	}
	return intrusionEffectiveConfigurationDecode([]byte(raw), runtime, settings)
}
