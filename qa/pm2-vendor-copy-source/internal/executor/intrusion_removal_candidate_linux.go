//go:build linux

package executor

import (
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
)

type intrusionRemovalCandidate struct {
	Settings          map[string]int
	Ports             []int
	EffectiveIdentity string
	// Private observation evidence only; NEVER executed as a command stream.
	dump []byte
}

// Only positive, bounded literal times emitted by the fixed upstream test
// dump are understood. No expression, alias, permanent-ban guess or call to
// an executable/string evaluator may derive an uninstall target.
func intrusionRemovalLiteralSeconds(value any) (int, error) {
	if n, ok := value.(float64); ok {
		if n >= 1 && n <= 604800 && n == float64(int(n)) {
			return int(n), nil
		}
		return 0, errors.New("底层防护时间不是规范正整数")
	}
	raw, ok := value.(string)
	if !ok || len(raw) < 1 || len(raw) > 10 {
		return 0, errors.New("底层防护时间字面值未知")
	}
	factor := 1
	if last := raw[len(raw)-1]; last < '0' || last > '9' {
		factor = map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[last]
		raw = raw[:len(raw)-1]
	}
	n, err := strconv.Atoi(raw)
	if err != nil || factor == 0 || n < 1 || n > 604800/factor || strconv.Itoa(n) != raw {
		return 0, errors.New("底层防护时间不是受支持的有界字面量")
	}
	return n * factor, nil
}

// A PURE read-only candidate, NOT permission to uninstall or send the dump
// stream. A later controller must obtain it from a trusted, bounded private
// copy omitting ONLY the owned Jail, then recheck the original files/tree,
// actual daemon/kernel and durable queue authority around every real change.
// All filters, matching capacity, other Jails and global declarations must
// retain the complete current effective identity. Unknown defaults stay unknown.
func intrusionRemovalCandidateDecode(raw []byte, current intrusionRuntimeState, beforeIdentity string) (out intrusionRemovalCandidate, candidateErr error) {
	defer func() {
		if candidateErr != nil {
			out = intrusionRemovalCandidate{}
		}
	}()
	digest, err := hex.DecodeString(beforeIdentity)
	if err != nil || len(digest) != 32 || strings.ToLower(beforeIdentity) != beforeIdentity || intrusionPolicyValidate(current.Policy) != nil {
		return out, errors.New("卸载候选缺少完整实际配置比较身份")
	}
	if _, err := intrusionActionRecipeValidate(intrusionRecipeJSON(current.Recipe), current.Policy); err != nil {
		return out, err
	}
	var dump intrusionEffectiveDump
	if len(raw) < 1 || len(raw) > 32<<10 || decodeProgramQueueJSON(raw, &dump) != nil || dump.Format != 1 || len(dump.Commands) < 16 || len(dump.Commands) > 512 {
		return out, errors.New("底层卸载候选不是完整固定测试观察")
	}
	settings := map[string]int{}
	var ports []int
	for _, cmd := range dump.Commands {
		if len(cmd) < 4 || cmd[1] != "sshd" {
			continue
		}
		key, ok := cmd[2].(string)
		if !ok {
			continue // The complete decoder below rejects unknown declarations.
		}
		if cmd[0] == "set" && len(cmd) == 4 {
			item, wanted := map[string]struct {
				name   string
				factor int
			}{"maxretry": {"max_retry", 1}, "findtime": {"find_time_minutes", 60}, "bantime": {"ban_time_minutes", 60}}[key]
			if wanted {
				if _, duplicate := settings[item.name]; duplicate {
					return out, errors.New("底层卸载候选的限额声明重复")
				}
				if key == "maxretry" {
					if _, numeric := cmd[3].(float64); !numeric {
						return out, errors.New("底层重试次数不是测试输出的明确整数")
					}
				}
				n, err := intrusionRemovalLiteralSeconds(cmd[3])
				if err != nil || n%item.factor != 0 {
					return out, errors.New("底层卸载限额未知或不是完整分钟；未猜测默认值")
				}
				settings[item.name] = n / item.factor
			}
		}
		if cmd[0] == "multi-set" && key == "action" && len(cmd) == 5 && cmd[3] == current.Policy.Action {
			pairs, ok := cmd[4].([]any)
			if !ok || len(pairs) != 24 {
				return out, errors.New("底层卸载动作不是完整固定范围")
			}
			for _, value := range pairs {
				pair, ok := value.([]any)
				if !ok || len(pair) != 2 || pair[0] != "port" {
					continue
				}
				text, ok := pair[1].(string)
				if !ok || ports != nil {
					return out, errors.New("底层卸载动作端口缺失或重复")
				}
				ports, err = intrusionPortList(text)
				if err != nil {
					return out, errors.New("底层卸载端口不是已核对的数字范围；未转换服务别名")
				}
			}
		}
	}
	if _, err := intrusionJournalSettings(settings); err != nil || intrusionJournalPorts(ports) != nil {
		return out, errors.New("底层卸载候选缺少完整可支持的实际限额和端口")
	}
	expected := current
	expected.Policy.Ports = slices.Clone(ports)
	expected.Recipe.Values, err = intrusionStockActionValues(expected.Policy, current.Recipe.Values["nftables"], current.Recipe.Values["chain"])
	if err != nil {
		return out, err
	}
	expected.Recipe.Values["banEpoch"] = current.Recipe.Values["banEpoch"]
	effective, err := intrusionEffectiveConfigurationDecode(raw, expected, settings)
	if err != nil || effective.Identity != beforeIdentity {
		return out, errors.New("去除面板配置会改变过滤器、容量、其他 Jail 或全局状态；未授权接管底层配置")
	}
	return intrusionRemovalCandidate{Settings: settings, Ports: slices.Clone(ports), EffectiveIdentity: effective.Identity, dump: slices.Clone(raw)}, nil
}
