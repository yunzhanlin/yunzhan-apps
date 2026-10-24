//go:build linux

package executor

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

type intrusionScalarChange struct{ Key, From, To string }
type intrusionScalarPlan struct {
	Process, ProcessStart, Action string
	Changes                       []intrusionScalarChange
}

// A PURE plan, not an actuator. It does not reload or change any Jail/filter,
// ban, ticket timestamp, executable or nft object. A later durable controller
// must verify the exact original pending record, files, disk declarations and
// freshly observed BEFORE/AFTER kernel scope immediately before execution.
// Mixed scalar states caused by interruption are accepted ONLY if every field
// still belongs to that original transaction; historical ban data is unused.
func intrusionJournalScalarPlan(original intrusionJournalPlan, current intrusionRuntimeState, state string) (out intrusionScalarPlan, planErr error) {
	defer func() {
		if planErr != nil {
			out = intrusionScalarPlan{}
		}
	}()
	if err := intrusionJournalValidate(original); err != nil {
		return out, err
	}
	if state != "committed" && state != "rolled_back" {
		return out, errors.New("入侵防护标量目标不是固定提交或恢复状态")
	}
	if current.Process != original.ProcessBefore || current.ProcessStart != original.ProcessStartBefore || current.JournalMatch != original.JournalMatchBefore {
		return out, errors.New("实际 Jail 进程或日志后端已不属于原事务，未执行标量变更")
	}
	if intrusionPolicyValidate(current.Policy) != nil {
		return out, errors.New("实际 Jail 动作或匹配容量无法核对")
	}
	policy := original.BeforePolicy
	policy.Ports = slices.Clone(current.Policy.Ports)
	if !reflect.DeepEqual(policy, current.Policy) || !slices.Equal(current.Policy.Ports, original.BeforePolicy.Ports) && !slices.Equal(current.Policy.Ports, original.TargetPorts) {
		return out, errors.New("实际 Jail 动作身份、匹配容量或端口不属于原事务前后状态")
	}
	targetRecipe, err := intrusionPortRecipeTargetForValidatedOriginal(original)
	if err != nil {
		return out, err
	}
	if _, err := intrusionPortRecipeDecodeAgainstValidatedOriginal(intrusionRecipeJSON(current.Recipe), original, targetRecipe); err != nil {
		return out, err
	}
	portsNow, err := intrusionPortList(current.Recipe.Values["port"])
	if err != nil || !slices.Equal(portsNow, current.Policy.Ports) {
		return out, errors.New("实际动作端口与完整属性采样不一致；未把混合读取当作恢复依据")
	}
	if _, err := intrusionJournalSettings(current.Settings); err != nil {
		return out, err
	}
	before, err := intrusionJournalBeforeSettings(original)
	if err != nil {
		return out, err
	}
	out = intrusionScalarPlan{Process: current.Process, ProcessStart: current.ProcessStart, Action: current.Policy.Action, Changes: []intrusionScalarChange{}}
	for _, item := range []struct {
		key, setting string
		factor       int
	}{{"maxretry", "max_retry", 1}, {"findtime", "find_time_minutes", 60}, {"bantime", "ban_time_minutes", 60}} {
		now, old, next := current.Settings[item.setting], before[item.setting], original.TargetSettings[item.setting]
		if now != old && now != next {
			return out, errors.New("实际 Jail 限额不属于原事务前后状态，未猜测恢复值")
		}
		wanted := next
		if state == "rolled_back" {
			wanted = old
		}
		if now != wanted {
			out.Changes = append(out.Changes, intrusionScalarChange{Key: item.key, From: strconv.Itoa(now * item.factor), To: strconv.Itoa(wanted * item.factor)})
		}
	}
	ports := func(values []int) string {
		labels := make([]string, len(values))
		for i, p := range values {
			labels[i] = strconv.Itoa(p)
		}
		return strings.Join(labels, ",")
	}
	wanted := original.TargetPorts
	if state == "rolled_back" {
		wanted = original.BeforePolicy.Ports
	}
	if !slices.Equal(current.Policy.Ports, wanted) {
		out.Changes = append(out.Changes, intrusionScalarChange{Key: "port", From: ports(current.Policy.Ports), To: ports(wanted)})
	}
	return out, nil
}
