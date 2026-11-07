//go:build linux

package executor

import (
	_ "embed"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"local/panel/internal/core"
)

//go:embed intrusion_port_template_mutation.py
var intrusionPortTemplateMutationBody string

var intrusionPortTemplateMutationScript = intrusionProcessIdentityScript + "\n" + intrusionPortTemplateMutationBody

type intrusionPortTemplateReceipt struct {
	Format        int    `json:"format"`
	PID           string `json:"pid"`
	StartTicks    string `json:"start_ticks"`
	Field         string `json:"field"`
	Action        string `json:"action"`
	FromSHA256    string `json:"from_sha256"`
	ToSHA256      string `json:"to_sha256"`
	Applied       bool   `json:"applied"`
	AlreadyTarget bool   `json:"already_target"`
}

// Grammar only, NOT an actuator or a public command API. No observed or
// persisted action string becomes helper input. Both values must match the
// original source-derived BEFORE/AFTER templates, then only their typed
// program/table/chain/port inputs are sent for independent fixed rendering.
func intrusionPortTemplateMutationArgs(original intrusionJournalPlan, change intrusionPortRecipeChange) ([]string, error) {
	after, err := intrusionPortRecipeTarget(original)
	if err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"actionstart", "actionflush"}, change.Field) || change.From == change.To {
		return nil, errors.New("入侵防护模板变更不是两项固定原端口属性")
	}
	before := original.ActionBefore.Values
	from, to := original.BeforePolicy.Ports, original.TargetPorts
	if change.From == after[change.Field] && change.To == before[change.Field] {
		from, to = to, from
	} else if change.From != before[change.Field] || change.To != after[change.Field] {
		return nil, errors.New("入侵防护模板不属于原完整计划的源代码推导前后值；未传入脚本")
	}
	labels := func(ports []int) string {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.Itoa(p)
		}
		return strings.Join(parts, ",")
	}
	return []string{"-I", "-B", "-c", intrusionPortTemplateMutationScript, original.ProcessBefore, change.Field, original.BeforePolicy.Action, before["nftables"], original.BeforePolicy.Table, original.BeforePolicy.Chain, labels(from), labels(to), original.ProcessStartBefore}, nil
}

func intrusionPortTemplateMutationDecode(raw []byte, original intrusionJournalPlan, change intrusionPortRecipeChange) (intrusionPortTemplateReceipt, error) {
	var out intrusionPortTemplateReceipt
	if _, err := intrusionPortTemplateMutationArgs(original, change); err != nil {
		return out, err
	}
	if len(raw) < 1 || len(raw) > 1024 || decodeProgramQueueJSON(raw, &out) != nil || out.Format != 1 || out.PID != original.ProcessBefore || out.StartTicks != original.ProcessStartBefore || out.Field != change.Field || out.Action != original.BeforePolicy.Action || out.FromSHA256 != core.Hash(change.From) || out.ToSHA256 != core.Hash(change.To) || out.Applied == out.AlreadyTarget {
		return intrusionPortTemplateReceipt{}, errors.New("入侵防护模板回执未知或摘要不符；保留原事务，未重试")
	}
	canonical, err := json.Marshal(out)
	if err != nil || strings.TrimSuffix(string(raw), "\n") != string(canonical) {
		return intrusionPortTemplateReceipt{}, errors.New("入侵防护模板回执不是字段完整的规范结果；未重试")
	}
	return out, nil
}
