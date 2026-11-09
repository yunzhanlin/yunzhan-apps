//go:build linux

package executor

import (
	_ "embed"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
)

//go:embed intrusion_scalar_mutation.py
var intrusionScalarMutationBody string

var intrusionScalarMutationScript = intrusionProcessIdentityScript + "\n" + intrusionScalarMutationBody

type intrusionScalarMutationReceipt struct {
	Format        int    `json:"format"`
	PID           string `json:"pid"`
	StartTicks    string `json:"start_ticks"`
	Field         string `json:"field"`
	Action        string `json:"action"`
	From          string `json:"from"`
	To            string `json:"to"`
	Applied       bool   `json:"applied"`
	AlreadyTarget bool   `json:"already_target"`
}

// Request grammar ONLY. There is intentionally no Config.Run call or public
// route here. The durable controller still needs pending-record verification,
// CAS, mixed-kernel observation, terminal publication and crash recovery.
func intrusionScalarMutationArgs(pid, start, action string, change intrusionScalarChange) ([]string, error) {
	if _, err := intrusionFail2banProcess("MainPID=" + pid + "\nActiveState=active\n"); err != nil {
		return nil, err
	}
	if !intrusionProcessTicksValid(start) {
		return nil, errors.New("标量变更缺少原进程内核起始身份")
	}
	if change.From == change.To {
		return nil, errors.New("未为无变化的标量生成变更请求")
	}
	if change.Key == "port" {
		if !slices.Contains([]string{"nftables", "nftables-multiport"}, action) {
			return nil, errors.New("标量动作身份未知")
		}
		for _, raw := range []string{change.From, change.To} {
			ports, err := intrusionPortList(raw)
			if err != nil {
				return nil, err
			}
			labels := make([]string, len(ports))
			for i, p := range ports {
				labels[i] = strconv.Itoa(p)
			}
			if strings.Join(labels, ",") != raw {
				return nil, errors.New("标量端口不是完整规范集合")
			}
		}
	} else {
		type limits struct{ min, max, factor int }
		bounds, ok := map[string]limits{"maxretry": {2, 20, 1}, "findtime": {60, 86400, 60}, "bantime": {600, 604800, 60}}[change.Key]
		if !ok {
			return nil, errors.New("未知标量字段不能生成执行请求")
		}
		action = "-"
		for _, raw := range []string{change.From, change.To} {
			n, err := strconv.Atoi(raw)
			if err != nil || strconv.Itoa(n) != raw || n < bounds.min || n > bounds.max || n%bounds.factor != 0 {
				return nil, errors.New("标量限额不规范或超限")
			}
		}
	}
	return []string{"-I", "-B", "-c", intrusionScalarMutationScript, pid, change.Key, action, change.From, change.To, start}, nil
}

func intrusionScalarMutationDecode(raw []byte, pid, start, action string, change intrusionScalarChange) (intrusionScalarMutationReceipt, error) {
	var out intrusionScalarMutationReceipt
	if _, err := intrusionScalarMutationArgs(pid, start, action, change); err != nil {
		return out, err
	}
	if change.Key != "port" {
		action = "-"
	}
	if len(raw) < 1 || len(raw) > 1024 || decodeProgramQueueJSON(raw, &out) != nil || out.Format != 1 || out.PID != pid || out.StartTicks != start || out.Field != change.Key || out.Action != action || out.From != change.From || out.To != change.To || out.Applied == out.AlreadyTarget {
		return intrusionScalarMutationReceipt{}, errors.New("标量变更回执不完整或身份不符；执行结果未知，未重试")
	}
	canonical, err := json.Marshal(out)
	if err != nil || strings.TrimSuffix(string(raw), "\n") != string(canonical) {
		return intrusionScalarMutationReceipt{}, errors.New("标量变更回执不是字段完整的规范结果；未重试")
	}
	return out, nil
}
