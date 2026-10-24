//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"slices"
)

// Fail2ban's configuration reader resolves port literals in actionstart and
// actionflush before loading them. Setting only the port property does NOT
// regenerate those two declarations. A transaction must qualify all THREE
// independent original BEFORE/AFTER fields, including interruption states.
// This is a PURE model: it never sends properties or executes any command.
type intrusionPortRecipeChange struct{ Field, From, To string }
type intrusionPortRecipePlan struct {
	Process, Action string
	Changes         []intrusionPortRecipeChange
}

func intrusionPortRecipeTarget(original intrusionJournalPlan) (map[string]string, error) {
	if err := intrusionJournalValidate(original); err != nil {
		return nil, err
	}
	return intrusionPortRecipeTargetForValidatedOriginal(original)
}

// Only synchronous callers that already validated this unchanged original
// plan may share its PURE derivation. No lock, pending-byte/boot/PID, actual
// file/dump or kernel observation check is cached or removed at a write gate.
func intrusionPortRecipeTargetForValidatedOriginal(original intrusionJournalPlan) (map[string]string, error) {
	policy := original.BeforePolicy
	policy.Ports = slices.Clone(original.TargetPorts)
	values, err := intrusionStockActionValues(policy, original.ActionBefore.Values["nftables"], original.ActionBefore.Values["chain"])
	if err != nil {
		return nil, err
	}
	values["banEpoch"] = original.ActionBefore.Values["banEpoch"]
	return values, nil
}

// This broader observation is valid ONLY inside a byte-exact pending original
// transaction; the ordinary public/runtime recipe validator stays strict.
// No unknown init option/property/command is ignored. Every non-port-bearing
// field is EXACTLY the original, including action generation and empty verbs.
func intrusionPortRecipeDecode(raw string, original intrusionJournalPlan) (intrusionActionRecipe, error) {
	values, err := intrusionPortRecipeTarget(original)
	if err != nil {
		return intrusionActionRecipe{}, err
	}
	return intrusionPortRecipeDecodeAgainstValidatedOriginal(raw, original, values)
}

func intrusionPortRecipeDecodeAgainstValidatedOriginal(raw string, original intrusionJournalPlan, values map[string]string) (out intrusionActionRecipe, err error) {
	defer func() {
		if err != nil {
			out = intrusionActionRecipe{}
		}
	}()
	if len(raw) < 1 || len(raw) > 24<<10 || decodeProgramQueueJSON([]byte(raw), &out) != nil || out.Format != 1 || out.Action != original.BeforePolicy.Action || !slices.Equal(out.Properties, original.ActionBefore.Properties) || len(out.Values) != len(original.ActionBefore.Values) {
		return out, errors.New("入侵防护原端口动作观察不是完整固定属性范围；未接管额外选项")
	}
	for key, before := range original.ActionBefore.Values {
		now, exists := out.Values[key]
		if !exists {
			return out, errors.New("入侵防护原动作字段缺失；未把缺失值当作空命令")
		}
		if now == before {
			continue
		}
		if !slices.Contains([]string{"port", "actionstart", "actionflush"}, key) || now != values[key] {
			return out, errors.New("入侵防护实际动作不是原端口事务的完整前后值；未执行或恢复外部命令")
		}
	}
	return out, nil
}

func intrusionPortRecipeChanges(original intrusionJournalPlan, current intrusionActionRecipe, state string) (out intrusionPortRecipePlan, err error) {
	defer func() {
		if err != nil {
			out = intrusionPortRecipePlan{}
		}
	}()
	if state != "committed" && state != "rolled_back" {
		return out, errors.New("入侵防护端口动作目标状态未知")
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return out, err
	}
	wanted, err := intrusionPortRecipeTarget(original)
	if err != nil {
		return out, err
	}
	if _, err = intrusionPortRecipeDecodeAgainstValidatedOriginal(string(raw), original, wanted); err != nil {
		return out, err
	}
	if state == "rolled_back" {
		wanted = original.ActionBefore.Values
	}
	out = intrusionPortRecipePlan{Process: original.ProcessBefore, Action: original.BeforePolicy.Action, Changes: []intrusionPortRecipeChange{}}
	for _, key := range []string{"actionstart", "actionflush", "port"} {
		if current.Values[key] != wanted[key] {
			out.Changes = append(out.Changes, intrusionPortRecipeChange{Field: key, From: current.Values[key], To: wanted[key]})
		}
	}
	return out, nil
}
