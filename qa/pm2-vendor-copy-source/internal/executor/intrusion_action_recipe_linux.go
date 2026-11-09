//go:build linux

package executor

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

func renderIntrusionManagedScope(settings map[string]any, policy intrusionManagedPolicy) (string, error) {
	if err := intrusionPolicyValidate(policy); err != nil {
		return "", err
	}
	jail, err := renderIntrusionPortScope(settings, policy.Ports)
	if err != nil {
		return "", err
	}
	// maxretry defaults can otherwise change maxmatches on a later boot.
	// Persist the independently observed original capacity, not the new retry.
	return jail + "maxmatches = " + strconv.Itoa(policy.MaxMatches) + "\n", nil
}

type intrusionActionRecipe struct {
	Format     int               `json:"format"`
	Action     string            `json:"action"`
	Properties []string          `json:"properties"`
	Values     map[string]string `json:"values"`
}

// These are the closed stock nft multiport semantics supported by the first
// transaction migration. Strings observed from the daemon are NEVER executed.
// In particular no custom reload/reban/repair/prolong verb can be adopted.
func intrusionStockActionValues(policy intrusionManagedPolicy, program, chainProperty string) (map[string]string, error) {
	if intrusionPolicyValidate(policy) != nil || program != "nft" && program != "/usr/sbin/nft" && program != "/usr/bin/nft" || chainProperty != policy.Chain && chainProperty != "<known/chain>" {
		return nil, errors.New("入侵防护完整动作身份未支持安全接管")
	}
	labels := make([]string, len(policy.Ports))
	for i, p := range policy.Ports {
		labels[i] = strconv.Itoa(p)
	}
	set := func(name string) string {
		// The only substitution accepted by upstream's set-name grammar.
		if name == "addr-set-"+policy.Name {
			return "addr-set-<name>"
		}
		if name == "addr6-set-"+policy.Name {
			return "addr6-set-<name>"
		}
		return name
	}
	addSet := fmt.Sprintf(`%s add set inet %s <addr_set> \{ type <addr_type>\; \}`, program, policy.Table)
	addRule := fmt.Sprintf("for proto in $(echo 'tcp' | sed 's/,/ /g'); do\n%s add rule inet %s %s $proto dport \\{ $(echo '%s' | sed s/:/-/g) \\} <addr_family> saddr @<addr_set> reject\ndone", program, policy.Table, policy.Chain, strings.Join(labels, ","))
	deleteRuleAndSet := fmt.Sprintf(`{ %s -a list chain inet %s %s | grep -oP '@<addr_set>\s+.*\s+\Khandle\s+(\d+)$'; } | while read -r hdl; do
%s delete rule inet %s %s $hdl; done
%s delete set inet %s <addr_set>`, program, policy.Table, policy.Chain, program, policy.Table, policy.Chain, program, policy.Table)
	values := map[string]string{
		"actionstart": fmt.Sprintf("%s add table inet %s\n%s -- add chain inet %s %s \\{ type filter hook input priority -1 \\; \\}\n%s\n%s", program, policy.Table, program, policy.Table, policy.Chain, addSet, addRule),
		"actionstop":  deleteRuleAndSet + fmt.Sprintf("\n{ %s list table inet %s | grep -qP '^\\s+set\\s+'; } || {\n%s delete table inet %s\n}", program, policy.Table, program, policy.Table),
		"actionflush": fmt.Sprintf("{ %s flush set inet %s <addr_set> 2> /dev/null; } || {\n%s\n%s\n%s\n}", program, policy.Table, deleteRuleAndSet, addSet, addRule),
		"actioncheck": fmt.Sprintf(`%s list chain inet %s %s | grep -q '@<addr_set>[ \t]'`, program, policy.Table, policy.Chain),
		"actionban":   fmt.Sprintf(`%s add element inet %s <addr_set> \{ <ip> \}`, program, policy.Table),
		"actionunban": fmt.Sprintf(`%s delete element inet %s <addr_set> \{ <ip> \}`, program, policy.Table),
		"port":        strings.Join(labels, ","), "protocol": "tcp", "chain": chainProperty,
		"name": policy.Name, "actname": policy.Action, "table": policy.Table, "table_family": "inet",
		"chain_type": "filter", "chain_hook": "input", "chain_priority": "-1", "addr_type": "ipv4_addr",
		"blocktype": "reject", "nftables": program, "addr_set": set(policy.IPv4Set), "addr_family": "ip",
		"addr_family?family=inet6": "ip6", "addr_type?family=inet6": "ipv6_addr", "addr_set?family=inet6": set(policy.IPv6Set),
		"actionreban": "", "actionreload": "", "actionrepair": "", "timeout": "60",
	}
	return values, nil
}

func intrusionActionRecipeValidate(raw string, policy intrusionManagedPolicy) (intrusionActionRecipe, error) {
	var out intrusionActionRecipe
	if len(raw) < 1 || len(raw) > 24<<10 || decodeProgramQueueJSON([]byte(raw), &out) != nil || out.Format != 1 || out.Action != policy.Action {
		return out, errors.New("入侵防护完整动作观察身份、格式或容量无法核对")
	}
	expected, err := intrusionStockActionValues(policy, out.Values["nftables"], out.Values["chain"])
	if err != nil {
		return out, err
	}
	epoch, err := strconv.ParseUint(out.Values["banEpoch"], 10, 53)
	if err != nil || strconv.FormatUint(epoch, 10) != out.Values["banEpoch"] {
		return out, errors.New("入侵防护动作代次不是规范观察")
	}
	expected["banEpoch"] = out.Values["banEpoch"]
	keys := []string{"ESCAPE_CRE", "ESCAPE_VN_CRE"}
	for name := range expected {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, out.Properties) || !reflect.DeepEqual(expected, out.Values) {
		return out, errors.New("入侵防护完整动作存在自定义命令、附加属性或与实际范围不符；未执行重载")
	}
	return out, nil
}
