//go:build linux

package executor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Upstream 1.0.2/1.1.0 expose chain=<known/chain>, but the actionstart getter
// resolves it. Accept only the COMPLETE fixed upstream multiport recipe to
// locate its literal chain in an otherwise lazy shared table. This string is
// NEVER executed, persisted as executable authority or returned to the UI.
// Custom recipes remain unverified; extracting one plausible line is unsafe.
func intrusionNftLazyChain(raw, table string, ports []int) (string, error) {
	if len(raw) < 1 || len(raw) > 4096 || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(raw, "\r\x00") || !intrusionNftWriteName(table) || intrusionJournalPorts(ports) != nil {
		return "", errors.New("延迟内核链的固定动作观察无效")
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) != 6 {
		return "", errors.New("延迟内核链不是完整受支持动作结构")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 16 || !intrusionNftWriteName(fields[6]) {
		return "", errors.New("延迟内核链身份无法从固定动作完整核对")
	}
	chain := fields[6]
	labels := make([]string, len(ports))
	for i, p := range ports {
		labels[i] = strconv.Itoa(p)
	}
	for _, program := range []string{"nft", "/usr/sbin/nft", "/usr/bin/nft"} {
		expected := fmt.Sprintf(`%s add table inet %s
%s -- add chain inet %s %s \{ type filter hook input priority -1 \; \}
%s add set inet %s <addr_set> \{ type <addr_type>\; \}
for proto in $(echo 'tcp' | sed 's/,/ /g'); do
%s add rule inet %s %s $proto dport \{ $(echo '%s' | sed s/:/-/g) \} <addr_family> saddr @<addr_set> reject
done
`, program, table, program, table, chain, program, table, program, table, chain, strings.Join(labels, ","))
		if raw == expected {
			return chain, nil
		}
	}
	return "", errors.New("延迟内核链的完整动作与固定上游规则不符，未解释或执行命令")
}
