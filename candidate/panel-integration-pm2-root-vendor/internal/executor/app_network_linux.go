//go:build linux

package executor

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

type networkListener struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Endpoint string `json:"endpoint"`
	Public   bool   `json:"public"`
	Process  string `json:"process,omitempty"`
}

func networkLines(raw string) ([]string, bool) {
	lines := []string{}
	limited := false
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(lines) >= 2000 {
			limited = true
			break
		}
		if len(line) > 2048 {
			line = line[:2048]
			limited = true
		}
		lines = append(lines, line)
	}
	return lines, limited
}

func parseNetworkListener(line string) (networkListener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || fields[0] != "tcp" && fields[0] != "udp" {
		return networkListener{}, false
	}
	endpoint := fields[4]
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		// ss may render an unbracketed IPv6 wildcard or address.
		index := strings.LastIndexByte(endpoint, ':')
		if index < 0 {
			return networkListener{}, false
		}
		host = strings.Trim(endpoint[:index], "[]")
	}
	public := true
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		public = !address.Unmap().IsLoopback()
	}
	process := ""
	if len(fields) > 6 {
		process = strings.Join(fields[6:], " ")
	}
	return networkListener{fields[0], fields[1], endpoint, public, process}, true
}

func buildNetworkThreatReport(listeners, connections, baseline []string, baselineKnown bool) map[string]any {
	current, previous := map[string]networkListener{}, map[string]networkListener{}
	invalid := 0
	for _, line := range listeners {
		listener, ok := parseNetworkListener(line)
		if !ok {
			invalid++
			continue
		}
		current[listener.Protocol+":"+listener.Endpoint] = listener
	}
	for _, line := range baseline {
		if listener, ok := parseNetworkListener(line); ok {
			previous[listener.Protocol+":"+listener.Endpoint] = listener
		}
	}
	keys := make([]string, 0, len(current))
	for key := range current {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	details, alerts := []networkListener{}, []map[string]any{}
	public, newPublic := 0, 0
	for _, key := range keys {
		listener := current[key]
		details = append(details, listener)
		if listener.Public {
			public++
		}
		if _, known := previous[key]; baselineKnown && !known {
			severity := "info"
			if listener.Public {
				severity = "warning"
				newPublic++
			}
			alerts = append(alerts, map[string]any{"kind": "new-listener", "protocol": listener.Protocol, "endpoint": listener.Endpoint, "public": listener.Public, "severity": severity, "advice": "核对服务和公网防火墙规则；监听变化本身不是入侵证据。"})
		}
	}
	keys = keys[:0]
	for key := range previous {
		if _, exists := current[key]; !exists && baselineKnown {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		old := previous[key]
		alerts = append(alerts, map[string]any{"kind": "closed-listener", "protocol": old.Protocol, "endpoint": old.Endpoint, "public": old.Public, "severity": "info", "advice": "核对是否为计划停服或端口迁移，不自动重启服务。"})
	}
	return map[string]any{"listeners": listeners, "listener_details": details, "connections": connections, "alerts": alerts, "baseline_present": baselineKnown, "listener_count": len(details), "public_listener_count": public, "new_public_listeners": newPublic, "connection_count": len(connections), "invalid_lines": invalid, "scope": "真实 TCP / UDP 监听和 TCP 连接快照；无可信基线时不生成变化告警，不执行封禁，不等同于流量内容 IDS"}
}
