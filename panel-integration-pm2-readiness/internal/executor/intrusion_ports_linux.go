//go:build linux

package executor

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
)

const intrusionMaxPorts = 16

// Only canonical numeric ports from fixed, numeric-output observations.
// An unknown service alias or all-ports action is not proof of SSH coverage.
func intrusionPortNumber(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != value {
		return 0, errors.New("SSH 防护端口不是规范的 1..65535 数字")
	}
	return n, nil
}

func intrusionPortList(raw string) ([]int, error) {
	if len(raw) > 512 || strings.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("SSH 防护端口输出不完整或超限")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\n\t") {
		return nil, errors.New("SSH 防护端口缺失或格式不明确")
	}
	seen := map[int]bool{}
	for _, piece := range strings.Split(raw, ",") {
		piece = strings.TrimSpace(piece)
		endpoints := strings.Split(piece, ":")
		if len(endpoints) > 2 {
			return nil, errors.New("SSH 防护端口范围格式无效")
		}
		first, err := intrusionPortNumber(endpoints[0])
		if err != nil {
			return nil, err
		}
		last := first
		if len(endpoints) == 2 {
			last, err = intrusionPortNumber(endpoints[1])
			if err != nil || last < first || last-first >= intrusionMaxPorts {
				return nil, errors.New("SSH 防护端口范围无效或超限")
			}
		}
		for port := first; port <= last; port++ {
			if seen[port] || len(seen) >= intrusionMaxPorts {
				return nil, errors.New("SSH 防护端口重复或超限")
			}
			seen[port] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func intrusionSSHDPorts(raw string) ([]int, error) {
	if len(raw) > 24<<10 || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("SSHD 实际配置输出不完整或超限")
	}
	ports := []int{}
	seen := map[int]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "port" {
			continue
		}
		if len(fields) != 2 {
			return nil, errors.New("SSHD 端口字段不完整")
		}
		port, err := intrusionPortNumber(fields[1])
		if err != nil {
			return nil, err
		}
		if !seen[port] {
			if len(ports) >= intrusionMaxPorts {
				return nil, errors.New("SSHD 端口数量超限")
			}
			ports = append(ports, port)
			seen[port] = true
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("未核对到 SSHD 明确端口；不猜测 22")
	}
	sort.Ints(ports)
	return ports, nil
}

// ss -H -ltnp is numeric and includes process identities. Socket activation
// without a visible sshd owner is deliberately unverified, never guessed.
func intrusionListeningPorts(raw string) ([]int, error) {
	if len(raw) > 24<<10 || strings.ContainsAny(raw, "\x00\r") || raw != "" && !strings.HasSuffix(raw, "\n") {
		return nil, errors.New("SSH 实际监听输出不完整或超限")
	}
	seen := map[int]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, `"sshd",pid=`) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "LISTEN" {
			return nil, errors.New("SSHD 监听记录格式无效")
		}
		_, label, err := net.SplitHostPort(fields[3])
		if err != nil {
			return nil, errors.New("SSHD 监听地址无法核对")
		}
		port, err := intrusionPortNumber(label)
		if err != nil {
			return nil, err
		}
		if !seen[port] && len(seen) >= intrusionMaxPorts {
			return nil, errors.New("SSH 实际监听端口数量超限")
		}
		seen[port] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("未核对到带 sshd 进程身份的实际监听")
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func intrusionActionNames(raw string) ([]string, error) {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("SSHD Jail 动作列表超限")
	}
	header := "The jail sshd has the following actions:\n"
	if !strings.HasPrefix(raw, header) || !strings.HasSuffix(raw, "\n") {
		return nil, errors.New("SSHD Jail 动作列表格式未知")
	}
	list := strings.TrimSuffix(strings.TrimPrefix(raw, header), "\n")
	if strings.ContainsAny(list, "\n\t") || list == "" {
		return nil, errors.New("SSHD Jail 动作列表缺失或不明确")
	}
	actions := []string{}
	seen := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		name := strings.TrimSpace(item)
		if len(name) == 0 || len(name) > 64 || seen[name] || len(actions) >= 8 {
			return nil, errors.New("SSHD Jail 动作名称重复或超限")
		}
		for i, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '.' || c == '-')) {
				return nil, errors.New("SSHD Jail 动作名称无效")
			}
		}
		seen[name] = true
		actions = append(actions, name)
	}
	sort.Strings(actions)
	return actions, nil
}
