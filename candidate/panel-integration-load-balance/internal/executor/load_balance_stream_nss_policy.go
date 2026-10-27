package executor

import (
	"bytes"
	"errors"
	"strings"
)

var errLoadBalanceStreamNSSPolicy = errors.New("TCP/UDP 专用身份仅支持经核对的 files/systemd NSS 配置；当前身份源尚未支持，未修改系统认证配置或创建账户")

// Network-backed NSS may turn an unavailable lookup into the same getent exit
// as absence inside a restricted child. Do not guess or change nsswitch.conf.
// Other databases (hosts, DNS, services, etc.) are not constrained or modified.
func validateLoadBalanceStreamNSSPolicy(raw []byte) error {
	if len(raw) == 0 || len(raw) > 65536 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return errLoadBalanceStreamNSSPolicy
	}
	wanted := map[string]bool{"passwd": true, "group": true, "shadow": true, "gshadow": true, "initgroups": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !wanted[name] {
			// A misspelled separator must not conceal a second critical line.
			fields := strings.Fields(line)
			if len(fields) > 0 && wanted[fields[0]] {
				return errLoadBalanceStreamNSSPolicy
			}
			continue
		}
		if !ok || seen[name] {
			return errLoadBalanceStreamNSSPolicy
		}
		seen[name] = true
		fields := strings.Fields(value)
		valid := len(fields) == 1 && fields[0] == "files" || len(fields) == 2 && fields[0] == "files" && fields[1] == "systemd"
		// systemd's documented optional supplementary-group merge is exact;
		// no NOTFOUND/UNAVAIL shortcut or caller-defined NSS service is allowed.
		if name == "group" || name == "initgroups" {
			valid = valid || len(fields) == 3 && fields[0] == "files" && fields[1] == "[SUCCESS=merge]" && fields[2] == "systemd"
		}
		if !valid {
			return errLoadBalanceStreamNSSPolicy
		}
	}
	for _, name := range []string{"passwd", "group", "shadow", "gshadow"} {
		if !seen[name] {
			return errLoadBalanceStreamNSSPolicy
		}
	}
	return nil
}
