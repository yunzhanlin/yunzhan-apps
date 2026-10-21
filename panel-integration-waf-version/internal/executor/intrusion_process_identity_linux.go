//go:build linux

package executor

import (
	_ "embed"
	"errors"
	"strconv"
	"strings"
)

//go:embed intrusion_process_identity.py
var intrusionProcessIdentityScript string

func intrusionProcessTicksValid(raw string) bool {
	if len(raw) < 1 || len(raw) > 20 || raw[0] == '0' {
		return false
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && value > 0 && strconv.FormatUint(value, 10) == raw
}

func intrusionReadProcessStart(read func(string, ...string) (string, error)) (string, error) {
	raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "process-start")
	value := strings.TrimSuffix(raw, "\n")
	if err != nil || raw != value+"\n" || !intrusionProcessTicksValid(value) {
		return "", errors.New("Fail2ban 原进程内核起始身份无法核对；未仅凭相同进程号继续")
	}
	return value, nil
}
