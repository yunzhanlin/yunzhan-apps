package executor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This is the existing Nginx body/HTML root-supervisor budget, not authority
// for source code. Every source command separately switches to panel-build
// and clears active, inherited and ambient capabilities with fixed setpriv.
// Require the actual effective set before creating records or downloading.
func validateNginxNativeWorkerCapabilities(data []byte) error {
	if len(data) == 0 || len(data) > 32<<10 || !strings.HasSuffix(string(data), "\n") || strings.ContainsAny(string(data), "\r\x00") {
		return errors.New("原生引擎监督进程权限记录无效，未开始写入或编译")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "NoNewPrivs" && key != "CapInh" && key != "CapPrm" && key != "CapEff" && key != "CapBnd" && key != "CapAmb") {
			continue
		}
		if _, exists := fields[key]; exists {
			return errors.New("原生引擎监督进程权限记录重复，未开始写入或编译")
		}
		fields[key] = strings.TrimSpace(value)
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("原生引擎监督进程缺少禁止提权约束，未开始写入或编译")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, err := strconv.ParseUint(fields[key], 16, 64)
		if err != nil || len(fields[key]) != 16 || fields[key] != strings.ToLower(fields[key]) || value != 0xeb {
			return fmt.Errorf("原生引擎监督进程 %s 不是固定完整权限集合，未开始写入或编译", key)
		}
	}
	return nil
}
