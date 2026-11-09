package executor

import (
	"errors"
	"strings"
)

// Inspect actual ELF output, not a successful configure/make exit code or a
// compiler-flag declaration. Native Apache -t remains a separate ABI check.
func verifyApacheBodyELFHardening(dynamic, programHeaders, symbols string) error {
	for _, output := range []string{dynamic, programHeaders, symbols} {
		if len(output) == 0 || len(output) > 1<<20 || strings.ContainsRune(output, '\x00') {
			return errors.New("Apache 模块 ELF 加固证据为空、异常或超过上限")
		}
	}
	if !strings.Contains(dynamic, "BIND_NOW") {
		return errors.New("Apache 模块缺少实际立即绑定加固")
	}
	stack, relro := 0, 0
	for _, line := range strings.Split(programHeaders, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "GNU_STACK":
			stack++
			if len(fields) != 8 || fields[6] != "RW" {
				return errors.New("Apache 模块栈可执行或程序头不可验证")
			}
		case "GNU_RELRO":
			relro++
			if len(fields) != 8 || fields[6] != "R" {
				return errors.New("Apache 模块重定位只读区不可验证")
			}
		}
	}
	if stack != 1 || relro != 1 {
		return errors.New("Apache 模块缺少唯一非执行栈或只读重定位区")
	}
	for _, line := range strings.Split(symbols, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[3] == "FUNC" && fields[6] == "UND" {
			name, _, _ := strings.Cut(fields[7], "@")
			if name == "__stack_chk_fail" {
				return nil
			}
		}
	}
	return errors.New("Apache 模块缺少实际栈保护检查符号")
}
