//go:build linux

package executor

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Installing names with --no-upgrade is not evidence that the actual host
// libraries meet the package's ABI constraints. Recheck the authenticated
// dependency expressions against fully installed versions, without asking APT
// to upgrade a library or mixing the vendor catalog into system dependency
// resolution. The expression parser has already rejected arbitrary commands,
// profiles, unreviewed packages and unreviewed alternatives.
func (s *Service) threatIDSCheckInstalledDependencies(ctx context.Context, raw string) error {
	if _, err := threatIDSDependencies(raw); err != nil {
		return err
	}
	for _, entry := range strings.Split(raw, ",") {
		first := strings.TrimSpace(strings.Split(entry, "|")[0])
		fields := strings.Fields(first)
		name := fields[0]
		if threatIDSNonEngineDependency(name) {
			continue
		}
		state, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Status}\t${Version}", "--", name)
		status, version, ok := strings.Cut(strings.TrimSpace(state), "\t")
		if err != nil || !ok || status != "installed" || version == "" || len(version) > 128 || strings.ContainsAny(version, " \r\n\t\x00") || version[0] < '0' || version[0] > '9' {
			return errors.New("IDS 实际固定库没有完整安装或版本不可核对；未升级库、启动或激活候选")
		}
		if len(fields) == 1 {
			continue
		}
		if len(fields) != 3 {
			return errors.New("IDS 固定库版本约束不完整")
		}
		op := map[string]string{"(>=": "ge", "(=": "eq", "(>>": "gt", "(<=": "le", "(<<": "lt"}[fields[1]]
		wanted := strings.TrimSuffix(fields[2], ")")
		if op == "" || wanted == "" || wanted[0] < '0' || wanted[0] > '9' {
			return errors.New("IDS 固定库版本约束不在已审核结构中")
		}
		if _, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/dpkg", "--compare-versions", version, op, wanted); err != nil {
			return errors.New("IDS 系统原有库低于候选程序的 ABI 要求；未跨软件源升级库或激活候选")
		}
	}
	return nil
}
