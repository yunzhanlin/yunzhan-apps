//go:build linux

package executor

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Private observations for the future durable writer. Historical ban addresses
// are never targets. A successful snapshot alone grants NO mutation authority.
type intrusionRuntimeState struct {
	Policy           intrusionManagedPolicy
	SSHPorts         []int
	Settings         map[string]int
	Bans             []netip.Addr
	Kernel           []byte
	KernelDirectory  []byte
	KernelState      string
	KernelScopePorts []int
	KernelPortsBySet map[string][]int
	KernelIdentity   string
	Process          string
	ProcessStart     string
	JournalMatch     string
	Recipe           intrusionActionRecipe
	FilterMetadata   intrusionFilterMetadata
}

func intrusionFail2banProcess(raw string) (string, error) {
	if len(raw) > 256 || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(raw, "\r\x00") {
		return "", errors.New("Fail2ban 进程观察无效")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "MainPID" && key != "ActiveState" || fields[key] != "" || value == "" {
			return "", errors.New("Fail2ban 进程状态不是完整固定字段")
		}
		fields[key] = value
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	if len(fields) != 2 || fields["ActiveState"] != "active" || err != nil || pid < 2 || pid > 1<<22 || strconv.Itoa(pid) != fields["MainPID"] {
		return "", errors.New("Fail2ban 未处于明确的已运行进程状态；未自动启用或重启")
	}
	return fields["MainPID"], nil
}

func intrusionRuntimeJournalMatch(raw string) (string, error) {
	// These are the actual default systemd match shapes observed on the two
	// declared native distributions. A custom/file backend is not silently
	// converted to systemd: Fail2ban would restart that Jail and lose bans.
	// Debian 13's packaged OpenSSH 10 filter also covers sshd-session. Keep
	// its complete disjunction, not a guessed substring or a backend change.
	for _, match := range []string{
		"_SYSTEMD_UNIT=sshd.service + _COMM=sshd",
		"_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
		"_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session",
	} {
		if raw == "Current match filter:\n"+match+"\n" {
			return match, nil
		}
	}
	return "", errors.New("运行中 Jail 未核对为支持的实际 systemd 后端；未切换后端或重启")
}

func intrusionRuntimeLimits(read func(string, ...string) (string, error)) (map[string]int, error) {
	out := map[string]int{}
	for _, item := range []struct {
		name, property string
		factor         int
	}{{"max_retry", "maxretry", 1}, {"find_time_minutes", "findtime", 60}, {"ban_time_minutes", "bantime", 60}} {
		raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", item.property)
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSuffix(raw, "\n"))
		if err != nil || raw != strconv.Itoa(n)+"\n" || n < 1 || n%item.factor != 0 {
			return nil, errors.New("运行中 Jail 限额不是规范的完整分钟配置")
		}
		out[item.name] = n / item.factor
	}
	_, err := intrusionJournalSettings(out)
	return out, err
}

func intrusionRuntimePolicy(read func(string, ...string) (string, error)) (intrusionManagedPolicy, error) {
	return intrusionRuntimePolicyForOriginal(read, nil)
}

func intrusionRuntimePolicyForOriginal(read func(string, ...string) (string, error), original *intrusionJournalPlan) (intrusionManagedPolicy, error) {
	var out intrusionManagedPolicy
	raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "actions")
	if err != nil {
		return out, err
	}
	names, err := intrusionActionNames(raw)
	if err != nil || len(names) != 1 || (names[0] != "nftables" && names[0] != "nftables-multiport") {
		return out, errors.New("SSH Jail 不是唯一受支持的 nftables 动作，未替换或移除其他动作")
	}
	out.Format, out.Action = 1, names[0]
	raw, err = read("/usr/bin/fail2ban-client", "get", "sshd", "maxmatches")
	if err != nil {
		return out, err
	}
	out.MaxMatches, err = strconv.Atoi(strings.TrimSuffix(raw, "\n"))
	if err != nil || raw != strconv.Itoa(out.MaxMatches)+"\n" || out.MaxMatches < 1 || out.MaxMatches > 1024 {
		return out, errors.New("SSH Jail 运行中匹配容量无法完整核对")
	}
	property := func(name string) (string, error) {
		return read("/usr/bin/fail2ban-client", "get", "sshd", "action", out.Action, name)
	}
	raw, err = property("port")
	if err != nil {
		return out, err
	}
	out.Ports, err = intrusionPortList(raw)
	if err != nil {
		return out, err
	}
	protocol, err := property("protocol")
	if err != nil || protocol != "tcp\n" {
		return out, errors.New("SSH Jail 动作协议不是明确的 TCP")
	}
	for _, item := range []struct {
		name   string
		target *string
	}{{"name", &out.Name}, {"table", &out.Table}} {
		raw, err = property(item.name)
		if err != nil {
			return out, err
		}
		*item.target, err = intrusionNftProperty(raw)
		if err != nil || !intrusionNftWriteName(*item.target) {
			return out, errors.New("SSH Jail 动作名称或表身份未知")
		}
	}
	family, err := property("table_family")
	if err != nil || family != "inet\n" {
		return out, errors.New("SSH Jail 动作地址族不是支持的 inet")
	}
	for _, item := range []struct {
		name   string
		target *string
	}{{"addr_set", &out.IPv4Set}, {"addr_set?family=inet6", &out.IPv6Set}} {
		raw, err = property(item.name)
		if err != nil {
			return out, err
		}
		*item.target, err = intrusionNftSetProperty(raw, out.Name)
		if err != nil {
			return out, err
		}
	}
	raw, err = property("chain")
	if err != nil {
		return out, err
	}
	out.Chain, err = intrusionNftProperty(raw)
	if err != nil {
		return out, err
	}
	// Always check the complete resolved fixed recipe, including when chain is
	// literal. A successful kernel sample must not authorize reloading a custom
	// root action with side effects or a different rule-generation recipe.
	resolved, err := property("actionstart")
	if err != nil {
		return out, err
	}
	chain, err := intrusionNftLazyChain(resolved, out.Table, out.Ports)
	if err != nil && original != nil {
		// A fixed property SET does not regenerate a resolved actionstart.
		// ONLY the guarded original reader can observe independent original
		// BEFORE/AFTER literals; the ordinary reader remains strict.
		for _, ports := range [][]int{original.BeforePolicy.Ports, original.TargetPorts} {
			chain, err = intrusionNftLazyChain(resolved, out.Table, ports)
			if err == nil {
				break
			}
		}
	}
	if err != nil || (out.Chain != "<known/chain>" && out.Chain != chain) {
		return out, errors.New("SSH Jail 完整动作与当前端口和链身份不符，未执行重载")
	}
	out.Chain = chain
	return out, intrusionPolicyValidate(out)
}

func (s *Service) readIntrusionMutationRuntime(ctx context.Context) (intrusionRuntimeState, error) {
	return s.readIntrusionRuntime(ctx, nil)
}

func (s *Service) readIntrusionRuntime(ctx context.Context, original *intrusionJournalPlan) (out intrusionRuntimeState, probeErr error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			probeErr = errors.New("入侵防护实际观察超过固定时间上限或已取消；未将不完整采样作为变更依据")
		}
	}()
	readActual := s.intrusionReadOnlySession(ctx)
	read := func(program string, args ...string) (string, error) {
		raw, err := readActual(program, args...)
		if err != nil {
			return "", errors.New("入侵防护实际观察失败: " + filepath.Base(program))
		}
		if len(raw) > 24<<10 || strings.ContainsRune(raw, 0) {
			return "", errors.New("入侵防护实际观察超限或不完整")
		}
		return raw, nil
	}
	process := func() (string, error) {
		raw, err := read("/usr/bin/systemctl", "show", "fail2ban.service", "--property=MainPID,ActiveState")
		if err != nil {
			return "", err
		}
		return intrusionFail2banProcess(raw)
	}
	journal := func() (string, error) {
		raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "journalmatch")
		if err != nil {
			return "", err
		}
		return intrusionRuntimeJournalMatch(raw)
	}
	ssh := func() ([]int, error) {
		raw, err := read("/usr/sbin/sshd", "-T")
		if err != nil {
			return nil, err
		}
		ports, err := intrusionSSHDPorts(raw)
		if err != nil {
			return nil, err
		}
		raw, err = read("/usr/bin/ss", "-H", "-ltnp")
		if err != nil {
			return nil, err
		}
		listening, err := intrusionListeningPorts(raw)
		if err != nil || !slices.Equal(ports, listening) {
			return nil, errors.New("SSHD 实际配置与监听端口不一致，未猜测默认端口")
		}
		return ports, nil
	}
	bans := func() ([]netip.Addr, error) {
		raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "banip")
		if err != nil {
			return nil, err
		}
		return intrusionBannedAddresses(raw)
	}
	var err error
	if out.Process, err = process(); err != nil {
		return out, err
	}
	if out.ProcessStart, err = intrusionReadProcessStart(read); err != nil {
		return out, err
	}
	if out.JournalMatch, err = journal(); err != nil {
		return out, err
	}
	if out.FilterMetadata, err = intrusionReadFilterMetadata(read); err != nil {
		return out, err
	}
	if out.SSHPorts, err = ssh(); err != nil {
		return out, err
	}
	if out.Settings, err = intrusionRuntimeLimits(read); err != nil {
		return out, err
	}
	if out.Policy, err = intrusionRuntimePolicyForOriginal(read, original); err != nil {
		return out, err
	}
	recipe := func(policy intrusionManagedPolicy) (intrusionActionRecipe, error) {
		raw, e := read("/usr/bin/fail2ban-client", "get", "sshd", "actionproperties", policy.Action)
		if e != nil {
			return intrusionActionRecipe{}, e
		}
		if original != nil {
			return intrusionPortRecipeDecode(raw, *original)
		}
		return intrusionActionRecipeValidate(raw, policy)
	}
	if out.Recipe, err = recipe(out.Policy); err != nil {
		return out, err
	}
	if original != nil {
		if _, err := intrusionJournalScalarPlan(*original, out, "committed"); err != nil {
			return out, err
		}
		if !slices.Equal(out.SSHPorts, intrusionJournalObservedSSHPorts(*original)) {
			return out, errors.New("实际 SSH 监听已偏离原事务准备时观察，未调整外部配置或猜测新防护端口")
		}
	}
	if out.Bans, err = bans(); err != nil {
		return out, err
	}
	kernel, err := intrusionObserveRuntimeKernel(read, out.Policy, out.Bans, original)
	if err != nil {
		return out, err
	}
	out.Kernel, out.KernelDirectory = kernel.Raw, kernel.Directory
	out.KernelState, out.KernelScopePorts, out.KernelIdentity = kernel.Scope.State, kernel.Scope.Ports, kernel.Scope.StaticIdentity
	out.KernelPortsBySet = kernel.Scope.PortsBySet
	// A torn combination of independently valid CLI samples is not a durable
	// BEFORE state. Require identical policy, limits, backend, SSH and process.
	nowPolicy, err := intrusionRuntimePolicyForOriginal(read, original)
	if err != nil {
		return out, err
	}
	nowRecipe, err := recipe(nowPolicy)
	if err != nil {
		return out, err
	}
	nowSettings, err := intrusionRuntimeLimits(read)
	if err != nil {
		return out, err
	}
	nowBans, err := bans()
	if err != nil {
		return out, err
	}
	nowSSH, err := ssh()
	if err != nil {
		return out, err
	}
	nowJournal, err := journal()
	if err != nil {
		return out, err
	}
	nowFilter, err := intrusionReadFilterMetadata(read)
	if err != nil || nowFilter != out.FilterMetadata {
		return out, errors.New("过滤器可读元数据在内核观察前后改变；未接受混合状态")
	}
	nowProcess, err := process()
	if err != nil {
		return out, err
	}
	nowStart, err := intrusionReadProcessStart(read)
	if err != nil || nowStart != out.ProcessStart {
		return out, errors.New("Fail2ban 内核进程起始身份在观察期间变化；未把复用的进程号作为原服务")
	}
	if !reflect.DeepEqual(out.Policy, nowPolicy) || !reflect.DeepEqual(out.Recipe, nowRecipe) || !reflect.DeepEqual(out.Settings, nowSettings) || !slices.Equal(out.Bans, nowBans) || !slices.Equal(out.SSHPorts, nowSSH) || out.JournalMatch != nowJournal || out.Process != nowProcess {
		return out, errors.New("入侵防护实际状态在观察期间改变，未将混合采样作为变更依据")
	}
	// Re-observe actual kernel policy AFTER the second daemon observation.
	// Re-reading only the daemon could miss replacement handles, bypass rules,
	// or changes in a shared table while all daemon properties remain valid.
	if err := intrusionRuntimeKernelTransactionRecheck(read, out, original); err != nil {
		return out, err
	}
	return out, nil
}
