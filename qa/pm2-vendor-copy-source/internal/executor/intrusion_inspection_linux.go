//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

type intrusionActionObservation struct {
	Name                string `json:"name"`
	Ports               []int  `json:"ports"`
	Protocol            string `json:"protocol"`
	ScopeVerified       bool   `json:"scope_verified"`
	KernelScopeVerified bool   `json:"kernel_scope_verified"`
	KernelScopeDeferred bool   `json:"kernel_scope_deferred"`
	KernelIPv4          bool   `json:"kernel_ipv4"`
	KernelIPv6          bool   `json:"kernel_ipv6"`
	Detail              string `json:"detail"`
}
type intrusionInspection struct {
	Format              int                          `json:"format"`
	CheckedAt           string                       `json:"checked_at"`
	Installed           bool                         `json:"installed"`
	Version             string                       `json:"version"`
	ServiceActive       bool                         `json:"service_active"`
	ConfigMatches       bool                         `json:"config_matches"`
	Healthy             bool                         `json:"healthy"`
	KernelScopeVerified bool                         `json:"kernel_scope_verified"`
	KernelScopeDeferred bool                         `json:"kernel_scope_deferred"`
	ActiveBansKnown     bool                         `json:"active_bans_known"`
	ActiveBans          int                          `json:"active_bans"`
	SSHEffectivePorts   []int                        `json:"ssh_effective_ports"`
	SSHListeningPorts   []int                        `json:"ssh_listening_ports"`
	SSHPortsMatch       bool                         `json:"ssh_ports_match"`
	Actions             []intrusionActionObservation `json:"actions"`
	Settings            map[string]int               `json:"settings"`
	RuntimeSettings     map[string]int               `json:"runtime_settings"`
	Warnings            []string                     `json:"warnings"`
	Detail              string                       `json:"detail"`
}

func intrusionSettings(settings map[string]any) (map[string]int, error) {
	if len(settings) != 3 {
		return nil, errors.New("SSH 防入侵清单配置字段不完整或未知")
	}
	out := map[string]int{}
	for name, bounds := range map[string][2]int{"max_retry": {2, 20}, "find_time_minutes": {1, 1440}, "ban_time_minutes": {10, 10080}} {
		raw, ok := settings[name]
		if !ok {
			return nil, errors.New("SSH 防入侵清单配置缺失")
		}
		var n int
		switch v := raw.(type) {
		case int:
			n = v
		case float64:
			if v < float64(bounds[0]) || v > float64(bounds[1]) || v != float64(int(v)) {
				return nil, errors.New("SSH 防入侵清单配置数值无效")
			}
			n = int(v)
		default:
			return nil, errors.New("SSH 防入侵清单配置类型无效")
		}
		if n < bounds[0] || n > bounds[1] {
			return nil, errors.New("SSH 防入侵清单配置数值超限")
		}
		out[name] = n
	}
	return out, nil
}

func renderIntrusionPortScope(settings map[string]any, ports []int) (string, error) {
	if _, err := intrusionSettings(settings); err != nil {
		return "", err
	}
	if len(ports) < 1 || len(ports) > intrusionMaxPorts {
		return "", errors.New("SSH 防护端口范围缺失")
	}
	labels := make([]string, len(ports))
	for i, p := range ports {
		if p < 1 || p > 65535 || i > 0 && ports[i-1] >= p {
			return "", errors.New("SSH 防护端口范围未规范化")
		}
		labels[i] = strconv.Itoa(p)
	}
	legacy := renderIntrusion(settings)
	return strings.Replace(legacy, "intrusion-prevention 1.0", "intrusion-prevention 1.1", 1) + "port = " + strings.Join(labels, ",") + "\nprotocol = tcp\n", nil
}

func (s *Service) intrusionConfigObservation() (fileBackup, error) {
	name := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
	if err := s.wafOwnedDirectory(filepath.Dir(name), false); err != nil {
		return fileBackup{}, fmt.Errorf("SSH 防护配置父路径无法核对，未修复: %w", err)
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return fileBackup{}, err
	}
	defer root.Close()
	return hardeningReadBackupLimit(root, filepath.Base(name), name, false, 16<<10)
}

// Every command is a fixed read-only CLI operation. Never return shell action
// bodies, log usernames, IP lists or configuration contents to this endpoint.
func (s *Service) inspectIntrusion(ctx context.Context) (out intrusionInspection, probeErr error) {
	out = intrusionInspection{Format: 1, CheckedAt: core.Now(), SSHEffectivePorts: []int{}, SSHListeningPorts: []int{}, Actions: []intrusionActionObservation{}, Settings: map[string]int{}, RuntimeSettings: map[string]int{}, Warnings: []string{}, Detail: "未安装；只读检查不自动安装、重启、封禁或解封"}
	manifest, err := s.readSoftwareManifest("intrusion-prevention")
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Installed = true
	out.Version = manifest.Version
	out.Settings, err = intrusionSettings(manifest.Settings)
	if err != nil {
		return out, err
	}
	before, err := s.intrusionConfigObservation()
	if err != nil {
		return out, err
	}
	var managedPolicy *intrusionManagedPolicy
	var managedFiles []fileBackup
	if intrusionManagedVersion(manifest.Version) {
		managedFiles, err = s.intrusionJournalCurrentFiles()
		if err != nil {
			return out, err
		}
		var policy intrusionManagedPolicy
		if !managedFiles[2].existed || decodeProgramQueueJSON(managedFiles[2].data, &policy) != nil || intrusionPolicyValidate(policy) != nil {
			return out, errors.New("防入侵1.1私有策略缺失或无法核对；未修复或回退旧版默认值")
		}
		managedPolicy = &policy
	} else if manifest.Version != "1.0" && manifest.Version != "1.0.0" {
		return out, errors.New("防入侵安装版本未支持独立检查")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			probeErr = errors.New("SSH 防护只读检查超过固定时间上限或已取消；状态尚未完整核对，没有执行修复")
		}
	}()
	readActual := s.intrusionReadOnlySession(ctx)
	read := func(program string, args ...string) (string, error) {
		value, err := readActual(program, args...)
		if err != nil {
			return "", fmt.Errorf("SSH 防护实际状态读取失败: %s", filepath.Base(program))
		}
		if len(value) > 24<<10 || strings.ContainsRune(value, 0) {
			return "", errors.New("SSH 防护实际输出超限或含非法字符")
		}
		return value, nil
	}
	config, e := read("/usr/sbin/sshd", "-T")
	if e == nil {
		out.SSHEffectivePorts, e = intrusionSSHDPorts(config)
	}
	if e != nil {
		out.Warnings = append(out.Warnings, e.Error())
	}
	listeners, e := read("/usr/bin/ss", "-H", "-ltnp")
	if e == nil {
		out.SSHListeningPorts, e = intrusionListeningPorts(listeners)
	}
	if e != nil {
		out.Warnings = append(out.Warnings, e.Error())
	}
	out.SSHPortsMatch = len(out.SSHEffectivePorts) > 0 && slices.Equal(out.SSHEffectivePorts, out.SSHListeningPorts)
	if !out.SSHPortsMatch {
		out.Warnings = append(out.Warnings, "SSHD 配置端口与实际监听不一致或无法核对；未猜测默认端口")
	}
	scoped, e := renderIntrusionPortScope(manifest.Settings, out.SSHEffectivePorts)
	out.ConfigMatches = before.existed && (string(before.data) == renderIntrusion(manifest.Settings) || e == nil && string(before.data) == scoped)
	if managedPolicy != nil {
		scoped, e = renderIntrusionManagedScope(manifest.Settings, *managedPolicy)
		out.ConfigMatches = e == nil && before.existed && string(before.data) == scoped && slices.Equal(managedPolicy.Ports, out.SSHEffectivePorts) && hardeningBackupSame(before, managedFiles[0])
	}
	if !out.ConfigMatches {
		out.Warnings = append(out.Warnings, "受管 Jail 文件与清单/端口范围不一致；未覆盖外部改动")
	}
	active, e := read("/usr/bin/systemctl", "is-active", "fail2ban")
	out.ServiceActive = e == nil && active == "active\n"
	if !out.ServiceActive {
		out.Warnings = append(out.Warnings, "Fail2ban 服务当前不是已核验的 active 状态")
	}
	if _, e = read("/usr/bin/fail2ban-client", "status", "sshd"); e != nil {
		out.Warnings = append(out.Warnings, "SSHD Jail 当前无法读取")
		return out, nil
	}
	banRaw, banErr := read("/usr/bin/fail2ban-client", "get", "sshd", "banip")
	banned, decodeErr := intrusionBannedAddresses(banRaw)
	out.ActiveBansKnown = banErr == nil && decodeErr == nil
	if out.ActiveBansKnown {
		out.ActiveBans = len(banned)
	} else {
		out.Warnings = append(out.Warnings, "运行中封禁列表无法完整核对；未确认内核作用域")
	}
	names, e := read("/usr/bin/fail2ban-client", "get", "sshd", "actions")
	var actions []string
	if e == nil {
		actions, e = intrusionActionNames(names)
	}
	if e != nil {
		out.Warnings = append(out.Warnings, "SSHD Jail 封禁动作无法完整核对")
	}
	for _, name := range actions {
		action := intrusionActionObservation{Name: name, Ports: []int{}, Detail: "未核验动作范围；没有执行或展示其命令"}
		if name != "nftables" && name != "nftables-multiport" && name != "iptables-multiport" {
			out.Actions = append(out.Actions, action)
			out.Warnings = append(out.Warnings, "存在尚未支持核验范围的 SSHD Jail 动作")
			continue
		}
		raw, readErr := read("/usr/bin/fail2ban-client", "get", "sshd", "action", name, "port")
		if readErr == nil {
			action.Ports, readErr = intrusionPortList(raw)
		}
		protocol, protocolErr := read("/usr/bin/fail2ban-client", "get", "sshd", "action", name, "protocol")
		action.Protocol = strings.TrimSpace(protocol)
		action.ScopeVerified = readErr == nil && protocolErr == nil && protocol == "tcp\n" && out.SSHPortsMatch && slices.Equal(action.Ports, out.SSHListeningPorts)
		if action.ScopeVerified {
			action.Detail = "运行中动作的数字端口范围与 SSH 实际监听一致；不是攻击拦截实测"
		} else {
			out.Warnings = append(out.Warnings, "运行中封禁动作未完整覆盖且仅覆盖 SSH 实际端口")
		}
		if action.ScopeVerified && out.ActiveBansKnown {
			if name == "nftables" || name == "nftables-multiport" {
				kernel, kernelErr := inspectIntrusionKernel(read, name, out.SSHListeningPorts, banned)
				if kernelErr != nil {
					out.Warnings = append(out.Warnings, kernelErr.Error())
				} else {
					action.KernelScopeVerified, action.KernelIPv4, action.KernelIPv6 = kernel.Verified, kernel.IPv4, kernel.IPv6
					action.KernelScopeDeferred = kernel.Deferred
					if kernel.Deferred {
						action.Detail = "当前无封禁且已核对受管内核作用域尚未创建；等待首次实际封禁验证，不宣称内核防护已经通过"
						out.Warnings = append(out.Warnings, action.Detail)
					} else {
						action.Detail = "实际内核端口规则与运行中封禁集合均通过核对；这是只读采样，不是攻击拦截旅程验收"
					}
				}
			} else {
				out.Warnings = append(out.Warnings, "当前动作的内核格式尚未支持完整核验；未仅凭运行属性认定健康")
			}
		}
		out.Actions = append(out.Actions, action)
	}
	for _, setting := range []struct {
		name, property string
		factor         int
	}{{"max_retry", "maxretry", 1}, {"find_time_minutes", "findtime", 60}, {"ban_time_minutes", "bantime", 60}} {
		raw, readErr := read("/usr/bin/fail2ban-client", "get", "sshd", setting.property)
		n, parseErr := strconv.Atoi(strings.TrimSuffix(raw, "\n"))
		if readErr != nil || parseErr != nil || n < 1 || raw != strconv.Itoa(n)+"\n" {
			out.Warnings = append(out.Warnings, "运行中 Jail 限额无法核对")
			continue
		}
		out.RuntimeSettings[setting.property] = n
		if n != out.Settings[setting.name]*setting.factor {
			out.Warnings = append(out.Warnings, "运行中 Jail 限额与安装清单不一致")
		}
	}
	if managedPolicy != nil {
		// Deliberately AFTER the kernel observation. The repeated get-actions
		// begins the second real batch; the final ban read then belongs to
		// that batch, not an unauthorized third phase or two prefetched reads.
		actual, readErr := intrusionRuntimePolicy(read)
		if readErr != nil || !reflect.DeepEqual(actual, *managedPolicy) {
			out.Warnings = append(out.Warnings, "运行中动作身份、匹配容量或端口与私有策略不一致；未确认受管作用域")
		}
	}
	if out.ActiveBansKnown {
		finalRaw, finalReadErr := read("/usr/bin/fail2ban-client", "get", "sshd", "banip")
		if finalReadErr != nil {
			return out, finalReadErr
		}
		finalBanned, finalDecodeErr := intrusionBannedAddresses(finalRaw)
		if finalDecodeErr != nil || !slices.Equal(banned, finalBanned) {
			return out, errors.New("封禁列表在只读采样期间变化，请刷新；未以旧列表确认内核作用域")
		}
	}
	after, e := s.intrusionConfigObservation()
	if e != nil || !hardeningBackupSame(before, after) {
		return out, errors.New("SSH 防护配置在采样期间改变，未确认生效")
	}
	now, e := s.readSoftwareManifest("intrusion-prevention")
	if e != nil || !reflect.DeepEqual(manifest, now) {
		return out, errors.New("SSH 防护安装清单在采样期间改变")
	}
	if managedPolicy != nil {
		afterFiles, err := s.intrusionJournalCurrentFiles()
		if err != nil {
			return out, err
		}
		for i := range managedFiles {
			if !hardeningBackupSame(managedFiles[i], afterFiles[i]) {
				return out, errors.New("防入侵私有策略或受管文件在检查期间改变")
			}
		}
	}
	out.KernelScopeVerified = len(out.Actions) > 0 && out.ActiveBansKnown
	allKnown := len(out.Actions) > 0 && out.ActiveBansKnown
	anyDeferred := false
	for _, action := range out.Actions {
		out.KernelScopeVerified = out.KernelScopeVerified && action.KernelScopeVerified
		allKnown = allKnown && (action.KernelScopeVerified || action.KernelScopeDeferred)
		anyDeferred = anyDeferred || action.KernelScopeDeferred
	}
	out.KernelScopeDeferred = allKnown && anyDeferred
	out.Healthy = out.ServiceActive && out.ConfigMatches && out.SSHPortsMatch && out.KernelScopeVerified && len(out.Warnings) == 0
	out.Detail = "只读采样核对受管文件、实际监听、Jail 限额和实际内核端口/封禁集合；不执行修复或宣称已经通过攻击拦截旅程验收"
	return out, nil
}

func (s *Service) intrusionInspectionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/intrusion-prevention/inspection", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		out, err := s.inspectIntrusionClosed(r.Context())
		if err != nil {
			respond(w, 409, map[string]any{"error": err.Error(), "state_unknown": true})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/intrusion-prevention/workspace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		out, err := s.inspectIntrusionWorkspace(r.Context())
		if err != nil {
			respond(w, 409, map[string]any{"error": "防入侵工作区尚未完整核对；未修复、重放或公开原始记录", "state_unknown": true})
			return
		}
		respond(w, 200, out)
	})
}
