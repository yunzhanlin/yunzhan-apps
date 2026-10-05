//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const firewallConfigPath = "/etc/panel/firewall.nft"
const firewallGuardDir = "/var/lib/panel-executor/firewall-changes"

type firewallGuard struct {
	ChangeID string `json:"change_id"`
	Old      string `json:"old_config"`
	New      string `json:"new_config"`
	State    string `json:"state"`
}

func renderFirewall(v core.FirewallConfig, table string, sshPorts ...int) (string, error) {
	if table != "panel" && table != "panel_candidate" {
		return "", errors.New("无效防火墙表名")
	}
	if v.DefaultAction != "accept" && v.DefaultAction != "drop" {
		return "", errors.New("无效默认策略")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# managed by panel; revision=%d; enabled=%t\ntable inet %s {\n", v.Revision, v.Enabled, table)
	policy := "accept"
	if v.Enabled {
		policy = v.DefaultAction
	}
	fmt.Fprintf(&b, "  chain input {\n    type filter hook input priority filter; policy %s;\n", policy)
	b.WriteString("    iifname \"lo\" accept comment \"panel rescue loopback\"\n")
	b.WriteString("    ct state established,related accept comment \"panel established traffic\"\n")
	b.WriteString("    meta l4proto { icmp, ipv6-icmp } accept comment \"panel network control\"\n")
	ports := []int{22, 80, 443, 19443}
	seen := map[int]bool{22: true, 80: true, 443: true, 19443: true}
	for _, port := range sshPorts {
		if port < 1 || port > 65535 {
			return "", errors.New("SSH 端口超出有效范围")
		}
		if !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}
	sort.Ints(ports)
	labels := make([]string, len(ports))
	for i, port := range ports {
		labels[i] = strconv.Itoa(port)
	}
	fmt.Fprintf(&b, "    tcp dport { %s } accept comment \"panel fixed access ports\"\n", strings.Join(labels, ", "))
	if v.Enabled {
		for _, r := range v.Rules {
			if !r.Enabled {
				continue
			}
			prefix := "ip"
			if strings.Contains(r.Source, ":") {
				prefix = "ip6"
			}
			ports := strconv.Itoa(r.PortFrom)
			if r.PortTo != r.PortFrom {
				ports = fmt.Sprintf("%d-%d", r.PortFrom, r.PortTo)
			}
			name := strings.NewReplacer("\\", "_", "\"", "_", "\n", " ", "\r", " ").Replace(r.Name)
			fmt.Fprintf(&b, "    %s saddr %s %s dport %s %s comment \"%s\"\n", prefix, r.Source, r.Protocol, ports, r.Action, name)
		}
	}
	b.WriteString("  }\n}\n")
	return b.String(), nil
}

func firewallSSHPorts(ctx context.Context, run Command, v core.FirewallConfig) ([]int, error) {
	if !v.Enabled || v.DefaultAction != "drop" {
		return nil, nil
	}
	out, e := run(ctx, "/usr/sbin/sshd", "-T")
	if e != nil {
		return nil, fmt.Errorf("无法读取 SSH 实际端口，拒绝启用默认拦截规则: %w", e)
	}
	ports := parseSSHD(out).Ports
	if len(ports) == 0 {
		return nil, errors.New("SSH 实际端口为空，拒绝启用默认拦截规则")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, errors.New("SSH 实际端口无效，拒绝启用默认拦截规则")
		}
	}
	return ports, nil
}

func firewallLock() (*os.File, error) {
	if e := os.MkdirAll(firewallGuardDir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(firewallGuardDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

func firewallGuardPath(id string) string { return filepath.Join(firewallGuardDir, id+".json") }
func saveFirewallGuard(g firewallGuard) error {
	if !core.ValidID(g.ChangeID) {
		return errors.New("无效防火墙变更标识")
	}
	if e := os.MkdirAll(firewallGuardDir, 0700); e != nil {
		return e
	}
	b, _ := json.Marshal(g)
	return atomicWrite(firewallGuardPath(g.ChangeID), b, 0600)
}
func readFirewallGuard(id string) (firewallGuard, error) {
	var g firewallGuard
	if !core.ValidID(id) {
		return g, errors.New("无效防火墙变更标识")
	}
	b, e := os.ReadFile(firewallGuardPath(id))
	if e != nil {
		return g, e
	}
	e = json.Unmarshal(b, &g)
	if e == nil && g.ChangeID != id {
		e = errors.New("防火墙变更标识不匹配")
	}
	return g, e
}

func nftLoad(ctx context.Context, run Command, content string) error {
	if e := os.MkdirAll(filepath.Dir(firewallConfigPath), 0755); e != nil {
		return e
	}
	check := strings.Replace(content, "table inet panel {", "table inet panel_candidate {", 1)
	f, e := os.CreateTemp("/run/panel-executor", "panel-firewall-check-*.nft")
	if e != nil {
		return e
	}
	checkPath := f.Name()
	defer os.Remove(checkPath)
	if _, e = f.WriteString(check); e == nil {
		e = f.Chmod(0600)
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if _, e = run(ctx, "/usr/sbin/nft", "-c", "-f", checkPath); e != nil {
		return fmt.Errorf("nftables 候选配置校验失败: %w", e)
	}
	load := content
	if _, e = run(ctx, "/usr/sbin/nft", "list", "table", "inet", "panel"); e == nil {
		load = "delete table inet panel\n" + content
	}
	lf, e := os.CreateTemp("/run/panel-executor", "panel-firewall-load-*.nft")
	if e != nil {
		return e
	}
	loadPath := lf.Name()
	defer os.Remove(loadPath)
	if _, e = lf.WriteString(load); e == nil {
		e = lf.Chmod(0600)
	}
	if closeErr := lf.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if _, e = run(ctx, "/usr/sbin/nft", "-f", loadPath); e != nil {
		return fmt.Errorf("加载 nftables 配置失败: %w", e)
	}
	return nil
}

func defaultFirewallConfig() string {
	content, _ := renderFirewall(core.FirewallConfig{DefaultAction: "accept", Revision: 1}, "panel")
	return content
}

func restoreFirewallGuard(ctx context.Context, run Command, g firewallGuard) error {
	if g.State != "pending" {
		return nil
	}
	if e := nftLoad(ctx, run, g.Old); e != nil {
		return e
	}
	if e := atomicWrite(firewallConfigPath, []byte(g.Old), 0640); e != nil {
		return e
	}
	g.State = "rolled_back"
	return saveFirewallGuard(g)
}

func FirewallRollback(id string) error {
	lock, e := firewallLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	g, e := readFirewallGuard(id)
	if e != nil {
		return e
	}
	return restoreFirewallGuard(context.Background(), RunCommand, g)
}

func RecoverFirewall() error {
	lock, e := firewallLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	paths, e := filepath.Glob(filepath.Join(firewallGuardDir, "*.json"))
	if e != nil {
		return e
	}
	for _, path := range paths {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		g, e := readFirewallGuard(id)
		if e != nil {
			return e
		}
		if e = restoreFirewallGuard(context.Background(), RunCommand, g); e != nil {
			return e
		}
	}
	return nil
}

func (s *Service) previewFirewall(ctx context.Context, v core.FirewallConfig) (core.FirewallApplyResult, error) {
	sshPorts, e := firewallSSHPorts(ctx, s.Config.Run, v)
	if e != nil {
		return core.FirewallApplyResult{Status: "preview"}, e
	}
	content, e := renderFirewall(v, "panel", sshPorts...)
	result := core.FirewallApplyResult{Status: "preview", Config: content}
	if e != nil {
		return result, e
	}
	check := strings.Replace(content, "table inet panel {", "table inet panel_candidate {", 1)
	f, e := os.CreateTemp("/run/panel-executor", "panel-firewall-preview-*.nft")
	if e != nil {
		return result, e
	}
	path := f.Name()
	defer os.Remove(path)
	if _, e = f.WriteString(check); e == nil {
		e = f.Chmod(0600)
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e == nil {
		_, e = s.Config.Run(ctx, "/usr/sbin/nft", "-c", "-f", path)
	}
	if e != nil {
		return result, fmt.Errorf("nftables 候选配置校验失败: %w", e)
	}
	return result, nil
}

func (s *Service) applyFirewall(ctx context.Context, in core.FirewallApplyRequest) (core.FirewallApplyResult, error) {
	result := core.FirewallApplyResult{ChangeID: in.ChangeID, Steps: []core.Step{}}
	add := func(message string) {
		result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
	}
	if !core.ValidID(in.ChangeID) {
		return result, errors.New("无效防火墙变更标识")
	}
	sshPorts, e := firewallSSHPorts(ctx, s.Config.Run, in.Config)
	if e != nil {
		return result, e
	}
	content, e := renderFirewall(in.Config, "panel", sshPorts...)
	if e != nil {
		return result, e
	}
	lock, e := firewallLock()
	if e != nil {
		return result, e
	}
	defer lock.Close()
	paths, _ := filepath.Glob(filepath.Join(firewallGuardDir, "*.json"))
	for _, path := range paths {
		oldGuard, re := readFirewallGuard(strings.TrimSuffix(filepath.Base(path), ".json"))
		if re == nil && oldGuard.State == "pending" {
			if re = restoreFirewallGuard(ctx, s.Config.Run, oldGuard); re != nil {
				return result, re
			}
		}
	}
	old, readErr := os.ReadFile(firewallConfigPath)
	if errors.Is(readErr, os.ErrNotExist) {
		old = []byte(defaultFirewallConfig())
	} else if readErr != nil {
		return result, readErr
	}
	g := firewallGuard{ChangeID: in.ChangeID, Old: string(old), New: content, State: "pending"}
	if e = saveFirewallGuard(g); e != nil {
		return result, e
	}
	timer := "panel-firewall-rollback@" + in.ChangeID + ".timer"
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "start", timer); e != nil {
		return result, e
	}
	add("启动 45 秒独立恢复计时器")
	if e = nftLoad(ctx, s.Config.Run, content); e != nil {
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "stop", timer)
		_ = restoreFirewallGuard(context.Background(), s.Config.Run, g)
		return result, e
	}
	if e = atomicWrite(firewallConfigPath, []byte(content), 0640); e != nil {
		_ = restoreFirewallGuard(context.Background(), s.Config.Run, g)
		return result, e
	}
	add("候选规则已校验并原子加载")
	result.Status = "pending_confirmation"
	result.Config = content
	result.Deadline = time.Now().Add(45 * time.Second).Unix()
	return result, nil
}

func (s *Service) finishFirewall(ctx context.Context, id string, commit bool) error {
	lock, e := firewallLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	g, e := readFirewallGuard(id)
	if e != nil {
		return e
	}
	if g.State != "pending" {
		return errors.New("防火墙变更已经结束")
	}
	timer := "panel-firewall-rollback@" + id + ".timer"
	if commit {
		g.State = "committed"
		e = saveFirewallGuard(g)
	} else {
		e = restoreFirewallGuard(ctx, s.Config.Run, g)
	}
	_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "stop", timer)
	return e
}

func parseSSHD(output string) core.SSHStatus {
	status := core.SSHStatus{Available: true, CheckedAt: core.Now(), PasswordAuthentication: "unknown", PermitRootLogin: "unknown", PubkeyAuthentication: "unknown", X11Forwarding: "unknown", AllowTCPForwarding: "unknown"}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key, value := strings.ToLower(parts[0]), strings.ToLower(parts[1])
		switch key {
		case "port":
			if n, e := strconv.Atoi(value); e == nil {
				status.Ports = append(status.Ports, n)
			}
		case "passwordauthentication":
			status.PasswordAuthentication = value
		case "permitrootlogin":
			status.PermitRootLogin = value
		case "pubkeyauthentication":
			status.PubkeyAuthentication = value
		case "maxauthtries":
			status.MaxAuthTries, _ = strconv.Atoi(value)
		case "x11forwarding":
			status.X11Forwarding = value
		case "allowtcpforwarding":
			status.AllowTCPForwarding = value
		}
	}
	status.Ports = uniquePorts(status.Ports)
	if status.PasswordAuthentication == "yes" {
		status.Warnings = append(status.Warnings, "SSH 仍允许密码登录，建议确认密钥登录后关闭")
	}
	if status.PermitRootLogin == "yes" {
		status.Warnings = append(status.Warnings, "root 可以直接登录 SSH")
	}
	if status.PubkeyAuthentication != "yes" {
		status.Warnings = append(status.Warnings, "SSH 公钥认证未启用")
	}
	if status.MaxAuthTries > 4 {
		status.Warnings = append(status.Warnings, "单连接认证尝试次数偏高")
	}
	if status.X11Forwarding == "yes" {
		status.Warnings = append(status.Warnings, "SSH X11 转发已启用")
	}
	return status
}
func uniquePorts(values []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (s *Service) securityRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/security/firewall", func(w http.ResponseWriter, r *http.Request) {
		status := core.FirewallStatus{Available: true, Detail: "inet panel 表未加载"}
		if _, e := os.Stat("/usr/sbin/nft"); e != nil {
			status.Available = false
			status.Detail = "nftables 未安装"
			respond(w, 200, status)
			return
		}
		if out, e := s.Config.Run(r.Context(), "/usr/sbin/nft", "list", "table", "inet", "panel"); e == nil {
			status.Active = true
			status.Detail = strings.TrimSpace(out)
		}
		if paths, e := filepath.Glob(filepath.Join(firewallGuardDir, "*.json")); e == nil {
			for _, path := range paths {
				if g, re := readFirewallGuard(strings.TrimSuffix(filepath.Base(path), ".json")); re == nil && g.State == "pending" {
					status.Pending = true
					status.ChangeID = g.ChangeID
					break
				}
			}
		}
		respond(w, 200, status)
	})
	m.HandleFunc("POST /v1/security/firewall/preview", func(w http.ResponseWriter, r *http.Request) {
		var in core.FirewallApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		result, e := s.previewFirewall(r.Context(), in.Config)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, result)
	})
	m.HandleFunc("POST /v1/security/firewall/apply", func(w http.ResponseWriter, r *http.Request) {
		var in core.FirewallApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		result, e := s.applyFirewall(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		respond(w, 202, result)
	})
	for _, route := range []struct {
		path   string
		commit bool
	}{{"/v1/security/firewall/confirm", true}, {"/v1/security/firewall/rollback", false}} {
		route := route
		m.HandleFunc("POST "+route.path, func(w http.ResponseWriter, r *http.Request) {
			var in core.FirewallConfirmRequest
			if !readJSON(w, r, &in) {
				return
			}
			if e := s.finishFirewall(r.Context(), in.ChangeID, route.commit); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
			respond(w, 200, map[string]bool{"ok": true})
		})
	}
	m.HandleFunc("GET /v1/security/ssh", func(w http.ResponseWriter, r *http.Request) {
		if _, e := os.Stat("/usr/sbin/sshd"); e != nil {
			respond(w, 200, core.SSHStatus{Available: false, CheckedAt: core.Now(), Warnings: []string{"OpenSSH 服务端未安装"}})
			return
		}
		out, e := s.Config.Run(r.Context(), "/usr/sbin/sshd", "-T")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		status := parseSSHD(out)
		if _, e = s.Config.Run(r.Context(), "/usr/bin/systemctl", "is-active", "--quiet", "ssh.service"); e == nil {
			status.Active = true
		}
		if _, e = s.Config.Run(r.Context(), "/usr/bin/systemctl", "is-enabled", "--quiet", "ssh.service"); e == nil {
			status.Enabled = true
		}
		if !status.Active {
			status.Warnings = append(status.Warnings, "SSH 服务当前未运行")
		}
		respond(w, 200, status)
	})
}
