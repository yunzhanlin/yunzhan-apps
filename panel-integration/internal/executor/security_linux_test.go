//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestRenderFirewallKeepsRescueRulesAndEscapesComment(t *testing.T) {
	v := core.FirewallConfig{Enabled: true, DefaultAction: "drop", Revision: 4, Rules: []core.FirewallRule{{ID: strings.Repeat("a", 32), Name: "office \"web\"\nrule", Protocol: "tcp", Source: "192.168.1.0/24", PortFrom: 8080, PortTo: 8081, Action: "accept", Enabled: true}}}
	out, e := renderFirewall(v, "panel")
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"table inet panel", "policy drop", "iifname \"lo\" accept", "ct state established,related accept", "tcp dport { 22, 80, 443, 19443 } accept", "ip saddr 192.168.1.0/24 tcp dport 8080-8081 accept", `comment "office _web_ rule"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFirewallPreservesConfiguredSSHPortAndRejectsUnknownPort(t *testing.T) {
	v := core.FirewallConfig{Enabled: true, DefaultAction: "drop", Revision: 5}
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/sbin/sshd" || len(args) != 1 || args[0] != "-T" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return "port 2222\nport 2223\npasswordauthentication no\n", nil
	}
	ports, e := firewallSSHPorts(context.Background(), run, v)
	if e != nil || len(ports) != 2 || ports[0] != 2222 || ports[1] != 2223 {
		t.Fatalf("SSH ports %v: %v", ports, e)
	}
	out, e := renderFirewall(v, "panel", ports...)
	if e != nil || !strings.Contains(out, "tcp dport { 22, 80, 443, 2222, 2223, 19443 } accept") {
		t.Fatalf("SSH access not preserved: %v %s", e, out)
	}
	broken := func(context.Context, string, ...string) (string, error) { return "", errors.New("sshd config broken") }
	if _, e = firewallSSHPorts(context.Background(), broken, v); e == nil {
		t.Fatal("default-deny firewall accepted unknown SSH port")
	}
	if _, e = firewallSSHPorts(context.Background(), func(context.Context, string, ...string) (string, error) { return "passwordauthentication no\n", nil }, v); e == nil {
		t.Fatal("default-deny firewall accepted missing SSH port")
	}
	if _, e = renderFirewall(v, "panel", 65536); e == nil {
		t.Fatal("invalid SSH port reached nftables renderer")
	}
	if _, e = firewallSSHPorts(context.Background(), broken, core.FirewallConfig{DefaultAction: "accept"}); e != nil {
		t.Fatalf("safe allow mode unnecessarily requires sshd: %v", e)
	}
}

func TestRenderDisabledFirewallIgnoresCustomDrop(t *testing.T) {
	v := core.FirewallConfig{Enabled: false, DefaultAction: "drop", Revision: 2, Rules: []core.FirewallRule{{Name: "deny", Protocol: "tcp", Source: "0.0.0.0/0", PortFrom: 1, PortTo: 65535, Action: "drop", Enabled: true}}}
	out, e := renderFirewall(v, "panel")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out, "policy accept") || strings.Contains(out, "dport 1-65535 drop") {
		t.Fatal(out)
	}
}

func TestParseSSHDWarnings(t *testing.T) {
	s := parseSSHD("port 22\npasswordauthentication yes\npermitrootlogin yes\npubkeyauthentication no\nmaxauthtries 6\nx11forwarding yes\nallowtcpforwarding yes\n")
	if len(s.Warnings) != 5 || len(s.Ports) != 1 || s.Ports[0] != 22 {
		t.Fatalf("status=%+v", s)
	}
}
