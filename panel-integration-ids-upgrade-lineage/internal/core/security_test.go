package core

import (
	"strings"
	"testing"
	"time"
)

func TestFirewallValidationPendingAndNewConnectionConfirm(t *testing.T) {
	s := testStore(t)
	initial, e := s.Firewall()
	if e != nil || initial.Revision != 1 || initial.Enabled {
		t.Fatalf("initial=%+v error=%v", initial, e)
	}
	candidate := initial
	candidate.Enabled = true
	candidate.DefaultAction = "drop"
	candidate.Rules = []FirewallRule{{Name: "office", Protocol: "TCP", Source: "192.168.1.17/24", PortFrom: 8080, PortTo: 8081, Action: "ACCEPT", Enabled: true}}
	normalized, e := s.ValidateFirewall(candidate)
	if e != nil {
		t.Fatal(e)
	}
	if normalized.Rules[0].Source != "192.168.1.0/24" || normalized.Rules[0].Protocol != "tcp" || !ValidID(normalized.Rules[0].ID) {
		t.Fatalf("not normalized: %+v", normalized)
	}
	id := ID()
	if e = s.BeginFirewallChange(normalized, id, "proxy:41", "admin", time.Now().Add(time.Minute).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ConfirmFirewall(id, "proxy:41", "admin"); e == nil || !strings.Contains(e.Error(), "新的管理连接") {
		t.Fatalf("same connection accepted: %v", e)
	}
	updated, e := s.ConfirmFirewall(id, "proxy:42", "admin")
	if e != nil {
		t.Fatal(e)
	}
	if !updated.Enabled || updated.DefaultAction != "drop" || updated.Revision != 2 || updated.Rules[0].Source != "192.168.1.0/24" {
		t.Fatalf("updated=%+v", updated)
	}
}

func TestFirewallValidationRejectsRawOrInvalidRules(t *testing.T) {
	s := testStore(t)
	base, _ := s.Firewall()
	for _, rule := range []FirewallRule{
		{Name: "bad protocol", Protocol: "all", Source: "0.0.0.0/0", PortFrom: 1, PortTo: 2, Action: "accept", Enabled: true},
		{Name: "bad network", Protocol: "tcp", Source: "any", PortFrom: 22, PortTo: 22, Action: "accept", Enabled: true},
		{Name: "bad ports", Protocol: "udp", Source: "::/0", PortFrom: 9000, PortTo: 8000, Action: "drop", Enabled: true},
	} {
		v := base
		v.Rules = []FirewallRule{rule}
		if _, e := s.ValidateFirewall(v); e == nil {
			t.Fatalf("accepted invalid rule: %+v", rule)
		}
	}
}
