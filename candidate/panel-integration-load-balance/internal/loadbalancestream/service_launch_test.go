package loadbalancestream

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestServiceLaunchExactlySharesUnitPolicyWithoutShellOrBootChanges(t *testing.T) {
	request := strings.Repeat("a", 32)
	for _, version := range []string{"1.30.6", "1.31.5"} {
		f := serviceFacts()
		f.NginxVersion = version
		plan, err := PlanServiceLaunch([]Entry{fixture()}, nil, f, request)
		if err != nil || !bytes.Contains(plan.Service.Unit, []byte("Type=exec\n")) || bytes.Contains(plan.Service.Unit, []byte("ExecReload=")) {
			t.Fatal("exec identity or manager-only reload changed", err)
		}
		for _, args := range [][]string{plan.Start, plan.Syntax} {
			seen := map[string]bool{}
			for _, arg := range args {
				if strings.HasPrefix(arg, "--property=") {
					property := strings.TrimPrefix(arg, "--property=")
					key, _, _ := strings.Cut(property, "=")
					if seen[key] {
						t.Fatal("ambiguous property", key)
					}
					seen[key] = true
					if !bytes.Contains(plan.Service.Unit, []byte(property+"\n")) && property != "RuntimeMaxSec=10s" && property != "TimeoutStopSec=5s" && property != "RemainAfterExit=no" {
						t.Fatal("transient and recorded policy disagree", property)
					}
				}
				if strings.ContainsAny(arg, "$\n\r\x00") || arg == "/bin/sh" || arg == "--no-block" || arg == "--collect" {
					t.Fatal("unreviewed expansion, shell or early unit collection", arg)
				}
			}
			for _, property := range serviceProperties(plan.Service.MemoryHighBytes, plan.Service.MemoryMaxBytes, plan.Service.AllowedIPs) {
				key, _, _ := strings.Cut(property, "=")
				if !seen[key] {
					t.Fatal("missing isolation property", property)
				}
			}
		}
		start := strings.Join(plan.Start, "|")
		syntax := strings.Join(plan.Syntax, "|")
		if strings.Contains(start, "--wait") || !strings.Contains(syntax, "--wait") || !strings.Contains(start, "--unit="+ServiceUnitName) || !strings.Contains(start, "|--|/opt/panel/runtimes/nginx/"+version+"/sbin/nginx|-e|stderr|-p|"+ServiceRuntimePrefix+"|-c|"+ServiceConfigPath+"|-g|daemon off;") || !strings.HasSuffix(syntax, "|-c|/etc/panel/load-balance-stream/.candidate-"+request+".conf|-t") {
			t.Fatal("original fixed command/wait boundary drifted")
		}
		if !bytes.Contains(plan.Service.Current.Main, []byte("worker_shutdown_timeout 600s;\n")) {
			t.Fatal("long active TCP sessions can prevent generation retirement forever")
		}
	}
}

func TestServiceLaunchNoPartialArgsForUnknownFactsOrPaths(t *testing.T) {
	for _, request := range []string{"", strings.Repeat("A", 32), "../../etc/passwd", strings.Repeat("a", 32) + "\nUser=root", strings.Repeat("a", 31)} {
		if value, err := PlanServiceLaunch([]Entry{fixture()}, nil, serviceFacts(), request); err != ErrService || !reflect.DeepEqual(value, ServiceLaunchPlan{}) {
			t.Fatal("caller path/unit injection returned command", err)
		}
	}
	f := serviceFacts()
	f.IPFilterAvailable = false
	if value, err := PlanServiceLaunch([]Entry{fixture()}, nil, f, strings.Repeat("a", 32)); err != ErrService || !reflect.DeepEqual(value, ServiceLaunchPlan{}) {
		t.Fatal("missing measured prerequisites returned commands")
	}
	a, _ := PlanServiceLaunch([]Entry{fixture()}, nil, serviceFacts(), strings.Repeat("a", 32))
	b, _ := PlanServiceLaunch([]Entry{fixture()}, nil, serviceFacts(), strings.Repeat("a", 32))
	a.Start[0], a.Syntax[0], a.Service.AllowedIPs[0] = "bad", "bad", "0.0.0.0/0"
	c, _ := PlanServiceLaunch([]Entry{fixture()}, nil, serviceFacts(), strings.Repeat("a", 32))
	if !reflect.DeepEqual(b, c) {
		t.Fatal("returned launch argv aliases another plan")
	}
}

func TestServiceLaunchPolicyOnlyUpdatesOriginalUnitResourceAndExactTwoGenerationIPs(t *testing.T) {
	current, prior := fixture(), fixture()
	current.Revision++
	prior.Nodes = []Node{{Address: "198.51.100.9:41001", Weight: 1}, {Address: "[2001:db8::4]:41002", Weight: 3}}
	p, err := PlanServiceLaunch([]Entry{current}, []Entry{prior}, serviceFacts(), strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--runtime", "set-property", ServiceUnitName, fmt.Sprintf("MemoryHigh=%d", p.Service.MemoryHighBytes), fmt.Sprintf("MemoryMax=%d", p.Service.MemoryMaxBytes), "IPAddressAllow=", "IPAddressAllow=" + strings.Join(p.Service.AllowedIPs, " ")}
	if !reflect.DeepEqual(p.Policy, want) || len(p.Policy) != 7 {
		t.Fatal("reload property batch broadened or lost exact reset/replace order", p.Policy)
	}
	for _, arg := range p.Policy {
		if strings.ContainsAny(arg, "$\n\r\x00") || strings.Contains(arg, "Deny=") || strings.Contains(arg, "CPU") || strings.Contains(arg, "Tasks") || strings.Contains(arg, "Capability") || strings.Contains(arg, "User=") {
			t.Fatal("unrelated service isolation selected for mutation", arg)
		}
	}
	p.Policy[0] = "bad"
	q, _ := PlanServiceLaunch([]Entry{current}, []Entry{prior}, serviceFacts(), strings.Repeat("a", 32))
	if !reflect.DeepEqual(q.Policy, want) {
		t.Fatal("returned policy aliases another request")
	}
}
