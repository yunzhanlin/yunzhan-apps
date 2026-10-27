package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func fixture() Entry {
	return Entry{Format: 1, Revision: 1, Name: "db.lb.invalid", Protocol: "tcp", Port: 42000, ProbePort: 43000,
		Nodes:  []Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "[2001:db8::2]:41002", Weight: 3}},
		Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64}
}
func facts() ValidationContext {
	return ValidationContext{PanelControlPorts: []int{19100}, MemoryBudgetBytes: 64 << 20}
}
func clone(entry Entry) Entry { entry.Nodes = append([]Node(nil), entry.Nodes...); return entry }

func TestClosedEntryProfilesAndCanonicalMetadata(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, method := range []string{"round-robin", "least-connections", "source-ip"} {
			t.Run(protocol+"/"+method, func(t *testing.T) {
				entry := fixture()
				entry.Protocol = protocol
				entry.Method = method
				if protocol == "udp" {
					entry.UDPRequests = 1
					entry.UDPResponses = 1
				}
				if err := Validate(entry); err != nil {
					t.Fatal(err)
				}
				if err := ValidateSet([]Entry{entry}, facts()); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(entry)
				got, err := Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				again, _ := json.Marshal(got)
				if !bytes.Equal(raw, again) {
					t.Fatal("canonical record changed")
				}
			})
		}
	}
	for _, method := range []string{"round-robin", "least-connections"} {
		entry := fixture()
		entry.Method = method
		entry.Nodes[1].Backup = true
		if Validate(entry) != nil {
			t.Fatal("legitimate backup refused")
		}
	}
	entry := fixture()
	entry.Protocol = "udp"
	entry.UDPRequests = 1
	entry.UDPResponses = 0
	if Validate(entry) != nil {
		t.Fatal("one-way UDP must not invent a response requirement")
	}
}
func TestEntryRefusesInjectionControlPlanesAndUnboundedPolicy(t *testing.T) {
	changes := map[string]func(*Entry){
		"format": func(e *Entry) { e.Format = 2 }, "revision-zero": func(e *Entry) { e.Revision = 0 }, "revision-limit": func(e *Entry) { e.Revision = 1 << 60 },
		"upper-name": func(e *Entry) { e.Name = "DB.lb.invalid" }, "name-injection": func(e *Entry) { e.Name = "x.invalid;\nstream{}" }, "name-ip": func(e *Entry) { e.Name = "127.0.0.1" },
		"name-path": func(e *Entry) { e.Name = "../x.invalid" }, "name-dollar": func(e *Entry) { e.Name = "$host.invalid" }, "name-unicode": func(e *Entry) { e.Name = "中文.invalid" },
		"empty-label": func(e *Entry) { e.Name = "x..invalid" }, "long-label": func(e *Entry) { e.Name = strings.Repeat("x", 64) + ".invalid" }, "label-edge": func(e *Entry) { e.Name = "-x.invalid" },
		"protocol": func(e *Entry) { e.Protocol = "tcp;return bad" }, "port-low": func(e *Entry) { e.Port = 19999 }, "port-high": func(e *Entry) { e.Port = 60001 },
		"probe-low": func(e *Entry) { e.ProbePort = 0 }, "same-probe": func(e *Entry) { e.ProbePort = e.Port }, "nodes-small": func(e *Entry) { e.Nodes = e.Nodes[:1] },
		"nodes-large": func(e *Entry) { e.Nodes = make([]Node, 17) }, "duplicate-node": func(e *Entry) { e.Nodes[1] = e.Nodes[0] },
		"weight-low": func(e *Entry) { e.Nodes[0].Weight = 0 }, "weight-high": func(e *Entry) { e.Nodes[0].Weight = 101 },
		"all-backup": func(e *Entry) { e.Nodes[0].Backup = true; e.Nodes[1].Backup = true }, "hash-backup": func(e *Entry) { e.Method = "source-ip"; e.Nodes[1].Backup = true },
		"method": func(e *Entry) { e.Method = "random;include /etc/passwd" }, "connect-low": func(e *Entry) { e.ConnectMilliseconds = 499 }, "connect-high": func(e *Entry) { e.ConnectMilliseconds = 5001 },
		"session-low": func(e *Entry) { e.SessionSeconds = 1 }, "session-high": func(e *Entry) { e.SessionSeconds = 601 }, "connections-low": func(e *Entry) { e.MaxSessions = 15 }, "connections-high": func(e *Entry) { e.MaxSessions = 513 },
		"tcp-udp-policy": func(e *Entry) { e.UDPRequests = 1 }, "udp-no-bound": func(e *Entry) { e.Protocol = "udp"; e.UDPRequests = 0 },
		"udp-request-limit": func(e *Entry) { e.Protocol = "udp"; e.UDPRequests = 65 }, "udp-response-negative": func(e *Entry) { e.Protocol = "udp"; e.UDPRequests = 1; e.UDPResponses = -1 },
		"udp-response-limit": func(e *Entry) { e.Protocol = "udp"; e.UDPRequests = 1; e.UDPResponses = 65 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			entry := fixture()
			change(&entry)
			if Validate(entry) == nil {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
	for _, address := range []string{"example.com:80", "unix:/etc/passwd", "127.0.0.1:42000", "[::1]:43000", "127.0.0.1:19100", "192.0.2.10:19102", "[2001:db8::1]:19080",
		"0.0.0.0:80", "[::]:80", "224.0.0.1:80", "[ff02::1]:80", "169.254.169.254:80", "[fe80::1]:80", "[::ffff:127.0.0.1]:80", "[fe80::1%eth0]:80",
		"255.255.255.255:80", "100.100.100.200:80", "[fd00:ec2::254]:80", "192.0.2.10:080", "192.0.2.10:0", "192.0.2.10:65536", "192.0.2.10:80;return bad", "[2001:DB8::1]:80"} {
		t.Run(address, func(t *testing.T) {
			entry := fixture()
			entry.Nodes[0].Address = address
			if Validate(entry) == nil {
				t.Fatal("unsafe address accepted")
			}
		})
	}
}
func TestPrivateDecodeNeverNormalizesForgedMetadata(t *testing.T) {
	raw, _ := json.Marshal(fixture())
	for _, text := range []string{
		string(raw) + "\n", string(raw) + "{}", string(raw[:len(raw)-1]) + ",\"verified\":true}",
		strings.Replace(string(raw), "\"revision\":1", "\"revision\":1,\"revision\":1", 1),
		strings.Replace(string(raw), "\"revision\":1", "\"Revision\":1", 1),
		strings.Replace(string(raw), "\"revision\":1", "\"revision\":1.0", 1),
		strings.Replace(string(raw), "\"removed\":false", "\"removed\":null", 1),
		strings.Replace(string(raw), "\"backup\":false", "\"backup\":null", 1),
		strings.Replace(string(raw), "\"nodes\":[", "\"Nodes\":[", 1),
		"null", "[]", "{}",
	} {
		if _, err := Decode([]byte(text)); err == nil {
			t.Fatalf("forged metadata accepted: %q", text)
		}
	}
	if _, err := Decode(bytes.Repeat([]byte(" "), MaxEntryBytes+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestSetBudgetsListenersCustomControlPortsAndCompleteGraph(t *testing.T) {
	a := fixture()
	b := clone(a)
	b.Name = "b.lb.invalid"
	b.Port = 42010
	b.ProbePort = 43010
	if ValidateSet([]Entry{a, b}, facts()) != nil {
		t.Fatal("independent listeners refused")
	}
	one := int64(a.MaxSessions)*BytesPerSession + FixedBytesPerEntry
	limit := facts()
	limit.MemoryBudgetBytes = one
	if ValidateSet([]Entry{a}, limit) != nil {
		t.Fatal("exact planned buffer/zone budget refused")
	}
	limit.MemoryBudgetBytes--
	if ValidateSet([]Entry{a}, limit) == nil {
		t.Fatal("one byte over planned budget accepted")
	}
	for _, ctx := range []ValidationContext{{MemoryBudgetBytes: 64 << 20}, {PanelControlPorts: []int{0}, MemoryBudgetBytes: 64 << 20}, {PanelControlPorts: []int{19100}, MemoryBudgetBytes: MaxMemoryBudget + 1}, {PanelControlPorts: []int{19100}, OccupiedTCPPorts: []int{65536}, MemoryBudgetBytes: 64 << 20}} {
		if ValidateSet([]Entry{a}, ctx) == nil {
			t.Fatal("missing or invalid facts accepted")
		}
	}
	for _, port := range []int{a.Port, a.ProbePort} {
		ctx := facts()
		ctx.PanelControlPorts = append(ctx.PanelControlPorts, port)
		if ValidateSet([]Entry{a}, ctx) == nil {
			t.Fatal("actual custom control listener borrowed")
		}
		ctx = facts()
		ctx.OccupiedTCPPorts = []int{port}
		if ValidateSet([]Entry{a}, ctx) == nil {
			t.Fatal("occupied TCP listener borrowed")
		}
	}
	custom := clone(a)
	custom.Nodes[0].Address = "192.0.2.10:56789"
	ctx := facts()
	ctx.PanelControlPorts = append(ctx.PanelControlPorts, 56789)
	if ValidateSet([]Entry{custom}, ctx) == nil {
		t.Fatal("remote control-plane relay allowed")
	}
	for _, kind := range []string{"name", "tcp-port", "probe-port", "probe-on-tcp", "probe-target", "cycle"} {
		t.Run(kind, func(t *testing.T) {
			left, right := clone(a), clone(b)
			switch kind {
			case "name":
				right.Name = left.Name
			case "tcp-port":
				right.Port = left.Port
			case "probe-port":
				right.ProbePort = left.ProbePort
			case "probe-on-tcp":
				right.ProbePort = left.Port
			case "probe-target":
				left.Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", right.ProbePort)
			case "cycle":
				left.Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", right.Port)
				right.Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", left.Port)
			}
			if ValidateSet([]Entry{left, right}, facts()) == nil {
				t.Fatal("whole-set conflict accepted")
			}
		})
	}
	left, right := clone(a), clone(b)
	left.Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", right.Port)
	if ValidateSet([]Entry{left, right}, facts()) != nil {
		t.Fatal("acyclic managed chain refused")
	}
	right.Protocol = "udp"
	right.UDPRequests = 1
	right.UDPResponses = 1
	right.Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", left.Port)
	if ValidateSet([]Entry{left, right}, facts()) != nil {
		t.Fatal("different transport incorrectly made a cycle")
	}
	b.Protocol = "udp"
	b.Port = a.Port
	b.UDPRequests = 1
	b.UDPResponses = 1
	if ValidateSet([]Entry{a, b}, facts()) != nil {
		t.Fatal("separate TCP/UDP socket namespaces conflated")
	}
	b.Removed = true
	b.ProbePort = a.ProbePort
	if ValidateSet([]Entry{a, b}, facts()) != nil {
		t.Fatal("removed record falsely reserves memory or sockets")
	}
}
func TestCompleteSetCardinalityAndBoundedDeepCycles(t *testing.T) {
	entries := []Entry{}
	for i := 0; i < MaxEntries; i++ {
		e := fixture()
		e.Name = fmt.Sprintf("n%d.lb.invalid", i)
		e.Port = 44000 + i
		e.ProbePort = 50000 + i
		e.MaxSessions = 16
		entries = append(entries, e)
	}
	ctx := facts()
	ctx.MemoryBudgetBytes = MaxMemoryBudget
	if ValidateSet(entries, ctx) != nil {
		t.Fatal("bounded maximum set refused")
	}
	tooMany := append(append([]Entry(nil), entries...), fixture())
	if ValidateSet(tooMany, ctx) == nil {
		t.Fatal("129 entries accepted")
	}
	for i := 0; i < len(entries)-1; i++ {
		entries[i].Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", entries[i+1].Port)
	}
	if ValidateSet(entries, ctx) != nil {
		t.Fatal("bounded deep acyclic set refused")
	}
	entries[len(entries)-1].Nodes[0].Address = fmt.Sprintf("127.0.0.1:%d", entries[0].Port)
	if ValidateSet(entries, ctx) == nil {
		t.Fatal("deep cycle accepted")
	}
}
func TestRendererKeepsTransportTransparentAndVerificationSeparate(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			e := fixture()
			e.Protocol = protocol
			if protocol == "udp" {
				e.UDPRequests = 1
				e.UDPResponses = 1
			}
			output, err := Render(e)
			if err != nil {
				t.Fatal(err)
			}
			stream, http := string(output.Stream), string(output.HTTP)
			for _, text := range []string{"limit_conn_zone $server_addr", "  zone panel_l4_", "  proxy_buffer_size 64k;", "weight=3 max_conns=64", "limit_conn panel_l4_limit_", "proxy_connect_timeout 2000ms;", "proxy_timeout 30s;"} {
				if !strings.Contains(stream, text) {
					t.Fatal("missing closed policy", text)
				}
			}
			for _, text := range []string{"server_name", "location ", "proxy_set_header", "proxy_protocol", "proxy_ssl", "health_check", "proxy_bind", "resolver ", "include "} {
				if strings.Contains(stream, text) {
					t.Fatal("foreign/paid/unconfigured stream feature", text)
				}
			}
			if !strings.Contains(http, "listen 127.0.0.1:43000;") || !strings.Contains(http, ProbePath(e.Name)) || !strings.Contains(http, output.Fingerprint) || strings.Contains(http, "proxy_pass") {
				t.Fatal("separate verification context invalid")
			}
			if strings.Contains(stream, output.Fingerprint) {
				t.Fatal("generation marker polluted business bytes")
			}
			if protocol == "tcp" {
				if !strings.Contains(stream, "proxy_half_close on;") || !strings.Contains(stream, "proxy_next_upstream_tries 2;") || strings.Contains(stream, " udp ") {
					t.Fatal("TCP behavior changed")
				}
			} else if !strings.Contains(stream, "listen 127.0.0.1:42000 udp reuseport;") || !strings.Contains(stream, "proxy_requests 1;") || !strings.Contains(stream, "proxy_responses 1;") || !strings.Contains(stream, "proxy_next_upstream off;") || strings.Contains(stream, "proxy_half_close") {
				t.Fatal("UDP datagram behavior changed")
			}
			e.Revision++
			changed, _ := Render(e)
			if changed.Fingerprint == output.Fingerprint {
				t.Fatal("generation not revision-bound")
			}
			e.Removed = true
			removed, _ := Render(e)
			if len(removed.HTTP) != 0 || len(removed.Stream) != 0 || removed.Fingerprint == changed.Fingerprint {
				t.Fatal("tombstone rendered live routing or borrowed generation")
			}
		})
	}
}
