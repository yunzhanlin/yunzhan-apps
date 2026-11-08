//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestWAFRealNginxTrustedProxyIdentityAndScope(t *testing.T) {
	for _, mode := range []string{"default", "disabled", "xff-last", "xff-recursive", "real-ip"} {
		t.Run(mode, func(t *testing.T) {
			cfg := core.DefaultWAFConfig()
			cfg.Policy.CCEnabled = false
			cfg.Policy.Lists["ip_deny"] = []core.WAFEntry{{ID: core.ID(), Value: "203.0.113.0/24"}, {ID: core.ID(), Value: "198.51.100.0/24"}, {ID: core.ID(), Value: "2001:db8::/32"}}
			cfg.Policy.Lists["ip_allow"] = []core.WAFEntry{{ID: core.ID(), Value: "203.0.113.9/32"}}
			if mode != "default" {
				cfg.TrustedProxy = wafTrustedProxyFixture()
				cfg.TrustedProxy.Enabled = mode != "disabled"
				cfg.TrustedProxy.Recursive = mode == "xff-recursive"
				if mode == "real-ip" {
					cfg.TrustedProxy.Header = "X-Real-IP"
				}
			}
			f := wafTestNginxFixture(t, cfg)
			enabled := cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled
			header := "X-Forwarded-For"
			if mode == "real-ip" {
				header = "X-Real-IP"
			}
			for _, tc := range []struct {
				name, host, peer, forwarded, agent, client string
				status                                     int
			}{
				{"trusted-ipv4", "a.localhost", "127.0.0.1", "203.0.113.8", "Browser", "203.0.113.8", 403},
				{"trusted-ipv6", "a.localhost", "127.0.0.1", "2001:db8::beef", "Browser", "2001:db8::beef", 403},
				{"untrusted-peer", "a.localhost", "127.0.0.2", "203.0.113.8", "Browser", "127.0.0.2", 200},
				{"invalid-header", "a.localhost", "127.0.0.1", "not-an-address", "Browser", "127.0.0.1", 200},
				{"empty-header", "a.localhost", "127.0.0.1", "", "Browser", "127.0.0.1", 200},
				{"ip-allow-precedence", "a.localhost", "127.0.0.1", "203.0.113.9", "sqlmap", "203.0.113.9", 200},
				{"opted-out-site", "opted-out.localhost", "127.0.0.1", "203.0.113.8", "sqlmap", "127.0.0.1", 200},
			} {
				t.Run(tc.name, func(t *testing.T) {
					wantClient, wantStatus := tc.client, tc.status
					if !enabled {
						wantClient = tc.peer
						if tc.name == "trusted-ipv4" || tc.name == "trusted-ipv6" {
							wantStatus = 200
						}
						if tc.name == "ip-allow-precedence" {
							wantStatus = 403
						}
					}
					status, headers := f.request(t, tc.host, "/", tc.peer, map[string]string{header: tc.forwarded, "User-Agent": tc.agent})
					if status != wantStatus || headers.Get("X-Test-Client-IP") != wantClient {
						t.Fatalf("native identity mismatch: status=%d ip=%q want %d/%q", status, headers.Get("X-Test-Client-IP"), wantStatus, wantClient)
					}
					if enabled && tc.host != "opted-out.localhost" && headers.Get("X-Test-Peer-IP") != tc.peer {
						t.Fatal("original peer identity lost", headers)
					}
				})
			}
			// A different header must never become an additional trust source.
			other := "X-Real-IP"
			if header == other {
				other = "X-Forwarded-For"
			}
			status, headers := f.request(t, "a.localhost", "/", "127.0.0.1", map[string]string{other: "203.0.113.8", "User-Agent": "Browser"})
			if status != 200 || headers.Get("X-Test-Client-IP") != "127.0.0.1" {
				t.Fatal("unselected header was trusted", status, headers)
			}
			if strings.HasPrefix(mode, "xff-") {
				status, headers = f.request(t, "a.localhost", "/", "127.0.0.1", map[string]string{"X-Forwarded-For": "198.51.100.25, 127.0.0.1", "User-Agent": "Browser"})
				wantStatus, wantIP := 200, "127.0.0.1"
				if mode == "xff-recursive" {
					wantStatus, wantIP = 403, "198.51.100.25"
				}
				if status != wantStatus || headers.Get("X-Test-Client-IP") != wantIP {
					t.Fatal("recursive chain semantics differ", status, headers)
				}
			}
			if enabled {
				// Read the real generated access log, not response headers alone.
				found := false
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) {
					data, err := os.ReadFile(f.logPath)
					if err != nil {
						t.Fatal(err)
					}
					for _, line := range strings.Split(string(data), "\n") {
						var event core.WAFEvent
						if json.Unmarshal([]byte(line), &event) == nil && event.IP == "203.0.113.8" && event.Peer == "127.0.0.1" && event.Reason == "ip-deny" && event.Status == 403 {
							found = true
						}
					}
					if found {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !found {
					t.Fatal("actual WAF log did not preserve effective and original peer identities")
				}
			}
		})
	}
}

func TestWAFRealNginxTrustedProxyCCUsesVerifiedClientIdentity(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.TrustedProxy = wafTrustedProxyFixture()
	cfg.Rate = 200
	cfg.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("e", 32), Path: "/login", Rate: 1, Burst: 1, Enabled: true}}
	f := wafTestNginxFixture(t, cfg)
	blocked := false
	for i := 0; i < 8; i++ {
		status, headers := f.request(t, "a.localhost", "/login", "127.0.0.1", map[string]string{"X-Forwarded-For": "203.0.113.8", "User-Agent": "Browser"})
		if headers.Get("X-Test-Client-IP") != "203.0.113.8" {
			t.Fatal("trusted identity not active")
		}
		blocked = blocked || status == 429
	}
	if !blocked {
		t.Fatal("verified client burst was not limited")
	}
	status, _ := f.request(t, "a.localhost", "/login", "127.0.0.1", map[string]string{"X-Forwarded-For": "203.0.113.9", "User-Agent": "Browser"})
	if status != 200 {
		t.Fatal("independent trusted client was charged another client's budget", status)
	}
	blocked = false
	for i := 0; i < 8; i++ {
		status, headers := f.request(t, "a.localhost", "/login", "127.0.0.2", map[string]string{"X-Forwarded-For": "203.0.113." + string(rune('1'+i)), "User-Agent": "Browser"})
		if headers.Get("X-Test-Client-IP") != "127.0.0.2" {
			t.Fatal("untrusted peer spoofed CC identity")
		}
		blocked = blocked || status == 429
	}
	if !blocked {
		t.Fatal("changing untrusted headers bypassed per-peer CC budget")
	}
}
