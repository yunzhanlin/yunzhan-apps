//go:build linux

package executor

import (
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func apacheWAFNativeFixture(t *testing.T, cfg core.WAFConfig) wafNativeFixture {
	t.Helper()
	if os.Getenv("PANEL_QA_APACHE_NATIVE") != "1" {
		t.Skip("explicit isolated Apache native QA required")
	}
	release, ok := runtimecatalog.Find("apache-2.4.68")
	if !ok {
		t.Fatal("pinned Apache runtime missing")
	}
	if err := ordinary(release.CLI(), false); err != nil {
		t.Fatal("native Apache requested but exact pinned runtime absent", err)
	}
	root := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	id := strings.Repeat("a", 32)
	rules, err := renderApacheWAF(cfg, map[string][]string{id: {"protected.localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "events.log")
	rules = strings.ReplaceAll(rules, "/var/log/apache2/panel-waf.events.log", logPath)
	var global strings.Builder
	fmt.Fprintf(&global, "ServerRoot %s\nDefaultRuntimeDir %s\nPidFile %s\nListen %s\nServerName protected.localhost\nUser www-data\nGroup www-data\nErrorLog %s\nLogLevel warn\n", strconv.Quote(root), strconv.Quote(root), strconv.Quote(filepath.Join(root, "apache.pid")), address, strconv.Quote(filepath.Join(root, "error.log")))
	for _, name := range []string{"mpm_prefork", "authz_core", "authz_host", "unixd", "log_config", "env", "setenvif", "headers", "rewrite", "remoteip"} {
		module := filepath.Join(release.Prefix(), "modules/mod_"+name+".so")
		if err := ordinary(module, false); err != nil {
			t.Fatal("requested native module absent", name, err)
		}
		fmt.Fprintf(&global, "LoadModule %s_module %s\n", name, strconv.Quote(module))
	}
	global.WriteString("<Directory />\n Require all granted\n</Directory>\n")
	for _, name := range []string{"protected.localhost", "unmanaged.localhost"} {
		fmt.Fprintf(&global, "<VirtualHost %s>\n ServerName %s\n SetEnvIfExpr \"true\" PANEL_AW_SITE=%s\n Header always set X-Test-Client-IP \"expr=%%{REMOTE_ADDR}\"\n Header always set X-Test-Peer-IP \"expr=%%{CONN_REMOTE_ADDR}\"\n", address, name, id)
		if name == "protected.localhost" {
			global.WriteString(rules)
		}
		global.WriteString("RewriteEngine On\nRewriteRule ^ - [R=204,L]\n</VirtualHost>\n")
	}
	config := filepath.Join(root, "apache.conf")
	if err := os.WriteFile(config, []byte(global.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(release.CLI(), "-t", "-f", config).CombinedOutput(); err != nil {
		t.Fatalf("native Apache -t failed: %s %v", out, err)
	}
	startup := filepath.Join(root, "startup.log")
	output, err := os.OpenFile(startup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(release.CLI(), "-X", "-f", config)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		output.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("private Apache failed to terminate")
		}
		output.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			body, _ := os.ReadFile(startup)
			t.Fatalf("private Apache exited: %v %s", waitErr, body)
		default:
		}
		if connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
			connection.Close()
			return wafNativeFixture{address: address, logPath: logPath}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("private Apache did not become ready")
	return wafNativeFixture{}
}

func TestApacheWAFNativeTrustedProxyIdentityListsAndScope(t *testing.T) {
	for _, mode := range []string{"default", "disabled", "enabled"} {
		t.Run(mode, func(t *testing.T) {
			cfg := core.DefaultApacheWAFConfig()
			cfg.Policy.Lists["ip_deny"] = []core.WAFEntry{{ID: core.ID(), Value: "203.0.113.0/24"}, {ID: core.ID(), Value: "2001:db8::/32"}, {ID: core.ID(), Value: "10.0.0.0/8"}}
			cfg.Policy.Lists["ip_allow"] = []core.WAFEntry{{ID: core.ID(), Value: "203.0.113.9/32"}}
			if mode != "default" {
				cfg.TrustedProxy = apacheTrustedProxyFixture()
				cfg.TrustedProxy.Enabled = mode == "enabled"
			}
			f := apacheWAFNativeFixture(t, cfg)
			for _, tc := range []struct {
				name, host, peer, forwarded, agent, client string
				status                                     int
			}{
				{"ipv4", "protected.localhost", "127.0.0.1", "203.0.113.8", "Browser", "203.0.113.8", 403},
				{"ipv6", "protected.localhost", "127.0.0.1", "2001:db8::beef", "Browser", "2001:db8::beef", 403},
				{"private-visitor", "protected.localhost", "127.0.0.1", "10.10.2.3", "Browser", "10.10.2.3", 403},
				{"untrusted-peer", "protected.localhost", "127.0.0.2", "203.0.113.8", "Browser", "127.0.0.2", 204},
				{"chain-stops-at-untrusted", "protected.localhost", "127.0.0.1", "203.0.113.8, 192.0.2.10", "Browser", "192.0.2.10", 204},
				{"chain-skips-trusted", "protected.localhost", "127.0.0.1", "203.0.113.8, 127.0.0.1", "Browser", "203.0.113.8", 403},
				{"whitelist", "protected.localhost", "127.0.0.1", "203.0.113.9", "sqlmap", "203.0.113.9", 204},
				{"missing-header", "protected.localhost", "127.0.0.1", "", "Browser", "127.0.0.1", 204},
				{"unmanaged-site", "unmanaged.localhost", "127.0.0.1", "203.0.113.8", "sqlmap", "127.0.0.1", 204},
			} {
				t.Run(tc.name, func(t *testing.T) {
					client, status := tc.client, tc.status
					if mode != "enabled" {
						client = tc.peer
						if tc.name == "ipv4" || tc.name == "ipv6" || tc.name == "private-visitor" || tc.name == "chain-skips-trusted" {
							status = 204
						}
						if tc.name == "whitelist" {
							status = 403
						}
					}
					got, headers := f.request(t, tc.host, "/", tc.peer, map[string]string{"X-Forwarded-For": tc.forwarded, "User-Agent": tc.agent})
					if got != status || headers.Get("X-Test-Client-IP") != client || headers.Get("X-Test-Peer-IP") != tc.peer {
						t.Fatal("native identity or blocking mismatch", got, headers, "want", status, client, tc.peer)
					}
					if tc.host == "protected.localhost" && headers.Get("X-Panel-Apache-WAF") != apacheWAFProbe(cfg) {
						t.Fatal("native loaded configuration fingerprint mismatch", headers)
					}
					if tc.host == "unmanaged.localhost" && headers.Get("X-Panel-Apache-WAF") != "" {
						t.Fatal("unmanaged virtual host inherited protection fingerprint", headers)
					}
				})
			}
			status, headers := f.request(t, "protected.localhost", "/", "127.0.0.1", map[string]string{"X-Real-IP": "203.0.113.8", "User-Agent": "Browser"})
			if status != 204 || headers.Get("X-Test-Client-IP") != "127.0.0.1" {
				t.Fatal("unselected header became trusted", status, headers)
			}
			if mode == "enabled" {
				body, err := os.ReadFile(f.logPath)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, line := range strings.Split(string(body), "\n") {
					var event core.WAFEvent
					if json.Unmarshal([]byte(line), &event) == nil && event.IP == "203.0.113.8" && event.Peer == "127.0.0.1" && event.Reason == "ip-deny" && event.Status == 403 {
						found = true
					}
				}
				if !found {
					t.Fatal("real Apache log did not preserve both identities", string(body))
				}
				for _, secret := range []string{"X-Forwarded-For", "sqlmap", "X-Real-IP"} {
					if strings.Contains(string(body), secret) {
						t.Fatal("log retained request header", secret)
					}
				}
			}
		})
	}
}
