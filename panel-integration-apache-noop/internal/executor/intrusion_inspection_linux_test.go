//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func intrusionInspectionKernelFixture(t *testing.T, ports []int) string {
	t.Helper()
	value, _ := intrusionNftFixture(t)
	intrusionNftOwnSet(value)["elem"] = []any{}
	var right any
	if len(ports) == 1 {
		right = float64(ports[0])
	} else {
		list := []any{}
		for _, port := range ports {
			list = append(list, float64(port))
		}
		right = map[string]any{"set": list}
	}
	intrusionNftOwnRule(value)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = right
	return string(intrusionNftEncode(t, value))
}

func intrusionInspectionFixture(t *testing.T) (*Service, map[string]string, *int) {
	t.Helper()
	s := newHardeningFixture(t).s
	settings := map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
	if err := s.writeSoftwareManifest(softwareManifest{ID: "intrusion-prevention", Version: "1.0", Settings: settings, InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	file := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(renderIntrusion(settings)), 0644); err != nil {
		t.Fatal(err)
	}
	answers := map[string]string{
		"/usr/sbin/sshd -T":                                                       "port 22\npasswordauthentication no\n",
		"/usr/bin/ss -H -ltnp":                                                    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\n",
		"/usr/bin/systemctl is-active fail2ban":                                   "active\n",
		"/usr/bin/fail2ban-client status sshd":                                    "Status for the jail: sshd\n",
		"/usr/bin/fail2ban-client get sshd actions":                               "The jail sshd has the following actions:\nnftables\n",
		"/usr/bin/fail2ban-client get sshd action nftables port":                  "22\n",
		"/usr/bin/fail2ban-client get sshd action nftables protocol":              "tcp\n",
		"/usr/bin/fail2ban-client get sshd maxretry":                              "5\n",
		"/usr/bin/fail2ban-client get sshd findtime":                              "600\n",
		"/usr/bin/fail2ban-client get sshd bantime":                               "3600\n",
		"/usr/bin/fail2ban-client get sshd banip":                                 "\n",
		"/usr/bin/fail2ban-client get sshd action nftables name":                  "probe_sshd\n",
		"/usr/bin/fail2ban-client get sshd action nftables table":                 "f2b-table\n",
		"/usr/bin/fail2ban-client get sshd action nftables table_family":          "inet\n",
		"/usr/bin/fail2ban-client get sshd action nftables chain":                 "ERROR",
		"/usr/sbin/nft -j list tables":                                            "ERROR",
		"/usr/bin/fail2ban-client get sshd action nftables addr_set":              "addr-set-<name>\n",
		"/usr/bin/fail2ban-client get sshd action nftables addr_set?family=inet6": "addr6-set-<name>\n",
		"/usr/sbin/nft -j list table inet f2b-table":                              intrusionInspectionKernelFixture(t, []int{22}),
	}
	calls := new(int)
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing entire probe deadline")
		}
		key := name + " " + strings.Join(args, " ")
		answer, ok := answers[key]
		if !ok {
			t.Fatal("unexpected non-read-only operation", key)
		}
		*calls++
		if answer == "ERROR" {
			return "sensitive original backend data", errors.New("private backend error")
		}
		return answer, nil
	}
	return s, answers, calls
}

func TestIntrusionInspectionChecksActualRuntimeWithoutWriting(t *testing.T) {
	s, _, calls := intrusionInspectionFixture(t)
	paths := []string{s.softwareManifestPath("intrusion-prevention"), s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")}
	raw := [][]byte{}
	info := []os.FileInfo{}
	for _, p := range paths {
		r, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, r)
		v, e := os.Lstat(p)
		if e != nil {
			t.Fatal(e)
		}
		info = append(info, v)
	}
	out, err := s.inspectIntrusion(context.Background())
	if err != nil || !out.Installed || !out.Healthy || !out.ServiceActive || !out.ConfigMatches || !out.SSHPortsMatch || len(out.Actions) != 1 || !out.Actions[0].ScopeVerified || !out.Actions[0].KernelScopeVerified || !out.KernelScopeVerified || !out.ActiveBansKnown || out.ActiveBans != 0 || len(out.Warnings) != 0 || *calls != 18 {
		t.Fatal(out, err, *calls)
	}
	if !reflect.DeepEqual(out.SSHListeningPorts, []int{22}) || out.RuntimeSettings["findtime"] != 600 {
		t.Fatal(out)
	}
	for i, p := range paths {
		r, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		v, e := os.Lstat(p)
		if e != nil || !os.SameFile(info[i], v) || info[i].Mode() != v.Mode() || !info[i].ModTime().Equal(v.ModTime()) || !bytes.Equal(raw[i], r) {
			t.Fatal("inspection rewrote authority", p, e)
		}
	}
	if _, e := os.Lstat(filepath.Join(s.Config.SecurityDir, "intrusion-configuration.lock")); !os.IsNotExist(e) {
		t.Fatal("inspection created lock", e)
	}
}

func TestIntrusionInspectionNonstandardAndMultiplePortsAreNeverDefaulted(t *testing.T) {
	for _, scope := range []string{"2882", "22,2882"} {
		t.Run(scope, func(t *testing.T) {
			s, answers, _ := intrusionInspectionFixture(t)
			ports, err := intrusionPortList(scope)
			if err != nil {
				t.Fatal(err)
			}
			config, listeners := "", ""
			for _, port := range ports {
				label := intrusionPortLabel(port)
				config += "port " + label + "\n"
				listeners += "LISTEN 0 128 0.0.0.0:" + label + " 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\n"
			}
			answers["/usr/sbin/sshd -T"] = config
			answers["/usr/bin/ss -H -ltnp"] = listeners
			out, e := s.inspectIntrusion(context.Background())
			if e != nil || out.Healthy || out.Actions[0].ScopeVerified {
				t.Fatal("legacy22 falsely protects custom SSH", out, e)
			}
			answers["/usr/bin/fail2ban-client get sshd action nftables port"] = scope + "\n"
			answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, ports)
			manifest, e := s.readSoftwareManifest("intrusion-prevention")
			if e != nil {
				t.Fatal(e)
			}
			candidate, e := renderIntrusionPortScope(manifest.Settings, ports)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local"), []byte(candidate), 0644); e != nil {
				t.Fatal(e)
			}
			out, e = s.inspectIntrusion(context.Background())
			if e != nil || !out.Healthy || !reflect.DeepEqual(out.SSHListeningPorts, ports) {
				t.Fatal(out, e)
			}
		})
	}
}

func TestIntrusionInspectionKernelScopeIsIndependentFromRuntimeProperties(t *testing.T) {
	for _, mode := range []string{"stale-port", "missing-table", "extra-active-IP", "ban-list-changed"} {
		s, answers, _ := intrusionInspectionFixture(t)
		if mode == "stale-port" {
			answers["/usr/sbin/sshd -T"] = "port 2882\n"
			answers["/usr/bin/ss -H -ltnp"] = "LISTEN 0 128 0.0.0.0:2882 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\n"
			answers["/usr/bin/fail2ban-client get sshd action nftables port"] = "2882\n"
			manifest, e := s.readSoftwareManifest("intrusion-prevention")
			if e != nil {
				t.Fatal(e)
			}
			candidate, e := renderIntrusionPortScope(manifest.Settings, []int{2882})
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local"), []byte(candidate), 0644); e != nil {
				t.Fatal(e)
			}
		}
		if mode == "missing-table" {
			answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
		}
		if mode == "extra-active-IP" {
			value, _ := intrusionNftFixture(t)
			intrusionNftOwnRule(value)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(22)
			answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, value))
		}
		if mode == "ban-list-changed" {
			original := s.Config.Run
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				raw, e := original(ctx, program, args...)
				if program == "/usr/sbin/nft" {
					answers["/usr/bin/fail2ban-client get sshd banip"] = "127.0.0.2\n"
				}
				return raw, e
			}
		}
		out, e := s.inspectIntrusion(context.Background())
		if mode == "ban-list-changed" {
			if e == nil || out.Healthy {
				t.Fatal("changed ban snapshot accepted", out, e)
			}
			continue
		}
		if e != nil || out.Healthy || out.KernelScopeVerified || len(out.Actions) != 1 || !out.Actions[0].ScopeVerified || out.Actions[0].KernelScopeVerified || len(out.Warnings) == 0 {
			t.Fatal("runtime property replaced kernel proof", mode, out, e)
		}
	}
}

func intrusionPortLabel(port int) string { // fixtures use the same canonical range guard
	if port == 22 {
		return "22"
	}
	if port == 2882 {
		return "2882"
	}
	panic("unexpected fixture port")
}

func TestIntrusionInspectionRefusesFalsePositiveAndPrivateErrorLeak(t *testing.T) {
	for name, change := range map[string]func(*Service, map[string]string){
		"stale-sshd-config": func(s *Service, a map[string]string) { a["/usr/sbin/sshd -T"] = "port 2882\n" },
		"missing-listener":  func(s *Service, a map[string]string) { a["/usr/bin/ss -H -ltnp"] = "" },
		"service-down":      func(s *Service, a map[string]string) { a["/usr/bin/systemctl is-active fail2ban"] = "inactive\n" },
		"jail-unavailable":  func(s *Service, a map[string]string) { a["/usr/bin/fail2ban-client status sshd"] = "ERROR" },
		"alias-port": func(s *Service, a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd action nftables port"] = "ssh\n"
		},
		"extra-HTTP-port": func(s *Service, a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd action nftables port"] = "22,80\n"
		},
		"protocol-mismatch": func(s *Service, a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd action nftables protocol"] = "udp\n"
		},
		"unknown-python-action": func(s *Service, a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd actions"] = "The jail sshd has the following actions:\ncustom-python\n"
		},
		"retry-drift":        func(s *Service, a map[string]string) { a["/usr/bin/fail2ban-client get sshd maxretry"] = "9\n" },
		"window-drift":       func(s *Service, a map[string]string) { a["/usr/bin/fail2ban-client get sshd findtime"] = "1200\n" },
		"ban-output-corrupt": func(s *Service, a map[string]string) { a["/usr/bin/fail2ban-client get sshd bantime"] = "3600\nextra" },
		"CLI-private-error":  func(s *Service, a map[string]string) { a["/usr/sbin/sshd -T"] = "ERROR" },
		"extra-file-directive": func(s *Service, a map[string]string) {
			f := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
			raw, e := os.ReadFile(f)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(f, append(raw, []byte("port = 80\n")...), 0644); e != nil {
				t.Fatal(e)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, a, _ := intrusionInspectionFixture(t)
			change(s, a)
			out, e := s.inspectIntrusion(context.Background())
			if e != nil || out.Healthy || len(out.Warnings) == 0 {
				t.Fatal("unverified runtime reported healthy", out, e)
			}
			if strings.Contains(strings.Join(out.Warnings, " "), "private") || strings.Contains(strings.Join(out.Warnings, " "), "sensitive") {
				t.Fatal("backend private error leaked", out)
			}
		})
	}
}

func TestIntrusionInspectionDetectsAuthorityChangesAndUntrustedParents(t *testing.T) {
	for _, mode := range []string{"symlink", "writable", "file-changed", "manifest-changed"} {
		t.Run(mode, func(t *testing.T) {
			s, _, calls := intrusionInspectionFixture(t)
			file := s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local")
			if mode == "symlink" {
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(t.TempDir(), "outside"), file); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "writable" {
				if e := os.Chmod(filepath.Dir(file), 0777); e != nil {
					t.Fatal(e)
				}
			}
			original := s.Config.Run
			s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
				out, e := original(ctx, name, args...)
				if *calls == 1 && mode == "file-changed" {
					if x := os.WriteFile(file, []byte("# external changed configuration\n"), 0644); x != nil {
						t.Fatal(x)
					}
				}
				if *calls == 1 && mode == "manifest-changed" {
					m, x := s.readSoftwareManifest("intrusion-prevention")
					if x != nil {
						t.Fatal(x)
					}
					m.Settings["max_retry"] = 6
					if x = s.writeSoftwareManifest(m); x != nil {
						t.Fatal(x)
					}
				}
				return out, e
			}
			out, e := s.inspectIntrusion(context.Background())
			if e == nil || out.Healthy {
				t.Fatal("changed authority accepted", out, e)
			}
			if (mode == "symlink" || mode == "writable") && *calls != 0 {
				t.Fatal("untrusted path executed runtime commands", *calls)
			}
		})
	}
}

func TestIntrusionInspectionHTTPIsNoStoreAndCannotRepairUnknownManifest(t *testing.T) {
	s, _, calls := intrusionInspectionFixture(t)
	if e := os.WriteFile(s.softwareManifestPath("intrusion-prevention"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/v1/software/intrusion-prevention/inspection", nil))
	if response.Code != 409 || response.Header().Get("Cache-Control") != "no-store" || *calls != 0 {
		t.Fatal(response.Code, response.Body.String(), *calls)
	}
	if e := os.Remove(s.softwareManifestPath("intrusion-prevention")); e != nil {
		t.Fatal(e)
	}
	out, e := s.inspectIntrusion(context.Background())
	if e != nil || out.Installed || out.Healthy || *calls != 0 {
		t.Fatal(out, e)
	}
}
