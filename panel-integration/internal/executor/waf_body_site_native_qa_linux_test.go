//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Explicitly gated source-candidate integration on disposable compatibility
// VMs. This uses the real existing Nginx master/managed website includes and
// durable apply path, not a separate toy listener or mocked systemctl command.
func TestWAFBodyManagedSiteNativeQA(t *testing.T) {
	id := os.Getenv("PANEL_WAF_SITE_QA_ENGINE")
	if id == "" {
		t.Skip("explicit isolated QA gate required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main/unknown/non-root host")
	}
	if output, err := exec.Command("/usr/bin/sqlite3", "/var/lib/panel/panel.db", "SELECT (SELECT count(*) FROM jobs WHERE state IN ('queued','running'))+(SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running'));").Output(); err != nil || strings.TrimSpace(string(output)) != "0" {
		t.Fatal("compatibility VM has other active work; no service/config mutation permitted")
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal(err)
	}
	s := nativeWAFService()
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal("test requires already installed metadata WAF", err)
	}
	original, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || original.Body != nil || original.Policy.Mode != "block" {
		t.Fatal("refuse to replace an existing body policy or change global protection mode")
	}
	// Older installed metadata versions may have no new fingerprint endpoint.
	// Exact restoration must prove the original live response, not claim that
	// restoring untouched legacy bytes silently upgraded their health probe.
	probeOriginal, err := wafQALiveProbe()
	if err != nil {
		t.Fatal("cannot capture original live Nginx probe", err)
	}
	beforeNative := map[string]string{}
	for _, unit := range []string{"nginx.service", "panel.service", "panel-executor.service", "panel-nfs-server.service", "panel-pure-ftpd.service"} {
		out, err := exec.Command("/usr/bin/systemctl", "show", "-p", "MainPID,ExecMainStartTimestampMonotonic,ActiveState", unit).Output()
		if err != nil {
			t.Fatal(err)
		}
		beforeNative[unit] = string(out)
	}
	backupDir, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Files []struct {
			Source string      `json:"source"`
			File   string      `json:"file"`
			Exists bool        `json:"existed"`
			Mode   os.FileMode `json:"mode"`
			SHA    string      `json:"sha256"`
		} `json:"files"`
	}
	data, err := os.ReadFile(filepath.Join(backupDir, "index.json"))
	if err != nil || json.Unmarshal(data, &index) != nil {
		t.Fatal("missing durable QA original config backup")
	}
	backups := []fileBackup{}
	for _, file := range index.Files {
		b := fileBackup{path: file.Source, existed: file.Exists, mode: file.Mode}
		if b.existed {
			b.data, err = os.ReadFile(filepath.Join(backupDir, file.File))
			if err != nil || core.Hash(string(b.data)) != file.SHA {
				t.Fatal("QA original backup failed integrity")
			}
		}
		backups = append(backups, b)
	}
	site := core.ID()
	domain := "waf-body-business-" + site[:12] + ".localhost"
	path := filepath.Join(s.Config.ConfDir, site+".conf")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("own QA fixture collision")
	}
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"upstream":true}`)
	}))
	defer upstream.Close()
	owned := fmt.Sprintf("# managed by panel; site=%s\nserver {\n  listen 127.0.0.1:19101;\n  server_name %s;\n  client_max_body_size 1m;\n  access_log off;\n  location / { proxy_pass %s; }\n}\n", site, domain, upstream.URL)
	if err := atomicWrite(path, []byte(owned), 0644); err != nil {
		t.Fatal(err)
	}
	nativeRules := s.systemPath("/etc/panel/waf/body.d/" + site + ".conf")
	defer func() {
		// Restore only the exact previously captured managed files and our new
		// fixture. All new program/build/config audit histories remain retained.
		if err := restoreFiles(backups); err != nil {
			t.Error("original config restoration failed", err)
			return
		}
		for _, p := range []string{path, nativeRules} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		nginx, err := s.nginxBinary()
		if err == nil {
			_, err = s.Config.Run(context.Background(), nginx, "-t", "-c", s.Config.NginxConf)
		}
		if err == nil {
			_, err = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
		}
		if err == nil {
			for attempt := 0; attempt < 20; attempt++ {
				actual, probeErr := wafQALiveProbe()
				if probeErr == nil && actual == probeOriginal {
					err = nil
					break
				}
				err = fmt.Errorf("original live probe not restored: %v", probeErr)
				time.Sleep(100 * time.Millisecond)
			}
		}
		if err != nil {
			t.Error("original live WAF did not recover", err)
		}
		for _, b := range backups {
			got, err := backupFile(b.path)
			if err != nil || got.existed != b.existed || string(got.data) != string(b.data) || (b.existed && got.mode != b.mode) {
				t.Error("original configuration content/mode not exactly retained", b.path)
			}
		}
		for unit, before := range beforeNative {
			out, err := exec.Command("/usr/bin/systemctl", "show", "-p", "MainPID,ExecMainStartTimestampMonotonic,ActiveState", unit).Output()
			if err != nil || string(out) != before {
				t.Error("existing native master restarted or identity changed", unit)
			}
		}
		report := filepath.Join(backupDir, "site-native-acceptance.json")
		if data, err := os.ReadFile(report); err == nil {
			var result map[string]any
			if err := json.Unmarshal(data, &result); err != nil {
				t.Error(err)
				return
			}
			result["original_configs_and_native_masters_preserved"] = !t.Failed()
			result["passed"] = !t.Failed()
			if err := moduleWrite(report, result); err != nil {
				t.Error(err)
			}
		}
	}()
	cfg, err := core.DecodeWAFConfig(core.WAFSettings(original))
	if err != nil {
		t.Fatal(err)
	}
	// These historical disposable QA fixtures were archived before the new
	// WAF archive-reference guard existed. Do not weaken the production guard
	// or mutate its original settings: omit only this exact absent QA reference
	// from the temporary request-body test draft, then restore original bytes.
	omittedLegacyQAReference := false
	legacyQAReference := map[string]string{"arm64": "2aa9219de6c8bc649a671d573a335b76", "amd64": "a5872e670e539eaf43d2edcae99a1013"}[runtime.GOARCH]
	for i, rule := range cfg.Policy.CCRules {
		if rule.SiteID == legacyQAReference && !rule.Enabled {
			if _, err := os.Lstat(filepath.Join(s.Config.ConfDir, rule.SiteID+".conf")); !os.IsNotExist(err) {
				t.Fatal("legacy QA orphan is no longer absent; never omit it")
			}
			cfg.Policy.CCRules = append(cfg.Policy.CCRules[:i], cfg.Policy.CCRules[i+1:]...)
			omittedLegacyQAReference = true
			break
		}
	}
	policy := core.DefaultWAFBodyPolicy()
	policy.BodyLimitKiB, policy.NonFileLimitKiB = 128, 64
	cfg.Body = &core.WAFBodyConfig{EngineJobID: id, Sites: []core.WAFBodySitePolicy{{SiteID: site, Policy: policy}}}
	no := false
	groups := map[string]bool{}
	for _, name := range core.WAFGroupNames {
		groups[name] = false
	}
	cfg.Policy.Sites = append(cfg.Policy.Sites, core.WAFSitePolicy{SiteID: site, Mode: "block", CCEnabled: &no, Groups: groups})
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	type result struct {
		Mode, Name string
		Status     int
		Upstream   bool
	}
	results := []result{}
	secret := "private_site_waf_" + strconv.FormatInt(time.Now().UnixNano(), 16)
	for _, mode := range []string{"block", "observe", "off"} {
		cfg.Body.Sites[0].Policy.Mode = mode
		steps := []string{}
		if err := s.applyWAF(context.Background(), core.WAFSettings(cfg), false, func(m string) { steps = append(steps, m) }); err != nil {
			t.Fatal("real site policy apply failed", mode, err)
		}
		m, err := s.readSoftwareManifest("nginx-waf")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err = core.DecodeWAFConfig(m.Settings)
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := os.ReadFile(path)
		if strings.Contains(string(actual), wafBodySiteBegin) != (mode != "off") {
			t.Fatal("site enable/disable did not update actual managed config")
		}
		if _, err := os.Lstat(nativeRules); (err == nil) != (mode != "off") {
			t.Fatal("site disable did not remove actual rule file")
		}
		for _, probe := range []struct {
			name, ctype, body string
			blocked           int
		}{{"ordinary_json", "application/json", `{"term":"ordinary"}`, 200}, {"form_sqli", "application/x-www-form-urlencoded", url.Values{"term": {"1' OR '1'='1' -- " + secret}}.Encode(), 403}, {"json_sqli", "application/json", `{"nested":{"term":"1' OR '1'='1' -- ` + secret + `"}}`, 403}, {"json_xss", "application/json", `{"term":"<script>alert('` + secret + `')</script>"}`, 403}, {"malformed_json", "application/json", `{"term":` + secret, 400}, {"over_nonfile_limit", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 65*1024), 413}} {
			prior := reached.Load()
			req, _ := http.NewRequest("POST", "http://127.0.0.1:19101/probe", strings.NewReader(probe.body))
			req.Host = domain
			req.Header.Set("Content-Type", probe.ctype)
			req.Header.Set("User-Agent", "Mozilla/5.0 QA "+secret)
			req.Header.Set("Cookie", "private="+secret)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			want := 200
			if mode == "block" {
				want = probe.blocked
			}
			if err != nil || resp.StatusCode != want || (reached.Load() > prior) != (want == 200) {
				t.Fatalf("actual managed %s/%s: HTTP %d want %d, upstream=%v", mode, probe.name, resp.StatusCode, want, reached.Load() > prior)
			}
			results = append(results, result{mode, probe.name, resp.StatusCode, reached.Load() > prior})
		}
	}
	log, err := os.ReadFile(wafBodyLogPath)
	if err != nil || strings.Contains(string(log), secret) || !strings.Contains(string(log), "site="+site) || !strings.Contains(string(log), "rule=942100 phase=2") {
		t.Fatal("managed body log privacy/site/rule-phase contract failed")
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("deploy changed immutable program", err)
	}
	if err := moduleWrite(filepath.Join(backupDir, "site-native-acceptance.json"), map[string]any{"passed": false, "http_functionality_verified": true, "source_candidate_only": true, "signed_release_acceptance": false, "architecture": runtime.GOARCH, "engine_job": id, "site_id": site, "http_results": results, "private_markers_logged": false, "native_program_immutable": true, "exact_historical_arm_QA_orphan_omitted_only_from_temporary_draft": omittedLegacyQAReference}); err != nil {
		t.Fatal(err)
	}
	t.Log("actual managed-site policy proof:", filepath.Join(backupDir, "site-native-acceptance.json"))
}

func wafQALiveProbe() (string, error) {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	r, _ := http.NewRequest("GET", "http://127.0.0.1:19101/__panel_waf_check", nil)
	r.Host = "panel-waf-check.invalid"
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1025))
	if err != nil || len(body) > 1024 {
		return "", fmt.Errorf("unbounded original probe: %v", err)
	}
	return fmt.Sprintf("%d:%s", res.StatusCode, body), nil
}
