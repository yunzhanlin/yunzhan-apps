//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// An explicit private QA build is required. This never loads a module into the
// existing Nginx master and never changes a production configuration or unit.
func TestWAFNativeBodyThroughRealNginx(t *testing.T) {
	root := os.Getenv("PANEL_WAF_NATIVE_QA_ROOT")
	engineJob := os.Getenv("PANEL_WAF_ENGINE_QA_JOB")
	if root == "" && engineJob == "" {
		t.Skip("requires an owned pinned native-engine QA build")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") || os.Geteuid() != 0 {
		t.Fatal("not an authorized isolated native WAF QA host/root")
	}
	nginxBinary, nginxVersion, sourceRoot := "/usr/sbin/nginx", "1.24.0", filepath.Join(root, "build")
	var manifest struct {
		Root      string `json:"root"`
		State     string `json:"state"`
		Module    string `json:"module"`
		ModuleSHA string `json:"module_sha256"`
		Prototype bool   `json:"prototype"`
	}
	if engineJob != "" {
		if root != "" || !core.ValidID(engineJob) {
			t.Fatal("exactly one native QA build identity required")
		}
		if err := VerifyWAFEngineBuild(engineJob); err != nil {
			t.Fatal("bounded worker program verification failed", err)
		}
		record, err := readWAFBuildRecord(engineJob)
		if err != nil {
			t.Fatal(err)
		}
		root = filepath.Join(wafNativeBuildCache, engineJob)
		nginxBinary, nginxVersion, sourceRoot = record.NginxBinary, record.NginxVersion, filepath.Join(record.Prefix, "source")
		manifest.Root, manifest.State, manifest.Module, manifest.ModuleSHA = root, "ready", filepath.Join(record.Prefix, "nginx/ngx_http_modsecurity_module.so"), record.ModuleSHA
	} else {
		if strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" || !strings.HasPrefix(root, "/var/cache/panel-build/panel-waf-native-qa-") || !wafEngineConfigPath(root) {
			t.Fatal("unexpected prototype QA path")
		}
		data, err := os.ReadFile("/var/lib/panel-executor/qa-waf-native-build.json")
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &manifest); err != nil || manifest.Root != root || manifest.State != "built" || !manifest.Prototype || manifest.Module != filepath.Join(root, "build/nginx-1.24.0/objs/ngx_http_modsecurity_module.so") {
			t.Fatal("no matching pinned prototype build")
		}
	}
	module, err := os.ReadFile(manifest.Module)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(module)
	if hex.EncodeToString(sha[:]) != manifest.ModuleSHA {
		t.Fatal("QA module changed after compilation")
	}
	version, err := exec.Command(nginxBinary, "-v").CombinedOutput()
	versionMatch := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(string(version)))
	if err != nil || len(versionMatch) != 2 || versionMatch[1] != nginxVersion {
		t.Fatal("selected Nginx changed")
	}
	before := wafQANativeProtectedSnapshot(t)
	defer func() {
		if changed, ok := wafQANativeChanges(before, wafQANativeProtectedSnapshot(t)); !ok {
			t.Error("protected native identities/configuration changed", changed)
		}
	}()
	probe, err := os.MkdirTemp(root, "http-probe-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(probe, 0755); err != nil {
		t.Fatal(err)
	}
	u, err := user.Lookup("www-data")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	temporary := filepath.Join(probe, "body-tmp")
	if err = os.Mkdir(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(temporary, uid, gid); err != nil {
		t.Fatal(err)
	}
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 9<<20))
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"upstream":true}`)
	}))
	defer upstream.Close()
	var externalFetches atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalFetches.Add(1)
		_, _ = io.WriteString(w, "must_not_fetch_private_xml")
	}))
	defer external.Close()
	secret := "waf_private_" + strconv.FormatInt(time.Now().UnixNano(), 16)
	type caseResult struct {
		Mode            string `json:"mode"`
		Name            string `json:"name"`
		Status          int    `json:"status"`
		ReachedUpstream bool   `json:"reached_upstream"`
	}
	results := []caseResult{}
	metadataEvents := 0
	logBoundaryVerified := false
	privacyOK, privacyCheckedModes := true, 0
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	for _, mode := range []string{"block", "observe", "off"} {
		t.Run(mode, func(t *testing.T) {
			policy := defaultWAFBodyPolicy()
			policy.Mode = mode
			policy.BodyLimitKiB = 128
			policy.NonFileLimitKiB = 64
			rules, err := renderWAFBodyRules(policy, sourceRoot, temporary)
			if err != nil {
				t.Fatal(err)
			}
			rulesPath := filepath.Join(probe, mode+"-rules.conf")
			if err = os.WriteFile(rulesPath, []byte(rules), 0644); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			_ = listener.Close()
			logPath := filepath.Join(probe, mode+"-error.log")
			if err = os.WriteFile(logPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			metadataPath := filepath.Join(probe, mode+"-metadata.log")
			if err = os.WriteFile(metadataPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			pidPath := filepath.Join(probe, mode+".pid")
			confPath := filepath.Join(probe, mode+"-nginx.conf")
			conf := fmt.Sprintf("load_module %s;\nuser www-data;\nworker_processes 2;\npid %s;\nerror_log %s warn;\nevents { worker_connections 64; }\nhttp {\naccess_log off;\nmodsecurity_metadata_log %s;\nclient_body_temp_path %s;\nmap $server_name $panel_waf_site { default 0123456789abcdef0123456789abcdef; }\nserver { listen %s; server_name waf-qa.localhost; client_max_body_size 8m; modsecurity on; modsecurity_rules_file %s; location / { proxy_pass %s; } }\n}\n", manifest.Module, pidPath, logPath, metadataPath, temporary, address, rulesPath, upstream.URL)
			// Rejected oversized bodies may leave Nginx in its normal lingering
			// close window. Bound retirement only for this standalone QA child;
			// do not change the existing server's shutdown policy or hide failures.
			conf = strings.Replace(conf, "worker_processes 2;\n", "worker_processes 2;\nworker_shutdown_timeout 3s;\n", 1)
			if err = os.WriteFile(confPath, []byte(conf), 0600); err != nil {
				t.Fatal(err)
			}
			check, err := exec.Command(nginxBinary, "-t", "-p", probe+"/", "-c", confPath).CombinedOutput()
			if err != nil {
				t.Fatalf("isolated native config/ABI rejected: %s", check)
			}
			cmd := exec.Command(nginxBinary, "-p", probe+"/", "-c", confPath, "-g", "daemon off;")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var processLog bytes.Buffer
			cmd.Stdout = &processLog
			cmd.Stderr = &processLog
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			defer func() {
				_ = cmd.Process.Signal(syscall.SIGQUIT)
				select {
				case err := <-finished:
					if err != nil {
						t.Errorf("owned Nginx child exit: %v", err)
					}
				case <-time.After(8 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-finished
					t.Error("owned Nginx child did not shut down gracefully")
				}
				if conn, e := net.DialTimeout("tcp", address, 200*time.Millisecond); e == nil {
					conn.Close()
					t.Error("owned test port was left listening")
				}
			}()
			for deadline := time.Now().Add(5 * time.Second); ; {
				conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if e == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("isolated native Nginx did not start")
				}
				time.Sleep(50 * time.Millisecond)
			}
			sqli := "1' OR '1'='1' -- " + secret
			xss := "<script>alert('" + secret + "')</script>"
			form := func(value string) string { return url.Values{"term": {value}, "private_note": {secret}}.Encode() }
			jsonBody := func(value string) string {
				b, _ := json.Marshal(map[string]any{"nested": map[string]string{"term": value}, "private_note": secret})
				return string(b)
			}
			var upload bytes.Buffer
			writer := multipart.NewWriter(&upload)
			_ = writer.WriteField("term", xss)
			part, _ := writer.CreateFormFile("upload", "ordinary.txt")
			_, _ = io.WriteString(part, "ordinary file content")
			_ = writer.Close()
			var safeUpload bytes.Buffer
			safeWriter := multipart.NewWriter(&safeUpload)
			_ = safeWriter.WriteField("term", "ordinary field")
			safePart, _ := safeWriter.CreateFormFile("upload", "ordinary.txt")
			_, _ = io.WriteString(safePart, "ordinary file content")
			_ = safeWriter.Close()
			manyArgs := url.Values{}
			for i := 0; i < 257; i++ {
				manyArgs.Set(fmt.Sprintf("field_%03d", i), "ordinary")
			}
			type probeCase struct {
				name, method, ctype, body, encoding string
				blockStatus                         []int
			}
			cases := []probeCase{
				{"ordinary_get", "GET", "", "", "", []int{200}},
				{"ordinary_form", "POST", "application/x-www-form-urlencoded", form("ordinary search"), "", []int{200}},
				{"ordinary_json", "POST", "application/json", jsonBody("ordinary search"), "", []int{200}},
				{"ordinary_put_json", "PUT", "application/json", jsonBody("ordinary search"), "", []int{200}},
				{"ordinary_patch_json", "PATCH", "application/json", jsonBody("ordinary search"), "", []int{200}},
				{"ordinary_multipart", "POST", safeWriter.FormDataContentType(), safeUpload.String(), "", []int{200}},
				{"ordinary_xml", "POST", "application/xml", `<x><term>ordinary</term></x>`, "", []int{200}},
				{"form_sqli", "POST", "application/x-www-form-urlencoded", form(sqli), "", []int{403}},
				{"json_sqli", "POST", "application/json", jsonBody(sqli), "", []int{403}},
				{"vendor_json_sqli", "POST", "application/vnd.api+json; charset=utf-8", jsonBody(sqli), "", []int{403}},
				{"form_xss", "POST", "application/x-www-form-urlencoded", form(xss), "", []int{403}},
				{"json_xss", "POST", "application/json", jsonBody(xss), "", []int{403}},
				{"form_command", "POST", "application/x-www-form-urlencoded", form("; cat /etc/passwd; " + secret), "", []int{403}},
				{"form_traversal", "POST", "application/x-www-form-urlencoded", form("../../../../etc/passwd"), "", []int{403}},
				{"multipart_xss", "POST", writer.FormDataContentType(), upload.String(), "", []int{403}},
				{"malformed_json", "POST", "application/json", `{"nested":` + secret, "", []int{400}},
				{"body_over_limit", "POST", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 129*1024), "", []int{413}},
				{"non_file_body_over_limit", "POST", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 65*1024), "", []int{413}},
				{"json_depth_over_limit", "POST", "application/json", strings.Repeat(`{"a":`, 65) + `0` + strings.Repeat(`}`, 65), "", []int{400}},
				{"arguments_over_limit", "POST", "application/x-www-form-urlencoded", manyArgs.Encode(), "", []int{400}},
				{"xml_sqli", "POST", "application/xml", `<x><term>` + sqli + `</term></x>`, "", []int{403}},
				{"encoded_body", "POST", "application/json", jsonBody("ordinary search"), "gzip", []int{415}},
				{"xml_external_entity", "POST", "application/xml", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "` + external.URL + `/` + secret + `">]><x>&e;</x>`, "", []int{200, 400, 403}},
			}
			for _, c := range cases {
				countBefore := upstreamRequests.Load()
				req, err := http.NewRequest(c.method, "http://"+address+"/probe?private_query="+secret, strings.NewReader(c.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "waf-qa.localhost"
				req.Header.Set("User-Agent", "Mozilla/5.0 QA "+secret)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Cookie", "panel_session="+secret)
				req.Header.Set("Authorization", "Bearer "+secret)
				if c.ctype != "" {
					req.Header.Set("Content-Type", c.ctype)
				}
				if c.encoding != "" {
					req.Header.Set("Content-Encoding", c.encoding)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s request failed: %v", c.name, err)
				}
				response, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(response, []byte(secret)) {
					privacyOK = false
					t.Fatal("response exposed a private marker")
				}
				allowed := []int{200}
				if mode == "block" {
					allowed = c.blockStatus
				}
				if !wafQAStatusIn(resp.StatusCode, allowed) {
					t.Errorf("%s: HTTP %d, expected %v", c.name, resp.StatusCode, allowed)
				}
				reached := upstreamRequests.Load() > countBefore
				if reached != (resp.StatusCode == 200) {
					t.Errorf("%s: interception/upstream mismatch", c.name)
				}
				results = append(results, caseResult{mode, c.name, resp.StatusCode, reached})
			}
			if externalFetches.Load() != 0 {
				t.Fatal("XML parser made an external entity request")
			}
			time.Sleep(100 * time.Millisecond)
			logs, err := os.ReadFile(metadataPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(logs, []byte(secret)) || strings.Contains(string(logs), "client: 127.0.0.1") || strings.Contains(string(logs), "request: \"POST") || strings.Contains(string(logs), "Matched Data:") {
				privacyOK = false
				t.Error("native WAF log leaked matched/request context")
			}
			eventPattern := regexp.MustCompile(`yunzhan_waf_body rule=[0-9]+ phase=[1-5] severity=[0-9]+ disruptive=[01] site=0123456789abcdef0123456789abcdef`)
			events := eventPattern.FindAll(logs, -1)
			for _, line := range strings.Split(strings.TrimSpace(string(logs)), "\n") {
				if line != "" && !eventPattern.MatchString(line) {
					privacyOK = false
					t.Error("dedicated WAF log contained a non-metadata entry")
				}
			}
			if mode != "off" && !bytes.Contains(logs, []byte("rule=942100 phase=2")) {
				t.Error("SQLi rule event lost its original request-body phase")
			}
			if mode != "off" && len(events) == 0 {
				t.Error("no numerical native-engine event was emitted")
			}
			if mode == "off" && len(events) != 0 {
				t.Error("disabled native engine still emitted match events")
			}
			metadataEvents += len(events)
			privacyCheckedModes++
			if mode == "block" {
				// Fill only this newly created standalone test log. Native site
				// logs/configs are never padded, truncated or signalled.
				if err := os.WriteFile(filepath.Join(probe, "block-before-log-boundary.log"), logs, 0600); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(metadataPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(wafBodyLogLimit); err != nil {
					f.Close()
					t.Fatal(err)
				}
				f.Close()
				probeAttack := func() error {
					req, _ := http.NewRequest("POST", "http://"+address+"/probe", strings.NewReader(jsonBody(xss)))
					req.Header.Set("Content-Type", "application/json")
					res, err := client.Do(req)
					if err != nil {
						return err
					}
					_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
					res.Body.Close()
					if res.StatusCode != 403 {
						return fmt.Errorf("enforcement changed at log boundary: HTTP %d", res.StatusCode)
					}
					return nil
				}
				var group sync.WaitGroup
				failures := make(chan error, 32)
				for i := 0; i < 32; i++ {
					group.Add(1)
					go func() {
						defer group.Done()
						if err := probeAttack(); err != nil {
							failures <- err
						}
					}()
				}
				group.Wait()
				close(failures)
				for err := range failures {
					t.Error(err)
				}
				st, err := os.Stat(metadataPath)
				if err != nil || st.Size() != wafBodyLogLimit {
					t.Fatal("multi-worker metadata exceeded fixed disk cap", st, err)
				}
				if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
					t.Fatal(err)
				}
				for deadline := time.Now().Add(3 * time.Second); ; {
					st, err = os.Stat(metadataPath)
					if err == nil && st.Sys().(*syscall.Stat_t).Uid == uint32(uid) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("actual owned Nginx USR1 did not reopen worker-owned log")
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err := probeAttack(); err != nil {
					t.Fatal(err)
				}
				f, err = os.OpenFile(metadataPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(0); err != nil {
					f.Close()
					t.Fatal(err)
				}
				f.Close()
				if err := probeAttack(); err != nil {
					t.Fatal(err)
				}
				for deadline := time.Now().Add(2 * time.Second); ; {
					st, err = os.Stat(metadataPath)
					if err == nil && st.Size() > 0 && st.Size() < 512*32 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("metadata did not resume after same-inode truncate")
					}
					time.Sleep(20 * time.Millisecond)
				}
				current, err := os.ReadFile(metadataPath)
				if err != nil || bytes.Contains(current, []byte(secret)) {
					t.Fatal("private context leaked after reopen/rotation")
				}
				for _, line := range bytes.Split(bytes.TrimSpace(current), []byte{'\n'}) {
					if _, ok := parseWAFBodyEvent(line); !ok {
						t.Fatal("resumed metadata violated numeric-only contract")
					}
				}
				logBoundaryVerified = !t.Failed()
			}
			t.Logf("real Nginx %s: %d request cases, %d bounded metadata events; dedicated-log privacy=%v", mode, len(cases), len(events), privacyOK)
		})
	}
	after := wafQANativeProtectedSnapshot(t)
	changed, preserved := wafQANativeChanges(before, after)
	if !preserved {
		t.Error("protected native identities/configuration changed", changed)
	}
	report := map[string]any{"passed": !t.Failed(), "prototype": engineJob == "", "production_loaded": false, "bounded_worker_build_job": engineJob, "built_engine_verified": engineJob != "", "selected_nginx": nginxVersion, "selected_nginx_binary": nginxBinary, "engine_version": wafBodyEngineVersion, "connector_version": wafBodyConnectorVersion, "crs_version": wafBodyCRSVersion, "module_sha256": manifest.ModuleSHA, "cases": results, "metadata_event_count": metadataEvents, "external_entity_fetches": externalFetches.Load(), "no_private_marker_in_managed_events": privacyOK && privacyCheckedModes == 3, "website_error_log_boundary": "ordinary Nginx website errors are separate and may retain request context", "protected_native_state_unchanged": preserved, "before_snapshot": json.RawMessage(before), "after_snapshot": json.RawMessage(after), "named_live_monitor_changes": changed}
	if engineJob != "" {
		if err := VerifyWAFEngineBuild(engineJob); err != nil {
			t.Fatal("sealed program changed after real HTTP probe", err)
		}
	}
	report["two_worker_32_concurrent_attacks_log_cap_enforcement_USR1_and_same_inode_resume_verified"] = logBoundaryVerified
	if !logBoundaryVerified {
		t.Error("native metadata log boundary acceptance did not complete")
		report["passed"] = false
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	if err = os.WriteFile(filepath.Join(probe, "acceptance.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("native acceptance evidence retained at", filepath.Join(probe, "acceptance.json"))
}

func wafQAStatusIn(status int, allowed []int) bool {
	for _, v := range allowed {
		if status == v {
			return true
		}
	}
	return false
}

func wafQANativeProtectedSnapshot(t *testing.T) string {
	t.Helper()
	values := map[string]string{}
	for _, root := range []string{"/etc/nginx", "/etc/panel"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			sha := sha256.Sum256(b)
			values[path] = hex.EncodeToString(sha[:])
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nginx.service", "panel.service", "panel-executor.service", "panel-nfs-server.service", "panel-pure-ftpd.service"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID,ExecMainStartTimestampMonotonic,ActiveState", name).Output()
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		values[name] = string(b)
	}
	b, _ := json.Marshal(values)
	return string(b)
}

// Retain every before/after hash; only the 15 already-running QA monitor
// records may legitimately advance during HTTP probes. Configuration, native
// process identity, other baselines and new/removed files remain protected.
func wafQANativeChanges(before, after string) ([]string, bool) {
	var old, next map[string]string
	if json.Unmarshal([]byte(before), &old) != nil || json.Unmarshal([]byte(after), &next) != nil {
		return nil, false
	}
	allowed := map[string]bool{}
	for _, module := range []string{"enterprise-tamper-proof", "website-tamper-proof", "file-monitor"} {
		base := "/etc/panel/security-apps/modules/" + module + "/"
		for _, file := range []string{"history.sqlite", "history.json", "last-report.json", "baselines/080e8b1cace24105f6c1d84ebfd2fb01/monitoring.json", "baselines/080e8b1cace24105f6c1d84ebfd2fb01/last-check.json"} {
			allowed[base+file] = true
		}
	}
	changed, ok := []string{}, true
	for path, sha := range old {
		if actual, exists := next[path]; actual != sha || !exists {
			changed = append(changed, path)
			ok = ok && allowed[path] && exists
		}
	}
	for path := range next {
		if _, exists := old[path]; !exists {
			changed = append(changed, path)
			ok = false
		}
	}
	sort.Strings(changed)
	return changed, ok
}

func TestWAFQANativeChangesPreserveForeignState(t *testing.T) {
	allowed := "/etc/panel/security-apps/modules/file-monitor/history.json"
	for _, tc := range []struct {
		before, after string
		want          bool
	}{
		{`{"nginx.service":"a"}`, `{"nginx.service":"b"}`, false},
		{`{"/etc/nginx/nginx.conf":"a"}`, `{"/etc/nginx/nginx.conf":"b"}`, false},
		{`{"` + allowed + `":"a"}`, `{"` + allowed + `":"b"}`, true},
		{`{"` + allowed + `":"a"}`, `{}`, false},
		{`{}`, `{"` + allowed + `":"a"}`, false},
		{`{"/etc/panel/security-apps/modules/file-monitor/baselines/other/monitoring.json":"a"}`, `{"/etc/panel/security-apps/modules/file-monitor/baselines/other/monitoring.json":"b"}`, false},
	} {
		if _, got := wafQANativeChanges(tc.before, tc.after); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
