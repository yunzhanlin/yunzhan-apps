//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Prototype native acceptance, not a production enablement or install receipt.
// The runner binds only a copied, sealed compiler output and private logs. It
// never signals the existing Apache, opens Main19100, or modifies a real site.
func TestApacheBodyNativeHTTPParsersModesPrivacyAndPhysicalLogCeiling(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_HTTP") != "1" {
		t.Skip("explicit isolated Apache body HTTP fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("restricted root fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	input := "/run/panel-apache-body-inputs24aeg"
	var compiler struct {
		Passed    bool              `json:"compiler_fixture_passed"`
		Hardening bool              `json:"elf_hardening_verified"`
		Engine    string            `json:"engine_version"`
		ModuleSHA string            `json:"module_sha256"`
		Inputs    map[string]string `json:"input_sha256"`
		Assets    map[string]string `json:"assets"`
	}
	b, err := os.ReadFile(filepath.Join(input, "compiler-proof.json"))
	if err != nil || json.Unmarshal(b, &compiler) != nil || !compiler.Passed || !compiler.Hardening || compiler.Engine != apacheBodyEngineVersion || !reflect.DeepEqual(compiler.Assets, apacheBodyAssetPins()) {
		t.Fatal("no matching reviewed prototype compiler proof", err)
	}
	for _, s := range apacheBodySources() {
		if compiler.Inputs[s.Name] != s.SHA256 {
			t.Fatal("compiler source provenance mismatch")
		}
	}
	module := filepath.Join(input, "mod_security2.so")
	if digest, err := wafNativeFileSHA(ctx, module, 64<<20); err != nil || digest != compiler.ModuleSHA {
		t.Fatal("prototype module changed", err)
	}
	dynamic, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-d", module).CombinedOutput()
	if err != nil || strings.Contains(string(dynamic), "libyajl.so") || strings.Contains(string(dynamic), "/run/panel-") || strings.Contains(string(dynamic), "/var/tmp/") {
		t.Fatal("private JSON must be static; no writable build RPATH", string(dynamic), err)
	}
	headers, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", "-l", module).CombinedOutput()
	if err != nil {
		t.Fatal("native module program headers", err)
	}
	symbols, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", "-s", module).CombinedOutput()
	if err != nil {
		t.Fatal("native module symbols", err)
	}
	if err := verifyApacheBodyELFHardening(string(dynamic), string(headers), string(symbols)); err != nil {
		t.Fatal("native module hardening changed after sealing", err)
	}
	root, err := os.MkdirTemp("/run/panel-apache-body24aeg", "http-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	resources := filepath.Join(root, "resources")
	if err = os.Mkdir(resources, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(resources, 0755); err != nil {
		t.Fatal(err)
	}
	crs := wafEngineSources()[2]
	if err = extractWAFEngineSource(ctx, crs, filepath.Join(input, "crs.tar.gz"), filepath.Join(resources, "crs-source")); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(resources, "crs-source/coreruleset-4.30.0"), filepath.Join(resources, "coreruleset-4.30.0")); err != nil {
		t.Fatal(err)
	}
	unicodeDir := filepath.Join(resources, "modsecurity-v2.9.15")
	if err = os.Mkdir(unicodeDir, 0755); err != nil {
		t.Fatal(err)
	}
	unicode, err := os.ReadFile(filepath.Join(input, "unicode.mapping"))
	if err != nil || len(unicode) > 4<<20 {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(unicodeDir, "unicode.mapping"), unicode, 0644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "body-tmp")
	if err = os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(tmp, 33, 33); err != nil {
		t.Fatal(err)
	}
	var hits, externalHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		digest := sha256.Sum256(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"upstream": true, "bytes": len(body), "sha256": hex.EncodeToString(digest[:])})
	}))
	defer backend.Close()
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalHits.Add(1)
		_, _ = io.WriteString(w, "must_not_fetch")
	}))
	defer external.Close()
	secret := "apache_private_" + strconv.FormatInt(time.Now().UnixNano(), 16)
	form := func(v string) string { return url.Values{"term": {v}, "private_note": {secret}}.Encode() }
	jsonBody := func(v string) string {
		b, _ := json.Marshal(map[string]any{"nested": map[string]string{"term": v}, "private_note": secret})
		return string(b)
	}
	upload := func(v string) (string, string) {
		var b bytes.Buffer
		m := multipart.NewWriter(&b)
		_ = m.WriteField("term", v)
		f, _ := m.CreateFormFile("upload", "ordinary.txt")
		_, _ = io.WriteString(f, "ordinary file content")
		_ = m.Close()
		return b.String(), m.FormDataContentType()
	}
	safeUpload, safeType := upload("ordinary field")
	xssUpload, xssType := upload("<script>alert('" + secret + "')</script>")
	sqli := "1' OR '1'='1' -- " + secret
	xss := "<script>alert('" + secret + "')</script>"
	args := url.Values{}
	for i := 0; i < 257; i++ {
		args.Set(fmt.Sprintf("field_%03d", i), "ordinary")
	}
	type requestCase struct {
		name, method, contentType, body, encoding string
		block                                     []int
	}
	cases := []requestCase{
		{"ordinary_get", "GET", "", "", "", []int{200}},
		{"ordinary_form", "POST", "application/x-www-form-urlencoded", form("ordinary search"), "", []int{200}},
		{"ordinary_json", "POST", "application/json", jsonBody("ordinary search"), "", []int{200}},
		{"ordinary_put", "PUT", "application/json", jsonBody("ordinary search"), "", []int{200}},
		{"ordinary_patch", "PATCH", "application/json", jsonBody("ordinary search"), "", []int{200}},
		{"ordinary_upload", "POST", safeType, safeUpload, "", []int{200}},
		{"ordinary_xml", "POST", "application/xml", "<x><term>ordinary</term></x>", "", []int{200}},
		{"ordinary_vendor_json", "POST", "application/vnd.api+json; charset=utf-8", jsonBody("ordinary search"), "", []int{200}},
		{"ordinary_depth64_object", "POST", "application/json", strings.Repeat(`{"a":`, 64) + "0" + strings.Repeat("}", 64), "", []int{200}},
		{"ordinary_depth64_array", "POST", "application/json", strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64), "", []int{200}},
		{"ordinary_empty_object", "POST", "application/json", "{}", "", []int{200}},
		{"ordinary_empty_array", "POST", "application/json", "[]", "", []int{200}},
		{"form_sqli", "POST", "application/x-www-form-urlencoded", form(sqli), "", []int{403}},
		{"json_sqli", "POST", "application/json", jsonBody(sqli), "", []int{403}},
		{"vendor_json_sqli", "POST", "application/vnd.api+json; charset=utf-8", jsonBody(sqli), "", []int{403}},
		{"form_xss", "POST", "application/x-www-form-urlencoded", form(xss), "", []int{403}},
		{"json_xss", "POST", "application/json", jsonBody(xss), "", []int{403}},
		{"command", "POST", "application/x-www-form-urlencoded", form("; cat /etc/passwd; " + secret), "", []int{403}},
		{"traversal", "POST", "application/x-www-form-urlencoded", form("../../../../etc/passwd"), "", []int{403}},
		{"upload_xss", "POST", xssType, xssUpload, "", []int{403}},
		{"malformed_json", "POST", "application/json", `{"nested":` + secret, "", []int{400}},
		{"body_limit", "POST", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 129*1024), "", []int{413}},
		{"nonfile_limit", "POST", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 65*1024), "", []int{413}},
		{"depth_limit", "POST", "application/json", strings.Repeat(`{"a":`, 65) + "0" + strings.Repeat("}", 65), "", []int{400}},
		{"depth_limit_array", "POST", "application/json", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), "", []int{400}},
		{"depth_limit_mixed", "POST", "application/json", strings.Repeat(`{"a":[`, 33) + "0" + strings.Repeat("]}", 33), "", []int{400}},
		{"body_remainder_forwarding", "POST", "application/x-www-form-urlencoded", "term=" + strings.Repeat("a", 257*1024), "", []int{413}},
		{"argument_limit", "POST", "application/x-www-form-urlencoded", args.Encode(), "", []int{400}},
		{"xml_sqli", "POST", "application/xml", "<x><term>" + sqli + "</term></x>", "", []int{403}},
		{"encoded_body", "POST", "application/json", jsonBody("ordinary"), "gzip", []int{415}},
		{"xml_external_entity", "POST", "application/xml", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "` + external.URL + "/" + secret + `">]><x>&e;</x>`, "", []int{200, 400, 403}},
	}
	type result struct {
		Mode          string `json:"mode"`
		Name          string `json:"name"`
		Status        int    `json:"status"`
		Reached       bool   `json:"reached_upstream"`
		BodyUnchanged bool   `json:"body_unchanged_when_forwarded"`
	}
	results := []result{}
	transport := []map[string]any{}
	logCap := false
	eventCount := 0
	numericReports := []map[string]any{}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	log := apacheBodyMetadataLog
	for _, mode := range []string{"block", "observe", "off"} {
		t.Run(mode, func(t *testing.T) {
			// Each mode owns a new private sink. Preserve the previous mode's
			// evidence in the same bind mount; restricted root has no DAC_OVERRIDE
			// and must not truncate a worker-owned 0600 sink or weaken its mode.
			if mode != "block" {
				previous := filepath.Join(filepath.Dir(log), "before-"+mode+".events.log")
				if _, err := os.Lstat(previous); !os.IsNotExist(err) {
					t.Fatal("private mode evidence already exists", err)
				}
				if err := os.Rename(log, previous); err != nil {
					t.Fatal(err)
				}
			}
			sink, err := os.OpenFile(log, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = sink.Chown(33, 33)
			closeErr := sink.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			policy := defaultWAFBodyPolicy()
			policy.Mode = mode
			policy.BodyLimitKiB = 128
			policy.NonFileLimitKiB = 64
			rules, err := renderApacheBodySiteRules(policy, resources, tmp, "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			global, err := renderApacheBodyGlobalRules(resources)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			_ = listener.Close()
			var conf strings.Builder
			fmt.Fprintf(&conf, "ServerRoot /opt/panel/runtimes/apache/2.4.68\nDefaultRuntimeDir %s\nPidFile %s\nListen %s\nServerName protected.localhost\nUser www-data\nGroup www-data\nErrorLog %s\nLogLevel warn\n", root, filepath.Join(root, mode+".pid"), address, filepath.Join(root, mode+"-error.log"))
			for _, name := range []string{"mpm_event", "authz_core", "authz_host", "unixd", "log_config", "env", "setenvif", "unique_id", "proxy", "proxy_http"} {
				fmt.Fprintf(&conf, "LoadModule %s_module /opt/panel/runtimes/apache/2.4.68/modules/mod_%s.so\n", name, name)
			}
			fmt.Fprintf(&conf, "LoadModule security2_module %s\n<Directory />\nRequire all granted\n</Directory>\n", module)
			conf.WriteString(global)
			fmt.Fprintf(&conf, "<VirtualHost %s>\nServerName protected.localhost\nSetEnvIfExpr \"true\" PANEL_AW_SITE=0123456789abcdef0123456789abcdef\n%s\nProxyPass / %s/\n</VirtualHost>\n", address, rules, backend.URL)
			fmt.Fprintf(&conf, "<VirtualHost %s>\nServerName unmanaged.localhost\nSecRuleEngine Off\nProxyPass / %s/\n</VirtualHost>\n", address, backend.URL)
			config := filepath.Join(root, mode+".conf")
			if err = os.WriteFile(config, []byte(conf.String()), 0600); err != nil {
				t.Fatal(err)
			}
			apache := "/opt/panel/runtimes/apache/2.4.68/bin/httpd"
			check, err := exec.CommandContext(ctx, apache, "-t", "-f", config).CombinedOutput()
			if err != nil {
				t.Fatalf("real native v2 parser/ABI rejected: %s %v", check, err)
			}
			startup, err := os.OpenFile(filepath.Join(root, mode+"-startup.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, apache, "-DFOREGROUND", "-f", config)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Stdout, cmd.Stderr = startup, startup
			if err = cmd.Start(); err != nil {
				startup.Close()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case err := <-done:
					if err != nil {
						t.Error("owned Apache shutdown", err)
					}
				case <-time.After(10 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-done
					t.Error("owned Apache did not shut down")
				}
				startup.Close()
			}()
			for deadline := time.Now().Add(5 * time.Second); ; {
				conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if e == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("owned Apache readiness")
				}
				time.Sleep(25 * time.Millisecond)
			}
			probe := func(c requestCase, host string) (int, bool, bool) {
				t.Helper()
				before := hits.Load()
				req, err := http.NewRequestWithContext(ctx, c.method, "http://"+address+"/probe?private_query="+secret, strings.NewReader(c.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = host
				req.Header.Set("User-Agent", "Mozilla/5.0 QA "+secret)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Cookie", "panel_session="+secret)
				req.Header.Set("Authorization", "Bearer "+secret)
				if c.contentType != "" {
					req.Header.Set("Content-Type", c.contentType)
				}
				if c.encoding != "" {
					req.Header.Set("Content-Encoding", c.encoding)
				}
				var reused, gotConn atomic.Bool
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					gotConn.Store(true)
					reused.Store(info.Reused)
				}}))
				res, err := client.Do(req)
				if err != nil {
					failure := "other"
					if errors.Is(err, io.EOF) {
						failure = "EOF"
					} else if errors.Is(err, io.ErrUnexpectedEOF) {
						failure = "unexpected_EOF"
					}
					transport = append(transport, map[string]any{"mode": mode, "case": c.name, "got_connection": gotConn.Load(), "reused": reused.Load(), "error": failure})
					t.Error(c.name, "HTTP request failed", failure)
					return 0, hits.Load() > before, false
				}
				transport = append(transport, map[string]any{"mode": mode, "case": c.name, "status": res.StatusCode, "got_connection": gotConn.Load(), "reused": reused.Load(), "response_close": res.Close})
				response, err := io.ReadAll(io.LimitReader(res.Body, 8192))
				res.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(response, []byte(secret)) {
					t.Error("response exposed synthetic private marker")
				}
				reached := hits.Load() > before
				unchanged := !reached
				if reached {
					var receipt struct {
						Upstream bool   `json:"upstream"`
						Bytes    int    `json:"bytes"`
						SHA      string `json:"sha256"`
					}
					hash := sha256.Sum256([]byte(c.body))
					unchanged = json.Unmarshal(response, &receipt) == nil && receipt.Upstream && receipt.Bytes == len(c.body) && receipt.SHA == hex.EncodeToString(hash[:])
					if !unchanged {
						t.Error(c.name, "forwarded request body changed")
					}
				}
				return res.StatusCode, reached, unchanged
			}
			for _, c := range cases {
				status, reached, unchanged := probe(c, "protected.localhost")
				allowed := []int{200}
				if mode == "block" {
					allowed = c.block
				}
				if !wafQAStatusIn(status, allowed) || reached != (status == 200) {
					t.Error(c.name, "status", status, "wanted", allowed, "upstream", reached)
				}
				results = append(results, result{mode, c.name, status, reached, unchanged})
			}
			if externalHits.Load() != 0 {
				t.Error("XML fetched external entity")
			}
			status, reached, unchanged := probe(cases[2], "protected.localhost")
			if status != 200 || !reached || !unchanged {
				t.Error("ordinary request did not recover after denied/malformed inputs")
			}
			results = append(results, result{mode, "ordinary_after_all_inputs", status, reached, unchanged})
			status, reached, unchanged = probe(requestCase{"unmanaged_json_sqli", "POST", "application/json", jsonBody(sqli), "", nil}, "unmanaged.localhost")
			if status != 200 || !reached || !unchanged {
				t.Error("protected-site policy leaked to unmanaged vhost")
			}
			results = append(results, result{mode, "unmanaged_json_sqli", status, reached, unchanged})
			metadata, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "off" && len(metadata) != 0 {
				t.Error("off mode emitted engine events")
			}
			if mode != "off" && len(metadata) == 0 {
				t.Error("no actual numerical metadata events")
			}
			phaseOne := false
			for _, line := range bytes.Split(bytes.TrimSpace(metadata), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				eventCount++
				var event map[string]any
				if json.Unmarshal(line, &event) != nil || len(event) != 8 || event["engine"] != apacheBodyEngineVersion || event["site_id"] != "0123456789abcdef0123456789abcdef" || event["mode"] != mode {
					t.Error("invalid closed native event")
				}
				for _, name := range []string{"time_us", "rule_id", "phase", "severity"} {
					if _, ok := event[name].(float64); !ok {
						t.Error("nonnumeric event", name)
					}
				}
				if _, ok := event["blocked"].(bool); !ok {
					t.Error("invalid event action")
				}
				if event["rule_id"] == float64(128003) && event["phase"] == float64(1) && event["blocked"] == (mode == "block") {
					phaseOne = true
				}
			}
			if mode != "off" && !phaseOne {
				t.Error("missing correctly scoped/actioned real phase 1 encoding event")
			}
			numeric, readErr := readApacheBodyEvents(context.Background())
			if readErr != nil || !numeric.Available || numeric.Rejected != 0 || numeric.Partial || len(numeric.Events) != len(bytes.Split(bytes.TrimSpace(metadata), []byte{'\n'})) && len(metadata) != 0 {
				t.Fatal("actual emitted C events were not accepted by the bounded numeric reader", mode, readErr, numeric)
			}
			if mode == "off" && len(numeric.Events) != 0 || mode != "off" && len(numeric.Events) == 0 {
				t.Fatal("numeric report confused off mode with active match records", mode)
			}
			numericReports = append(numericReports, map[string]any{"mode": mode, "actual_emitted_records": len(numeric.Events), "reader_rejected_lines": numeric.Rejected, "reader_available": numeric.Available, "counting_contract": core.ApacheBodyCountingContract})
			for _, p := range []string{log, filepath.Join(root, mode+"-error.log"), filepath.Join(root, mode+"-startup.log")} {
				data, err := os.ReadFile(p)
				if err != nil || bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte("Matched Data:")) {
					t.Error("managed engine log privacy failure", p, err)
				}
			}
			if mode == "block" {
				if err = os.WriteFile(filepath.Join(root, "block-before-boundary.events.log"), metadata, 0600); err != nil {
					t.Fatal(err)
				}
				// Only this namespace-local fixture sink is temporarily reclaimed
				// to fill its physical boundary. Do not grant DAC_OVERRIDE, change
				// its permissions, or touch an original Apache log.
				readOnly, err := os.OpenFile(log, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				st, err := readOnly.Stat()
				if err != nil {
					readOnly.Close()
					t.Fatal(err)
				}
				owner, ok := st.Sys().(*syscall.Stat_t)
				if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || owner.Uid != 33 || owner.Gid != 33 || owner.Nlink != 1 {
					readOnly.Close()
					t.Fatal("unexpected private event sink identity")
				}
				err = readOnly.Chown(0, 0)
				readOnly.Close()
				if err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(log, os.O_RDWR|syscall.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				if now, e := f.Stat(); e != nil || !os.SameFile(st, now) {
					f.Close()
					t.Fatal("private event sink changed while filling boundary", e)
				}
				err = f.Truncate(32 << 20)
				ownerErr := f.Chown(33, 33)
				closeErr := f.Close()
				if err != nil || ownerErr != nil || closeErr != nil {
					t.Fatal(err, ownerErr, closeErr)
				}
				var wg sync.WaitGroup
				failures := make(chan error, 32)
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						req, _ := http.NewRequest("POST", "http://"+address+"/probe", strings.NewReader(jsonBody(xss)))
						req.Host = "protected.localhost"
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set("User-Agent", "Mozilla/5.0 QA")
						req.Header.Set("Accept", "application/json")
						res, e := client.Do(req)
						if e != nil {
							failures <- e
							return
						}
						_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
						res.Body.Close()
						if res.StatusCode != 403 {
							failures <- fmt.Errorf("log saturation changed enforcement: %d", res.StatusCode)
						}
					}()
				}
				wg.Wait()
				close(failures)
				for e := range failures {
					t.Error(e)
				}
				st, err = os.Stat(log)
				if err != nil || st.Size() != 32<<20 {
					t.Error("native event physical ceiling failed", err)
				}
				capacity, readErr := readApacheBodyEvents(context.Background())
				if readErr != nil || !capacity.Available || !capacity.Partial || !capacity.CapacityNearLimit || capacity.LogBytes != 32<<20 {
					t.Fatal("actual full numerical sink reader did not retain bounded honest capacity state", readErr, capacity)
				}
				numericReports = append(numericReports, map[string]any{"mode": "block-capacity-ceiling", "actual_emitted_records": len(capacity.Events), "log_bytes": capacity.LogBytes, "capacity_near_limit": capacity.CapacityNearLimit, "partial": capacity.Partial, "counting_contract": core.ApacheBodyCountingContract})
				logCap = !t.Failed()
			}
		})
	}
	proof := map[string]any{"passed": !t.Failed(), "prototype": true, "commercial_feature_parity_complete": false, "signed_application_installed": false, "normal_panel_gui_verified": false, "module_sha256": compiler.ModuleSHA, "engine_version": apacheBodyEngineVersion, "crs_version": wafBodyCRSVersion, "cases": results, "metadata_event_count": eventCount, "native_numeric_reader_reports": numericReports, "external_entity_fetches": externalHits.Load(), "32_concurrent_attacks_at_32MiB_physical_event_ceiling": logCap, "scope": "Private Apache native v2 HTTP parser, same-body forwarding, per-vhost mode, event privacy and actual numeric reader fixture. Not a signed UI install, CGI/PHP business claim, production config transaction or all-OS acceptance."}
	proof["transport"] = transport
	encoded, _ := json.MarshalIndent(proof, "", "  ")
	if err = os.WriteFile(filepath.Join(root, "http-proof.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_HTTP_PROOF", root)
}
